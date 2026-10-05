// federation-authority hosts the private IAM governance authority. Browser
// callbacks and provider dispatch are deliberately separate service boundaries.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/federation"
	"github.com/coreos/go-oidc/v3/oidc"
)

type config struct {
	Address, Certificate, Key, ClientCA, AuthorityCA string
	WorkloadIssuer, WorkloadAudience, RegistryPath   string
	CPOrigin, CPTokenFile                            string
	CanonicalRegistryPath, Environment               string
	StateDirectory                                   string
	ReadinessTrustID                                 string
	ReviewedTargets                                  string
	Policy                                           federation.Policy
}

type issuerTransport struct {
	host string
	base http.RoundTripper
}

func (t issuerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != t.host || r.URL.User != nil {
		return nil, errors.New("issuer transport origin refused")
	}
	return t.base.RoundTrip(r)
}

func load(path string) (config, error) {
	var c config
	if err := federation.LoadServiceDocument(path, &c); err != nil {
		return c, err
	}
	for _, v := range []string{c.Address, c.Certificate, c.Key, c.ClientCA, c.AuthorityCA, c.WorkloadAudience, c.RegistryPath, c.CanonicalRegistryPath, c.Environment, c.StateDirectory, c.CPTokenFile} {
		if v == "" {
			return c, errors.New("missing configuration")
		}
	}
	for _, v := range []string{c.CPOrigin, c.WorkloadIssuer} {
		u, e := url.Parse(v)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return c, errors.New("authority must use HTTPS")
		}
	}
	return c, nil
}

func roots(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(b) {
		return nil, errors.New("invalid trust roots")
	}
	return p, nil
}

func run(ctx context.Context, c config) error {
	i, err := os.Lstat(c.StateDirectory)
	if err != nil || !i.IsDir() || i.Mode().Perm()&0077 != 0 {
		return errors.New("state directory must be private and persistent")
	}
	ca, err := roots(c.AuthorityCA)
	if err != nil {
		return err
	}
	outbound := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: ca}
	cp, err := federation.NewHTTPAuthority(c.CPOrigin, federation.FileAuthorityTokens{Path: c.CPTokenFile}, outbound)
	if err != nil {
		return err
	}
	g, err := federation.OpenGovernanceComposition(federation.GovernanceCompositionConfig{
		NativeTargetLedgerPath: filepath.Join(c.StateDirectory, "native.db"), ApprovalLedgerPath: filepath.Join(c.StateDirectory, "approvals.db"), TrustLedgerPath: filepath.Join(c.StateDirectory, "trusts.db"), Registration: cp, ApprovalAuthority: cp, Now: time.Now,
	})
	if err != nil {
		return err
	}
	defer g.Close()
	if c.ReviewedTargets != "" {
		if err = g.LoadReviewedTargets(ctx, c.ReviewedTargets); err != nil {
			return errors.New("reviewed targets refused")
		}
	}
	protocol := &federation.NativeProtocol{Native: g.NativeTargets, Governance: g.Trusts, Scope: c.Policy.Scope, Now: time.Now}
	if c.ReviewedTargets != "" {
		protocol.Refresh = func(ctx context.Context) error { return g.LoadReviewedTargets(ctx, c.ReviewedTargets) }
	}
	// Discover only the explicitly configured issuer, over verified private TLS.
	issuerURL, _ := url.Parse(c.WorkloadIssuer)
	client := &http.Client{Timeout: 5 * time.Second, Transport: issuerTransport{host: issuerURL.Host, base: &http.Transport{TLSClientConfig: outbound}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	discovery, cancel := context.WithTimeout(oidc.ClientContext(ctx, client), 10*time.Second)
	provider, err := oidc.NewProvider(discovery, c.WorkloadIssuer)
	cancel()
	if err != nil {
		return errors.New("workload verifier unavailable")
	}
	access := &federation.ServiceAccess{RegistryPath: c.RegistryPath, CanonicalRegistryPath: c.CanonicalRegistryPath, Environment: c.Environment, Governance: g, Platform: cp, Verifier: provider.Verifier(&oidc.Config{ClientID: c.WorkloadAudience, SupportedSigningAlgs: []string{"RS256", "ES256"}})}
	sources, err := g.AuthoritySources(access, protocol, protocol)
	if err != nil {
		return err
	}
	handler, err := federation.NewAuthorityHandler(sources)
	if err != nil {
		return err
	}
	c.Policy.Now = time.Now
	events, err := federation.OpenOIDCEvents(filepath.Join(c.StateDirectory, "events.db"), protocol, protocol, time.Now, c.Policy.MaxEventLifetime)
	if err != nil {
		return err
	}
	defer events.Close()
	consumer, err := federation.New(federation.Authorities{Governance: g.Trusts, Platform: cp, Events: events, Canonical: cp}, c.Policy)
	if err != nil {
		return err
	}
	eventHandler, err := federation.NewServiceEventHandler(access, g.Trusts, events, consumer)
	if err != nil {
		return err
	}
	clientCA, err := roots(c.ClientCA)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/internal/federation/v1/", handler)
	mux.Handle("/internal/federation-events/v1/", eventHandler)
	mux.HandleFunc("/health/live", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	})
	// Readiness requires a current approved trust and both live authority sources.
	// Initial governance provisioning can proceed while this probe is not ready.
	mux.HandleFunc("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		probe, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		trust, err := g.Trusts.Trust(probe, c.ReadinessTrustID)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		facet := federation.RuntimeOIDCFederation
		if trust.Trust.Protocol != "OIDC" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if !slices.Contains(trust.Trust.OrganisationIDs, c.Policy.Scope.OrganisationID) || !slices.Contains(trust.Trust.EstateIDs, c.Policy.Scope.EstateID) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		platform, err := cp.FederationBinding(probe, trust.Trust.ProviderBinding, c.Policy.Scope, facet)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if federation.ValidateServicePlatformSnapshot(platform, trust.Trust.ProviderBinding, c.Policy.Scope, facet, time.Now()) != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if err = events.Ready(probe, trust); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	server := &http.Server{Addr: c.Address, Handler: federation.BoundServiceRequests(mux, 60*time.Second), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCA}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	errch := make(chan error, 1)
	go func() { errch <- server.ListenAndServeTLS(c.Certificate, c.Key) }()
	select {
	case err := <-errch:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 75*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			server.Close()
			return err
		}
		return nil
	}
}

func main() {
	path := flag.String("config", "", "protected JSON configuration file")
	flag.Parse()
	c, err := load(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid federation-authority configuration")
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err = run(ctx, c); err != nil {
		fmt.Fprintln(os.Stderr, "federation-authority stopped: dependency or service failure")
		os.Exit(1)
	}
}
