// Command c4-04-readiness observes registered CP native/workload authority
// and real Kratos/Hydra health without granting access or activating a tenant.
// It does not emit credentials, CP responses, URLs, principal IDs or tokens.
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
	"time"

	"github.com/baobab-platform/baobab-iam/internal/federation"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

// Protected operational inputs have no passwords or inline bearer tokens.
// IAM and CP service credentials remain in the two factory credential files.
type readinessDocument struct {
	Human        federation.RuntimeComposition `json:"human_runtime"`
	Issuer       federation.RuntimeComposition `json:"issuer_runtime"`
	KratosAdmin  string                        `json:"kratos_admin_origin"`
	HydraAdmin   string                        `json:"hydra_admin_origin"`
	PublicIssuer string                        `json:"public_issuer"`
}

// Only reviewed HTTPS origins with no userinfo, paths, query or fragments may
// carry private Ory admin traffic. No provider or resource URL is received from
// a bearer, browser hint, OAuth client or platform consumer.
func validOrigin(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" &&
		u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" &&
		!u.ForceQuery
}

func (d readinessDocument) valid() bool {
	return validOrigin(d.KratosAdmin) &&
		validOrigin(d.HydraAdmin) && validOrigin(d.PublicIssuer)
}

func trustedTransport(caFile string) (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile == "" {
		return config, nil
	}
	// The same opened, owner-validated private inode supplies all trust bytes.
	// A foreign 0600/0644 owner or a path replacement cannot select our roots.
	pem, err := federation.ReadProtectedServiceFile(caFile)
	if err != nil {
		return nil, errors.New("invalid protected CA file")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("invalid protected CA file")
	}
	config.RootCAs = roots
	return config, nil
}

func run(ctx context.Context, doc readinessDocument, tlsConfig *tls.Config) error {
	if !doc.valid() || ctx == nil || ctx.Err() != nil || tlsConfig == nil ||
		tlsConfig.InsecureSkipVerify {
		return errors.New("untrusted C4-04 readiness configuration")
	}
	// Ory connection and CP authority use the same explicit trust roots, but
	// distinct, restricted transports. Proxy-env routing and redirects cannot
	// carry a private admin request to a third-party endpoint.
	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig.Clone(),
			Proxy:           nil,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	adapter, err := ory.NewAdapter(ory.Config{
		KratosAdminURL: doc.KratosAdmin,
		HydraAdminURL:  doc.HydraAdmin,
		PublicIssuer:   doc.PublicIssuer,
		HTTPClient:     client,
	})
	if err != nil {
		return errors.New("invalid native health provider")
	}
	// This production factory reads *current* CP capability and
	// identity-runtime binding/health/artifact evidence on every call.
	result, err := ory.CheckComposedNativeWorkloadReadiness(
		ctx, doc.Human, doc.Issuer, tlsConfig, adapter,
	)
	if err != nil || !result.HumanCurrent || !result.WorkloadCurrent ||
		!result.KratosReady || !result.HydraReady {
		return errors.New("C4-04 current CP/native readiness denied")
	}
	return nil
}

func main() {
	configFile := flag.String("config", "", "private reviewed C4-04 runtime configuration")
	caFile := flag.String("ca-file", "", "private CA trust roots; omit for system roots")
	flag.Parse()
	if *configFile == "" {
		fmt.Fprintln(os.Stderr, "DENIED C4-04 missing protected runtime configuration")
		os.Exit(2)
	}
	var doc readinessDocument
	if federation.LoadServiceDocument(*configFile, &doc) != nil {
		fmt.Fprintln(os.Stderr, "DENIED C4-04 invalid protected runtime configuration")
		os.Exit(2)
	}
	roots, err := trustedTransport(*caFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "DENIED C4-04 invalid protected trust roots")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if run(ctx, doc, roots) != nil {
		fmt.Fprintln(os.Stderr, "DENIED C4-04 governed native/workload observation")
		os.Exit(1)
	}
	// An observation is transient. It NEVER authorizes issue/login/consent,
	// certifies provider support or promotes a release on its own.
	fmt.Println("OBSERVED_CURRENT C4-04 governed runtime (non-authorising)")
}
