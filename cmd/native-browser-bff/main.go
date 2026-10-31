// Command native-browser-bff hosts the governed Kratos/Hydra browser boundary.
// This command requires a reviewed private runtime and is not a deployment,
// provider activation, client bootstrap or authorization-grant mechanism.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/federation"
	"github.com/baobab-platform/baobab-iam/internal/nativebff"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
	"github.com/baobab-platform/baobab-iam/internal/tokenprofile"
	"github.com/jackc/pgx/v5/pgxpool"
)

type document struct {
	Human                   federation.RuntimeComposition    `json:"human_runtime"`
	IssuerRuntime           federation.RuntimeComposition    `json:"issuer_runtime"`
	KratosPublic            string                           `json:"kratos_public_origin"`
	KratosAdmin             string                           `json:"kratos_admin_origin"`
	RequireAAL2             bool                             `json:"require_aal2"`
	HydraAdmin              string                           `json:"hydra_admin_origin"`
	Issuer                  string                           `json:"issuer"`
	PublicOrigin            string                           `json:"public_origin"`
	ClientID                string                           `json:"client_id"`
	ClientSecretFile        string                           `json:"client_secret_file"`
	Scope                   string                           `json:"scope"`
	AccessAudience          string                           `json:"access_audience"`
	AccessScope             string                           `json:"access_scope"`
	CPCallerTokenFile       string                           `json:"cp_caller_token_file"`
	BrowserDatabaseDSNFile  string                           `json:"browser_database_dsn_file"`
	BrowserVaultKeyFile     string                           `json:"browser_vault_key_file"`
	ChallengeStorage        federation.PostgresStorageConfig `json:"challenge_storage"`
	HumanTokenProfilesFile  string                           `json:"human_token_profiles_file"`
	HumanConsentSealKeyFile string                           `json:"human_consent_seal_key_file"`
	TLSCertificateFile      string                           `json:"tls_certificate_file"`
	TLSPrivateKeyFile       string                           `json:"tls_private_key_file"`
}

func privateBytes(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("missing protected input")
	}
	secret, err := federation.ReadProtectedServiceFile(path)
	if err != nil {
		return nil, errors.New("protected input unavailable")
	}
	return secret, nil
}

func openBrowserPool(ctx context.Context, file string) (*pgxpool.Pool, error) {
	private, err := privateBytes(file)
	if err != nil {
		return nil, err
	}
	cfg, err := pgxpool.ParseConfig(strings.TrimSpace(string(private)))
	if err != nil || cfg.ConnConfig.TLSConfig == nil || cfg.ConnConfig.TLSConfig.InsecureSkipVerify ||
		cfg.ConnConfig.TLSConfig.ServerName == "" || len(cfg.ConnConfig.Fallbacks) != 0 {
		return nil, errors.New("TLS-verified PostgreSQL 17 browser vault required")
	}
	cfg.MaxConns = 8
	cfg.MinConns = 1
	cfg.MaxConnLifetime = 5 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, errors.New("browser database unavailable")
	}
	if pool.Ping(ctx) != nil {
		pool.Close()
		return nil, errors.New("browser database unavailable")
	}
	return pool, nil
}

func loadRoots(file string) (*x509.CertPool, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, errors.New("system trust unavailable")
	}
	if file == "" {
		return roots, nil
	}
	pem, err := privateBytes(file)
	if err != nil || !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("invalid protected CA roots")
	}
	return roots, nil
}

func run(ctx context.Context, listen string, d document, caFile string) error {
	if ctx == nil || ctx.Err() != nil || d.PublicOrigin == "" || d.Issuer == "" ||
		d.ClientID == "" || d.KratosAdmin == "" || d.CPCallerTokenFile == "" || d.TLSCertificateFile == "" ||
		d.TLSPrivateKeyFile == "" || d.HumanTokenProfilesFile == "" ||
		d.HumanConsentSealKeyFile == "" {
		return errors.New("incomplete governed browser configuration")
	}
	// A source-only IAM N02 host supports the currently approved Trade-buyer
	// delegated Principal profile, not a fictitious universal CP-human API.
	if d.AccessAudience != "baobab-trade" || d.AccessScope != "trade:buy" ||
		!strings.Contains(" "+d.Scope+" ", " trade:buy ") {
		return errors.New("unregistered human resource audience")
	}
	roots, err := loadRoots(caFile)
	if err != nil {
		return err
	}
	trust := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	certificate, err := privateBytes(d.TLSCertificateFile)
	if err != nil {
		return err
	}
	privateKey, err := privateBytes(d.TLSPrivateKeyFile)
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(certificate, privateKey)
	if err != nil {
		return errors.New("invalid BFF TLS identity")
	}
	providerTLS := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{TLSClientConfig: trust.Clone(), Proxy: nil}}
	secret, err := privateBytes(d.ClientSecretFile)
	if err != nil {
		return err
	}
	secret = []byte(strings.TrimSpace(string(secret)))
	if len(secret) < 32 {
		return errors.New("confidential OAuth credential too short")
	}
	vaultKey, err := privateBytes(d.BrowserVaultKeyFile)
	if err != nil || len(vaultKey) != 32 {
		return errors.New("exactly 256-bit browser vault key required")
	}
	storage, err := federation.OpenPostgresStorage(ctx, d.ChallengeStorage)
	if err != nil {
		return errors.New("durable CP-governed challenge storage unavailable")
	}
	defer storage.Close()
	fence, err := federation.OpenNativeChallengeLedgerWithStorage(storage)
	if err != nil {
		return errors.New("native challenge fence unavailable")
	}
	defer fence.Close()
	pool, err := openBrowserPool(ctx, d.BrowserDatabaseDSNFile)
	if err != nil {
		return err
	}
	defer pool.Close()
	browserStore, err := nativebff.NewPostgresStore(pool, vaultKey)
	if err != nil {
		return err
	}
	var profiles tokenprofile.Config
	if federation.LoadServiceDocument(d.HumanTokenProfilesFile, &profiles) != nil {
		return errors.New("registered human consent token profiles required")
	}
	seal, err := privateBytes(d.HumanConsentSealKeyFile)
	if err != nil {
		return err
	}
	config := ory.NativeHumanConfig{
		KratosPublicURL: d.KratosPublic, HydraAdminURL: d.HydraAdmin,
		Issuer: d.Issuer, Now: time.Now, Fence: fence,
		Client: providerTLS, TokenProfiles: &profiles, ConsentSealKey: seal,
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	handoff, supervisor, err := ory.StartNativeHumanRuntime(child, config, d.Human, d.IssuerRuntime, trust)
	if err != nil {
		return errors.New("current CP Kratos/Hydra runtime denied")
	}
	defer func() { cancel(); <-supervisor.Done() }()
	resolver, err := nativebff.NewHTTPPrincipalResolver(nativebff.PrincipalResolutionConfig{
		CPOrigin: d.Human.CPOrigin,
		Caller:   federation.FileAuthorityTokens{Path: d.CPCallerTokenFile},
		Now:      time.Now, TrustedRoots: roots,
	})
	if err != nil {
		return errors.New("CP delegated Principal boundary unavailable")
	}
	kratosSessions, err := nativebff.NewKratosAdminSessionRevoker(nativebff.KratosAdminRevokeConfig{
		Origin: d.KratosAdmin, TrustedRoots: roots,
	})
	if err != nil {return errors.New("Kratos global logout authority unavailable")}
	revoker, err := nativebff.NewOAuthRevoker(nativebff.OAuthRevokeConfig{
		Issuer: d.Issuer, ClientID: d.ClientID, ClientSecret: string(secret), TrustedRoots: roots,
	})
	if err != nil {
		return errors.New("confidential token revocation unavailable")
	}
	handler, err := nativebff.New(nativebff.Config{
		PublicOrigin: d.PublicOrigin, Issuer: d.Issuer, KratosOrigin: d.KratosPublic,
		RequireAAL2: d.RequireAAL2, Assurance: handoff, NativeSessions: kratosSessions,
		ClientID: d.ClientID, ClientSecret: string(secret),
		RedirectURI: strings.TrimRight(d.PublicOrigin, "/") + "/auth/callback",
		Scope:       d.Scope, AccessAudience: d.AccessAudience, AccessScope: d.AccessScope, TrustedRoots: roots,
		KratosSessionCookieName: "ory_kratos_session",
		Now:                     time.Now, Handoff: handoff, CP: resolver, Revoker: revoker,
		Store: browserStore,
	})
	if err != nil {
		return errors.New("invalid native BFF configuration")
	}
	server := &http.Server{
		Addr: listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 12 * time.Second, WriteTimeout: 20 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	bound, err := net.Listen("tcp", listen)
	if err != nil {
		return errors.New("native BFF listener unavailable")
	}
	defer bound.Close()
	listener := tls.NewListener(bound, &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
	})
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		<-child.Done()
		deadline, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		err := server.Shutdown(deadline)
		if err != nil {
			_ = server.Close()
		}
		done <- err
	}()
	err = server.Serve(listener)
	cancel()
	shutdownErr := <-done
	if !errors.Is(err, http.ErrServerClosed) || shutdownErr != nil {
		return errors.New("native BFF listener or graceful shutdown failed")
	}
	return nil
}

func main() {
	configFile := flag.String("config", "", "private reviewed native BFF JSON configuration")
	caFile := flag.String("ca-file", "", "optional owner-protected root PEM")
	listen := flag.String("listen", "127.0.0.1:8443", "TLS-only BFF listener behind approved ingress")
	flag.Parse()
	if *configFile == "" {
		fmt.Fprintln(os.Stderr, "DENIED N02 missing reviewed runtime")
		os.Exit(2)
	}
	var d document
	if federation.LoadServiceDocument(*configFile, &d) != nil {
		fmt.Fprintln(os.Stderr, "DENIED N02 invalid reviewed runtime")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, *listen, d, *caFile); err != nil {
		fmt.Fprintln(os.Stderr, "DENIED N02 native browser composition")
		os.Exit(1)
	}
}
