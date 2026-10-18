// Command ory-token-profile-hook serves the private authenticated Hydra hook.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/federation"
	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
	"github.com/baobab-platform/baobab-iam/internal/tokenprofile"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:4466", "private listener; expose only to Hydra")
	profiles := flag.String("profiles", "", "governed pinned Shared JSON projection with runtime bindings")
	keyFile := flag.String("key-file", "", "private hook authentication key file")
	runtimeFile := flag.String("runtime-config", "", "private reviewed C4 runtime composition JSON; required")
	caFile := flag.String("cp-ca-file", "", "optional CP TLS root PEM")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var config tokenprofile.Config
	if federation.LoadServiceDocument(*profiles, &config) != nil {
		log.Fatal("cannot load protected token profiles")
	}
	var composition federation.RuntimeComposition
	if federation.LoadServiceDocument(*runtimeFile, &composition) != nil {
		log.Fatal("reviewed runtime composition required")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		roots := x509.NewCertPool()
		if err != nil || !roots.AppendCertsFromPEM(pem) {
			log.Fatal("invalid CP trust roots")
		}
		tlsConfig.RootCAs = roots
	}
	dispatch, contexts, err := federation.StartRuntimeComposition(ctx, composition, provider.CapabilityWorkloadTokenIssue, tlsConfig)
	if err != nil {
		log.Fatal("cannot establish current CP runtime composition")
	}
	defer func() { cancel(); <-contexts.Done() }()
	key, err := (federation.FileAuthorityTokens{Path: *keyFile}).Token(ctx)
	if err != nil {
		log.Fatal("cannot read protected token hook authentication key")
	}
	hook, err := configuredHook(config, key, dispatch)
	if err != nil {
		log.Fatal("invalid token profile configuration or hook authentication key")
	}
	mux := http.NewServeMux()
	mux.Handle("/internal/ory/token-profile", hook)
	server := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = server.Shutdown(shutdown)
	}()
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Print("token hook listener failed")
		cancel()
	}
	// ListenAndServe returns when shutdown starts; wait for the request drain
	// before main returns and the process terminates its remaining goroutines.
	cancel()
	<-shutdownDone
}

// configuredHook always requires current CP dispatch, in every environment.
// Provider-only CI mechanics live in tests/ and are never a command fallback.
func configuredHook(config tokenprofile.Config, key string, authority ory.DispatchAuthority) (http.Handler, error) {
	return ory.NewGovernedCanonicalTokenProfileHook(config, key, authority)
}
