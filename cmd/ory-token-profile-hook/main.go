// Command ory-token-profile-hook serves the private authenticated Hydra hook.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"log"
	"net"
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
	sealFile := flag.String("human-consent-seal-key-file", "", "optional private IAM key governed buyer consent seals with; without it no human token is issued")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := runHook(ctx, *listen, *profiles, *keyFile, *runtimeFile, *caFile, *sealFile); err != nil {
		log.Fatal(err)
	}
}

func runHook(parent context.Context, listen, profiles, keyFile, runtimeFile, caFile, sealFile string) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var config tokenprofile.Config
	if federation.LoadServiceDocument(profiles, &config) != nil {
		return errors.New("cannot load protected token profiles")
	}
	var composition federation.RuntimeComposition
	if federation.LoadServiceDocument(runtimeFile, &composition) != nil {
		return errors.New("reviewed runtime composition required")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		roots := x509.NewCertPool()
		if err != nil || !roots.AppendCertsFromPEM(pem) {
			return errors.New("invalid CP trust roots")
		}
		tlsConfig.RootCAs = roots
	}
	dispatch, contexts, err := federation.StartRuntimeComposition(ctx, composition, provider.CapabilityWorkloadTokenIssue, tlsConfig)
	if err != nil {
		return errors.New("cannot establish current CP runtime composition")
	}
	defer func() { cancel(); <-contexts.Done() }()
	key, err := (federation.FileAuthorityTokens{Path: keyFile}).Token(ctx)
	if err != nil {
		return errors.New("cannot read protected token hook authentication key")
	}
	var sealKey []byte
	if sealFile != "" {
		seal, err := (federation.FileAuthorityTokens{Path: sealFile}).Token(ctx)
		if err != nil {
			return errors.New("cannot read protected human consent seal key")
		}
		sealKey = []byte(seal)
	}
	hook, err := configuredHook(config, key, dispatch, sealKey)
	if err != nil {
		return errors.New("invalid token profile configuration or hook authentication key")
	}
	mux := http.NewServeMux()
	mux.Handle("/internal/ory/token-profile", boundedHook(ctx, hook, 8*time.Second))
	server := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	return runHookServer(ctx, server)
}

// boundedHook bounds the ENTIRE composed check, including context renewal and
// lock waits. Its deadline is below the socket's write deadline, leaving time
// to return a denial rather than computing a success after Hydra disconnected.
func boundedHook(service context.Context, hook http.Handler, budget time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		operation, cancel := context.WithTimeout(r.Context(), budget)
		defer cancel()
		stop := context.AfterFunc(service, cancel)
		defer stop()
		hook.ServeHTTP(w, r.WithContext(operation))
	})
}

func runHookServer(ctx context.Context, server *http.Server) error {
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return errors.New("token hook listener failed")
	}
	defer listener.Close()
	return serveHookListener(ctx, server, listener)
}

// Shutdown closes the listener before draining active requests. Serve returning
// therefore cannot be treated as completion: join shutdown, forcing Close only
// after the bounded grace period, before allowing the process to exit.
func serveHookListener(ctx context.Context, server *http.Server, listener net.Listener) error {
	lifecycle, cancel := context.WithCancel(ctx)
	defer cancel()
	shutdownDone := make(chan error, 1)
	go func() {
		<-lifecycle.Done()
		shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		err := server.Shutdown(shutdown)
		if err != nil {
			_ = server.Close()
		}
		shutdownDone <- err
	}()
	err := server.Serve(listener)
	cancel()
	shutdownErr := <-shutdownDone
	if !errors.Is(err, http.ErrServerClosed) {
		return errors.New("token hook listener failed")
	}
	if shutdownErr != nil {
		return errors.New("token hook shutdown failed")
	}
	return nil
}

// configuredHook always requires current CP dispatch, in every environment.
// Provider-only CI mechanics live in tests/ and are never a command fallback.
// Human buyer issuance is enabled only with the consent seal key.
func configuredHook(config tokenprofile.Config, key string, authority ory.DispatchAuthority, sealKey []byte) (http.Handler, error) {
	if sealKey == nil {
		return ory.NewGovernedCanonicalTokenProfileHook(config, key, authority)
	}
	return ory.NewGovernedCanonicalTokenProfileHook(config, key, authority, ory.WithHumanConsentSealKey(sealKey))
}
