// This test-only process compiles the unchanged pinned CP verifier.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"github.com/baobab-platform/baobab-cp/internal/auth"
)

type input struct {
	Token       string `json:"token"`
	Audience    string `json:"audience"`
	Scope       string `json:"scope"`
	WrongIssuer bool   `json:"wrong_issuer"`
}

func main() {
	var in input
	if json.NewDecoder(io.LimitReader(os.Stdin, 1<<20)).Decode(&in) != nil {
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	issuer := "http://127.0.0.1:4444"
	if in.WrongIssuer {
		// A second configured issuer serves discovery with the SAME public JWKS.
		// The real signed token must still fail the issuer check.
		jwksURL := issuer + "/.well-known/jwks.json"
		var server *httptest.Server
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/openid-configuration" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": server.URL, "jwks_uri": jwksURL, "id_token_signing_alg_values_supported": []string{"RS256"}})
		}))
		defer server.Close()
		issuer = server.URL
	}
	verifier, err := auth.NewOIDCVerifier(ctx, issuer, in.Audience)
	if err != nil {
		os.Exit(2)
	}
	principal, err := verifier.Verify(ctx, in.Token)
	if err != nil && !errors.Is(err, auth.ErrInvalidToken) {
		os.Exit(2)
	}
	result := map[string]any{"verified": err == nil, "required_scope_present": false, "workload_identity_matches": false}
	if err == nil {
		result["required_scope_present"] = principal.HasScope(in.Scope)
		result["workload_identity_matches"] = principal.ActorType == "workload" && principal.ClientID == "baobab-trade-workload" && principal.Subject == principal.ClientID && strings.TrimRight(principal.Issuer, "/") == "http://127.0.0.1:4444"
	}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		os.Exit(2)
	}
}
