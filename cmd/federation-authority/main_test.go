package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/federation"
)

func TestConfigurationRefusesUnknownAndTrailingInput(t *testing.T) {
	for _, input := range []string{`{"Unknown":true}`, `{} {}`, `{} garbage`} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := load(path); err == nil {
			t.Fatal("invalid configuration admitted")
		}
	}
}

func TestPrivateServiceTLSReadinessAndGracefulShutdown(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "service-test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	var issuer *httptest.Server
	issuer = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"issuer": issuer.URL, "jwks_uri": issuer.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}})
	}))
	issuer.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	issuer.StartTLS()
	defer issuer.Close()
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	certPath := write("cert.pem", certPEM)
	keyPath := write("key.pem", keyPEM)
	registry := write("admission.json", []byte("[]"))
	token := write("token", []byte("fixture-only-token"))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	state := filepath.Join(dir, "state")
	if err = os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	c := config{Address: address, Certificate: certPath, Key: keyPath, ClientCA: certPath, AuthorityCA: certPath, WorkloadIssuer: issuer.URL, WorkloadAudience: "test-authority", RegistryPath: registry, CPOrigin: issuer.URL, CPTokenFile: token, ProtocolOrigin: issuer.URL, ProtocolTokenFile: token, StateDirectory: state, Policy: federation.Policy{Scope: federation.Scope{OrganisationID: "org_example", EstateID: "estate_example"}, MaxEventLifetime: time.Minute, MaxAuthenticationAge: time.Minute, MaxDecisionLifetime: time.Minute}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, c) }()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}}}
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(5 * time.Second)
	for {
		response, e := client.Get("https://" + address + "/health/live")
		if e == nil {
			response.Body.Close()
			if response.StatusCode != 204 {
				t.Fatal(response.StatusCode)
			}
			break
		}
		select {
		case e := <-done:
			t.Fatal("service stopped during startup", e)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("service did not start", e)
		}
		time.Sleep(10 * time.Millisecond)
	}
	response, err := client.Get("https://" + address + "/health/ready")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 503 {
		t.Fatal("empty governance reported ready")
	}
	client.CloseIdleConnections()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("service did not drain")
	}
	ca := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	authority, err := federation.NewHTTPAuthority(issuer.URL, federation.FileAuthorityTokens{Path: token}, ca)
	if err != nil {
		t.Fatal(err)
	}
	g, err := federation.OpenGovernanceComposition(federation.GovernanceCompositionConfig{NativeTargetLedgerPath: filepath.Join(state, "native.db"), ApprovalLedgerPath: filepath.Join(state, "approvals.db"), TrustLedgerPath: filepath.Join(state, "trusts.db"), Registration: authority, ApprovalAuthority: authority, Now: time.Now})
	if err != nil {
		t.Fatal("governance locks retained after shutdown", err)
	}
	g.Close()
	events, err := federation.OpenOIDCEvents(filepath.Join(state, "events.db"), authority, authority, time.Now, time.Minute)
	if err != nil {
		t.Fatal("event lock retained after shutdown", err)
	}
	events.Close()
}
