package ory

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

type nativeUnsafeRoundTripper func(*http.Request) (*http.Response, error)

func (fn nativeUnsafeRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}

func TestNativeProviderTransportRejectsProxyTLSAndSocketOverride(t *testing.T) {
	for name, c := range map[string]*http.Client{
		"arbitrary roundtripper": {Transport: nativeUnsafeRoundTripper(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("fake privileged issuer response")
		})},
		"ambient proxy": {Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}},
		"custom proxy": {Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
			return url.Parse("https://proxy.attacker.invalid")
		}}},
		"custom socket": {Transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("routing substituted")
		}}},
		"verify skipped":       {Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}},
		"hostname substituted": {Transport: &http.Transport{TLSClientConfig: &tls.Config{ServerName: "attacker.invalid"}}},
		"unsupported tls":      {Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS10}}},
		"key log":              {Transport: &http.Transport{TLSClientConfig: &tls.Config{KeyLogWriter: io.Discard}}},
		"callback override": {Transport: &http.Transport{TLSClientConfig: &tls.Config{
			VerifyConnection: func(tls.ConnectionState) error { return nil },
		}}},
		"custom cipher suites": {Transport: &http.Transport{TLSClientConfig: &tls.Config{
			CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
		}}},
		"custom protocol handler": {Transport: &http.Transport{TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{
			"h2": func(string, *tls.Conn) http.RoundTripper { return nil },
		}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := newNativeProviderHTTPClient(c); err == nil {
				t.Fatal("unsafe native provider request transport accepted")
			}
			if _, err := NewNativeHumanHandoff(NativeHumanConfig{
				KratosPublicURL: "https://kratos.private.invalid",
				HydraAdminURL:   "https://hydra.private.invalid",
				Issuer:          "https://issuer.private.invalid",
				Client:          c, Now: time.Now, Fence: openNativeTestFence(t),
			}); err == nil {
				t.Fatal("unsafe native handoff transport reached constructor")
			}
		})
	}
}

func TestNativeProviderTransportEnforcesTLSWithoutAmbientProxy(t *testing.T) {
	client, err := newNativeProviderHTTPClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.TLSClientConfig == nil ||
		transport.TLSClientConfig.MinVersion < tls.VersionTLS12 ||
		client.Timeout != 10*time.Second || client.CheckRedirect == nil {
		t.Fatal("default privileged transport did not enforce protected routing and TLS")
	}
	if err := client.CheckRedirect(&http.Request{}, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatal("native provider redirected a privileged request")
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	allowed := srv.Client()
	oldTransport := allowed.Transport.(*http.Transport)
	newClient, err := newNativeProviderHTTPClient(allowed)
	if err != nil {
		t.Fatalf("approved TLS test CA rejected: %v", err)
	}
	newTransport := newClient.Transport.(*http.Transport)
	if newTransport == oldTransport || newTransport.TLSClientConfig == oldTransport.TLSClientConfig ||
		newTransport.TLSClientConfig.RootCAs == oldTransport.TLSClientConfig.RootCAs ||
		newTransport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("privileged client inherited mutable or insecure TLS parameters")
	}
	oldTransport.TLSClientConfig.InsecureSkipVerify = true
	if newTransport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("caller changed verified transport after construction")
	}
	response, err := newClient.Get(srv.URL)
	if err != nil {
		t.Fatalf("cloned allowed CA did not validate real TLS: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("unexpected response: %d", response.StatusCode)
	}
}
