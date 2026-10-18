package ory

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/federation"
)

func TestNativeProductionFactoryRejectsMechanicsAndMissingComposition(t *testing.T) {
	c := NativeHumanConfig{KratosPublicURL: "https://kratos.invalid", HydraAdminURL: "https://hydra.invalid", Issuer: "https://issuer.invalid", Now: time.Now, Fence: openNativeTestFence(t)}
	for _, mode := range []string{"missing authority", "loopback override", "missing fence"} {
		config := c
		if mode == "loopback override" {
			config.AllowLoopbackHTTP = true
		}
		if mode == "missing fence" {
			config.Fence = nil
		}
		h, s, err := StartNativeHumanRuntime(context.Background(), config, federation.RuntimeComposition{}, federation.RuntimeComposition{}, nil)
		if err == nil || h != nil || s != nil {
			t.Fatal("unsafe production factory", mode)
		}
	}
}

func TestNativeRuntimeFactoryRejectsInsecureProviderTLSBeforeAuthority(t *testing.T) {
	c := NativeHumanConfig{KratosPublicURL: "https://kratos.invalid", HydraAdminURL: "https://hydra.invalid", Issuer: "https://issuer.invalid", Now: time.Now, Fence: openNativeTestFence(t), Client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}}
	_, s, err := StartNativeHumanRuntime(context.Background(), c, federation.RuntimeComposition{}, federation.RuntimeComposition{}, nil)
	if err == nil || !strings.Contains(err.Error(), "verified native provider TLS required") || s != nil {
		t.Fatal("unsafe TLS reached authority", err)
	}
}

func TestNativeRuntimeFactoryRejectsTLSHostOverride(t *testing.T) {
	c := NativeHumanConfig{KratosPublicURL: "https://kratos.invalid", HydraAdminURL: "https://hydra.invalid", Issuer: "https://issuer.invalid", Now: time.Now, Fence: openNativeTestFence(t), Client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{ServerName: "foreign.invalid"}}}}
	_, s, err := StartNativeHumanRuntime(context.Background(), c, federation.RuntimeComposition{}, federation.RuntimeComposition{}, nil)
	if err == nil || !strings.Contains(err.Error(), "verified native provider TLS required") || s != nil {
		t.Fatal("TLS hostname override reached authority", err)
	}
}
