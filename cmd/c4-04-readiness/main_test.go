package main

import (
	"context"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
)

func TestC404PrivateOriginsDoNotPermitRedirectRetargeting(t *testing.T) {
	for _, value := range []string{
		"https://ory.internal.example", "https://ory.internal.example:443",
	} {
		if !validOrigin(value) {
			t.Fatalf("valid pinned HTTPS origin denied: %q", value)
		}
	}
	for _, value := range []string{
		"", "http://127.0.0.1:4445", "https://user:secret@ory.example",
		"https://ory.example/extra", "https://ory.example?token=secret",
		"https://ory.example/#fragment", "https://ory.example?",
	} {
		if validOrigin(value) {
			t.Fatalf("unsafe Ory origin accepted: %q", value)
		}
	}
}

func TestC404MissingCompositionNeverContactsProvider(t *testing.T) {
	d := readinessDocument{
		KratosAdmin: "https://kratos.internal.example",
		HydraAdmin: "https://hydra.internal.example",
		PublicIssuer: "https://issuer.internal.example",
	}
	// A syntactically valid origin is not registration or a CP grant.
	if !d.valid() {
		t.Fatal("valid protected origins rejected")
	}
	if err := run(context.Background(), d, &tls.Config{MinVersion: tls.VersionTLS12}); err == nil {
		t.Fatal("unprovisioned native/workload runtime accepted")
	}
	for _, tc := range []struct{
		name string
		edit func(*readinessDocument)
	}{
		{"insecure issuer", func(d *readinessDocument) { d.PublicIssuer = "http://127.0.0.1:4444" }},
		{"query credential", func(d *readinessDocument) { d.KratosAdmin += "?key=private" }},
		{"absent Ory admin", func(d *readinessDocument) { d.HydraAdmin = "" }},
	}{
		t.Run(tc.name, func(t *testing.T) {
			copy := d
			tc.edit(&copy)
			if run(context.Background(), copy, &tls.Config{MinVersion: tls.VersionTLS12}) == nil {
				t.Fatal("untrusted configuration accepted")
			}
		})
	}
	if run(context.Background(), d, &tls.Config{InsecureSkipVerify: true}) == nil {
		t.Fatal("TLS verification bypass accepted")
	}
	if run(context.Background(), d, nil) == nil {
		t.Fatal("nil TLS configuration accepted")
	}
}

func TestC404PrivateCATrustRoots(t *testing.T) {
	dir := t.TempDir()
	unsafe := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(unsafe, []byte("not a PEM"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedTransport(unsafe); err == nil {
		t.Fatal("invalid CA data accepted")
	}
	if err := os.Chmod(unsafe, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedTransport(unsafe); err == nil {
		t.Fatal("group/world writable trust root accepted")
	}
	if _, err := trustedTransport(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing trust root accepted")
	}
	symlink := filepath.Join(dir, "link")
	if err := os.Symlink(unsafe, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedTransport(symlink); err == nil {
		t.Fatal("symlink trust root accepted")
	}
	trust, err := trustedTransport("")
	if err != nil || trust.InsecureSkipVerify || trust.MinVersion < tls.VersionTLS12 {
		t.Fatal("system trust roots not safe")
	}
}
