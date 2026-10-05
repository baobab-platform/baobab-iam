package federation

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

func TestServiceAdmissionSignatureAndCurrentRevocation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{Raw: []byte("verified-test-workload"), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	d := sha256.Sum256(cert.Raw)
	entry := WorkloadAdmission{CertificateSHA256: "sha256:" + hex.EncodeToString(d[:]), Issuer: "https://issuer.example", Subject: "workload-1", Active: true, ValidUntil: now.Add(time.Minute), Actions: []string{}, Scopes: []Scope{}}
	path := filepath.Join(t.TempDir(), "registry.json")
	write := func() {
		b, _ := json.Marshal([]WorkloadAdmission{entry})
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	a := &ServiceAccess{RegistryPath: path, Verifier: oidc.NewVerifier(entry.Issuer, &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, &oidc.Config{ClientID: "iam-authority", SupportedSigningAlgs: []string{"RS256"}})}
	claims := map[string]any{"iss": entry.Issuer, "sub": entry.Subject, "aud": "iam-authority", "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "actor_type": "workload", "scope": "federation-authority:read"}
	r := httptest.NewRequest("POST", "https://authority.example/internal/federation/v1/trust", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	r.Header.Set("Authorization", "Bearer "+signOIDC(t, key, claims))
	if _, err = a.AuthorizeAuthorityRequest(context.Background(), r, "AUTHENTICATE", ReferenceExpectation{}); err != nil {
		t.Fatal(err)
	}
	entry.Actions = []string{"APPROVAL_PROPOSE"}
	entry.Scopes = []Scope{{OrganisationID: "org_example", EstateID: "estate_example"}}
	write()
	a.Governance = &GovernanceComposition{}
	a.Platform = &HTTPAuthority{}
	want := ReferenceExpectation{Scope: entry.Scopes[0]}
	if _, err = a.AuthorizeAuthorityRequest(context.Background(), r, "APPROVAL_PROPOSE", want); err == nil {
		t.Fatal("missing human evidence admitted")
	}
	r.Header.Set("X-Baobab-Governance-Subject", "separate-human-token")
	ctx, err := a.AuthorizeAuthorityRequest(context.Background(), r, "APPROVAL_PROPOSE", want)
	if err != nil {
		t.Fatal(err)
	}
	if subject, ok := governanceSubjectToken(ctx); !ok || subject != "separate-human-token" {
		t.Fatal("human evidence substituted")
	}
	want.Scope.EstateID = "different_estate"
	if _, err = a.AuthorizeAuthorityRequest(context.Background(), r, "APPROVAL_PROPOSE", want); err == nil {
		t.Fatal("cross-estate admission allowed")
	}
	entry.Active = false
	write()
	if _, err = a.AuthorizeAuthorityRequest(context.Background(), r, "AUTHENTICATE", ReferenceExpectation{}); err == nil {
		t.Fatal("revoked workload admitted")
	}
	entry.Active = true
	write()
	claims["aud"] = "wrong-service"
	r.Header.Set("Authorization", "Bearer "+signOIDC(t, key, claims))
	if _, err = a.AuthorizeAuthorityRequest(context.Background(), r, "AUTHENTICATE", ReferenceExpectation{}); err == nil {
		t.Fatal("wrong audience admitted")
	}
	claims["aud"] = "iam-authority"
	claims["actor_type"] = "human"
	r.Header.Set("Authorization", "Bearer "+signOIDC(t, key, claims))
	if _, err = a.AuthorizeAuthorityRequest(context.Background(), r, "AUTHENTICATE", ReferenceExpectation{}); err == nil {
		t.Fatal("human bearer admitted as workload")
	}
	claims["actor_type"] = "workload"
	r.Header.Set("Authorization", "Bearer "+signOIDC(t, key, claims))
	r.TLS.VerifiedChains = nil
	if _, err = a.AuthorizeAuthorityRequest(context.Background(), r, "AUTHENTICATE", ReferenceExpectation{}); err == nil {
		t.Fatal("unverified certificate admitted")
	}
}

func TestPrivateDocumentRejectsSymlinkAndPublicFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "document")
	if err := os.WriteFile(path, []byte("[]"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := privateDocument(path); err == nil {
		t.Fatal("public document admitted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := path + "-link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := privateDocument(link); err == nil {
		t.Fatal("symlink admitted")
	}
}
