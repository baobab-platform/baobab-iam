package federation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	jose "github.com/go-jose/go-jose/v4"
	dsig "github.com/russellhaering/goxmldsig"
)

type brokerFixture struct {
	config                  BrokerConfiguration
	clock                   time.Time
	downstreamNonce, digest string
	key                     *rsa.PrivateKey
	exchangeCalls           int
	badProof                bool
	rawResponse             string
	server                  *httptest.Server
}

func (f *brokerFixture) BrokerConfiguration(context.Context, TrustSnapshot) (BrokerConfiguration, error) {
	return f.config, nil
}
func (f *brokerFixture) MapAssurance(_ context.Context, _ TrustSnapshot, _ ExternalPrincipal, a Assurance) (Assurance, error) {
	a.MappingStatus = "MAPPED"
	a.Level = "BAOBAB-A1"
	a.MappingEvidenceReference = "ref_cidecision"
	return a, nil
}
func brokerSetup(t *testing.T, protocol string) (*BrokerEvents, *brokerFixture, TrustSnapshot, string) {
	t.Helper()
	_, base := setup(t, protocol)
	now := time.Now().UTC().Truncate(time.Second)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "ci-signing-key", Algorithm: "RS256", Use: "sig"}}})
	s := base.snapshot
	s.Trust.UpdatedAt = now
	s.ValidUntil = now.Add(10 * time.Minute)
	f := &brokerFixture{clock: now, key: key}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.exchangeCalls++
		if f.rawResponse != "" {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, f.rawResponse)
			return
		}
		r.ParseForm()
		if r.Form.Get("code_verifier") == "" || r.Form.Get("grant_type") != "authorization_code" {
			t.Error("PKCE exchange absent")
			w.WriteHeader(400)
			return
		}
		digest := f.digest
		if f.badProof {
			digest = "sha256:" + strings.Repeat("f", 64)
		}
		claims := map[string]any{"iss": f.config.Settings.Issuer, "sub": "broker-local-subject", "aud": f.config.Settings.ClientID, "exp": f.clock.Add(4 * time.Minute).Unix(), "iat": f.clock.Unix(), "auth_time": f.clock.Unix(), "nonce": f.downstreamNonce, "baobab_upstream_evidence_digest": digest}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": strings.Repeat("fixture-access-token-", 2), "token_type": "bearer", "expires_in": 240, "scope": "openid", "id_token": signOIDC(t, key, claims)})
	}))
	t.Cleanup(f.server.Close)
	f.config = BrokerConfiguration{TrustID: s.Trust.ID, SnapshotID: s.SnapshotID, Revision: s.ApprovedRevision, Binding: s.Trust.ProviderBinding, Settings: BrokerSettings{Issuer: f.server.URL, ClientID: "bff", AuthorizationEndpoint: f.server.URL + "/auth", TokenEndpoint: f.server.URL + "/token", RedirectURI: "https://bff.example/callback", ProviderRoute: "enterprise", SigningAlgorithm: "RS256"}, BrokerJWKS: keys, Upstream: OIDCConfiguration{TrustID: s.Trust.ID, SnapshotID: s.SnapshotID, Revision: s.ApprovedRevision, Binding: s.Trust.ProviderBinding, ClientID: "broker-upstream", SigningAlgorithm: "RS256", JWKS: keys, ValidUntil: s.ValidUntil}, SAML: SAMLSettings{EntityID: "https://broker.example/realm", ACSURL: "https://broker.example/broker/enterprise/endpoint"}, ValidUntil: s.ValidUntil}
	if protocol == "saml2" {
		cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "upstream"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		f.config.SigningCertificates = []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	}
	path := filepath.Join(t.TempDir(), "broker.db")
	e, err := OpenBrokerEvents(BrokerEventsConfig{Path: path, Configuration: f, Mapper: f, Client: f.server.Client(), Now: func() time.Time { return f.clock }, MaxLifetime: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e, f, s, path
}
func upstreamOIDC(t *testing.T, f *brokerFixture, s TrustSnapshot, nonce string) string {
	return signOIDC(t, f.key, map[string]any{"iss": s.Trust.UpstreamIssuer, "sub": "upstream-stable-human", "aud": f.config.Upstream.ClientID, "exp": f.clock.Add(4 * time.Minute).Unix(), "iat": f.clock.Unix(), "auth_time": f.clock.Unix(), "nonce": nonce, "acr": "urn:enterprise:mfa", "amr": []string{"pwd", "otp"}})
}
func signedBrokerSAML(t *testing.T, f *brokerFixture, s TrustSnapshot, requestID string, mutate func(*saml.Assertion)) string {
	t.Helper()
	now := f.clock
	expires := now.Add(3 * time.Minute)
	assertion := &saml.Assertion{ID: "assertion-ci", Version: "2.0", IssueInstant: now, Issuer: saml.Issuer{Value: s.Trust.UpstreamIssuer}, Subject: &saml.Subject{NameID: &saml.NameID{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", NameQualifier: s.Trust.UpstreamIssuer, SPNameQualifier: f.config.SAML.EntityID, Value: "stable-saml-human"}, SubjectConfirmations: []saml.SubjectConfirmation{{Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer", SubjectConfirmationData: &saml.SubjectConfirmationData{InResponseTo: requestID, Recipient: f.config.SAML.ACSURL, NotOnOrAfter: expires}}}}, Conditions: &saml.Conditions{NotBefore: now.Add(-time.Second), NotOnOrAfter: expires, AudienceRestrictions: []saml.AudienceRestriction{{Audience: saml.Audience{Value: f.config.SAML.EntityID}}}}, AuthnStatements: []saml.AuthnStatement{{AuthnInstant: now, SessionNotOnOrAfter: &expires, AuthnContext: saml.AuthnContext{AuthnContextClassRef: &saml.AuthnContextClassRef{Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"}}}}}
	if mutate != nil {
		mutate(assertion)
	}
	block, _ := pem.Decode([]byte(f.config.SigningCertificates[0]))
	signer, err := dsig.NewSigningContext(f.key, [][]byte{block.Bytes})
	if err != nil {
		t.Fatal(err)
	}
	signer.IdAttribute = "ID"
	signer.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	response := saml.Response{ID: "response-ci", Version: "2.0", IssueInstant: now, InResponseTo: requestID, Destination: f.config.SAML.ACSURL, Issuer: &saml.Issuer{Value: s.Trust.UpstreamIssuer}, Status: saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}}, Assertion: assertion}
	root := response.Element()
	assertionElement := root.FindElement("./Assertion")
	signed, err := signer.SignEnveloped(assertionElement)
	if err != nil {
		t.Fatal(err)
	}
	root.RemoveChild(assertionElement)
	root.AddChild(signed)
	doc := etree.NewDocument()
	doc.SetRoot(root)
	raw, err := doc.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func runBrokerCapture(t *testing.T, e *BrokerEvents, f *brokerFixture, s TrustSnapshot) (BrokerChallenge, string) {
	t.Helper()
	secret := strings.Repeat("browser-private-", 3)
	r, err := e.Begin(context.Background(), s, secretDigest(secret))
	if err != nil {
		t.Fatal(err)
	}
	f.downstreamNonce = r.Nonce
	raw := upstreamOIDC(t, f, s, "upstream-request-nonce")
	if s.Trust.Protocol == "SAML2" {
		raw = signedBrokerSAML(t, f, s, "upstream-request-id", nil)
	}
	f.digest = secretDigest(raw)
	correlation := "upstream-request-nonce"
	if s.Trust.Protocol == "SAML2" {
		correlation = "upstream-request-id"
	}
	if err = e.Capture(context.Background(), s, BrokerEvidence{s.Trust.ID, r.Nonce, "enterprise", correlation, raw}); err != nil {
		t.Fatal(err)
	}
	return r, secret
}
func TestBrokerOIDCAndSAMLVerifyUpstreamAndFenceReplayAcrossRestart(t *testing.T) {
	for _, protocol := range []string{"oidc", "saml2"} {
		t.Run(protocol, func(t *testing.T) {
			e, f, s, path := brokerSetup(t, protocol)
			r, secret := runBrokerCapture(t, e, f, s)
			if err := e.Complete(context.Background(), s, BrokerCallback{r.EventID, r.State, secret, r.PKCEVerifier, "code", f.config.Settings.Issuer}); err != nil {
				t.Fatal(err)
			}
			raw, _ := os.ReadFile(path)
			for _, value := range []string{r.State, r.Nonce, r.PKCEVerifier, secret} {
				if strings.Contains(string(raw), value) {
					t.Fatal("browser secrets persisted")
				}
			}
			e.Close()
			reopened, err := OpenBrokerEvents(e.cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			p, a, err := reopened.Verify(context.Background(), r.EventID, s)
			if err != nil {
				t.Fatal(err)
			}
			if p.Subject == "broker-local-subject" || p.Issuer != s.Trust.UpstreamIssuer || a.Level != "BAOBAB-A1" {
				t.Fatal("downstream identity substituted upstream")
			}
			if protocol == "saml2" && (a.UpstreamEvidence.SAML == nil || a.UpstreamEvidence.OIDC != nil) {
				t.Fatal("SAML became invented OIDC evidence")
			}
			if _, _, err = reopened.Verify(context.Background(), r.EventID, s); err == nil {
				t.Fatal("replay accepted after restart")
			}
			if err = reopened.Complete(context.Background(), s, BrokerCallback{r.EventID, r.State, secret, r.PKCEVerifier, "code", f.config.Settings.Issuer}); err == nil {
				t.Fatal("callback replay accepted")
			}
		})
	}
}
func TestBrokerDownstreamTokenAloneAndWrongEvidenceCannotAuthenticate(t *testing.T) {
	e, f, s, _ := brokerSetup(t, "saml2")
	secret := strings.Repeat("b", 40)
	r, err := e.Begin(context.Background(), s, secretDigest(secret))
	if err != nil {
		t.Fatal(err)
	}
	if e.Complete(context.Background(), s, BrokerCallback{r.EventID, r.State, secret, r.PKCEVerifier, "code", f.config.Settings.Issuer}) == nil || f.exchangeCalls != 0 {
		t.Fatal("downstream token substituted upstream evidence")
	}
	r, secret = runBrokerCapture(t, e, f, s)
	f.badProof = true
	if e.Complete(context.Background(), s, BrokerCallback{r.EventID, r.State, secret, r.PKCEVerifier, "code", f.config.Settings.Issuer}) == nil {
		t.Fatal("wrong upstream digest accepted")
	}
}
func TestSAMLSignaturesNameIDAuthnContextAndProtocolConstraints(t *testing.T) {
	_, f, s, _ := brokerSetup(t, "saml2")
	cases := map[string]func(*saml.Assertion){"email-nameid": func(a *saml.Assertion) {
		a.Subject.NameID.Format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	}, "qualifier": func(a *saml.Assertion) { a.Subject.NameID.SPNameQualifier = "https://other-sp.example" }, "recipient": func(a *saml.Assertion) {
		a.Subject.SubjectConfirmations[0].SubjectConfirmationData.Recipient = "https://attacker.example"
	}, "request": func(a *saml.Assertion) {
		a.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = "other-request"
	}, "audience": func(a *saml.Assertion) { a.Conditions.AudienceRestrictions = nil }, "authn-context": func(a *saml.Assertion) { a.AuthnStatements[0].AuthnContext.AuthnContextClassRef = nil }, "expired": func(a *saml.Assertion) { a.Conditions.NotOnOrAfter = f.clock.Add(-time.Second) }, "missing-subject": func(a *saml.Assertion) { a.Subject = nil }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			raw := signedBrokerSAML(t, f, s, "upstream-request-id", mutate)
			if _, _, _, err := verifyBrokerSAML(s, f.config, raw, "upstream-request-id", f.clock, f.clock, 10*time.Minute); err == nil {
				t.Fatal("invalid signed SAML accepted")
			}
		})
	}
	raw := signedBrokerSAML(t, f, s, "upstream-request-id", nil)
	tampered := strings.Replace(raw, "stable-saml-human", "forged-human", 1)
	if _, _, _, err := verifyBrokerSAML(s, f.config, tampered, "upstream-request-id", f.clock, f.clock, 10*time.Minute); err == nil {
		t.Fatal("tampered signed XML accepted")
	}
	doc := etree.NewDocument()
	doc.ReadFromString(raw)
	assertion := doc.Root().FindElement("./Assertion")
	doc.Root().AddChild(assertion.Copy())
	wrapped, _ := doc.WriteToString()
	if boundedSAMLXML(wrapped) == nil {
		t.Fatal("multiple assertions accepted")
	}
	digest := sha256.Sum256([]byte(raw))
	if secretDigest(raw) != "sha256:"+hex.EncodeToString(digest[:]) {
		t.Fatal("bridge digest mismatch")
	}
}

func TestBrokerCallbackBindingsDenyBeforeCodeExchange(t *testing.T) {
	for _, field := range []string{"state", "browser", "pkce", "issuer", "event", "configuration"} {
		t.Run(field, func(t *testing.T) {
			e, f, s, _ := brokerSetup(t, "oidc")
			r, secret := runBrokerCapture(t, e, f, s)
			callback := BrokerCallback{r.EventID, r.State, secret, r.PKCEVerifier, "code", f.config.Settings.Issuer}
			switch field {
			case "state":
				callback.State += "wrong"
			case "browser":
				callback.BrowserSecret += "wrong"
			case "pkce":
				callback.PKCEVerifier += "wrong"
			case "issuer":
				callback.Issuer = "https://other.example"
			case "event":
				callback.EventID = "00000000-0000-4000-8000-000000000000"
			case "configuration":
				f.config.Settings.ProviderRoute = "other"
			}
			if e.Complete(context.Background(), s, callback) == nil || f.exchangeCalls != 0 {
				t.Fatal("unbound callback reached code exchange")
			}
		})
	}
}

func TestBrokerCaptureReplayAndClockFenceSurviveRestart(t *testing.T) {
	e, f, s, _ := brokerSetup(t, "oidc")
	r, _ := runBrokerCapture(t, e, f, s)
	raw := upstreamOIDC(t, f, s, "upstream-request-nonce")
	e.Close()
	reopened, err := OpenBrokerEvents(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.Capture(context.Background(), s, BrokerEvidence{s.Trust.ID, r.Nonce, "enterprise", "upstream-request-nonce", raw}) == nil {
		t.Fatal("capture replay accepted after restart")
	}
	f.clock = f.clock.Add(6 * time.Minute)
	if _, err = reopened.Prune(context.Background(), 128); err != nil {
		t.Fatal(err)
	}
	f.clock = f.clock.Add(-6 * time.Minute)
	if _, err = reopened.Prune(context.Background(), 128); err == nil {
		t.Fatal("clock rollback accepted after pruning")
	}
}

func TestBrokerMalformedCanonicalResponseBurnsCallback(t *testing.T) {
	e, f, s, _ := brokerSetup(t, "oidc")
	defer e.Close()
	r, secret := runBrokerCapture(t, e, f, s)
	callback := BrokerCallback{r.EventID, r.State, secret, r.PKCEVerifier, "code", f.config.Settings.Issuer}
	f.rawResponse = `{"id_token":"yyyyyyyyyyyyyyyyyyyy"}`
	if e.Complete(context.Background(), s, callback) == nil || f.exchangeCalls != 1 {
		t.Fatal("malformed canonical response authenticated a callback")
	}
	f.rawResponse = ""
	if e.Complete(context.Background(), s, callback) == nil || f.exchangeCalls != 1 {
		t.Fatal("failed canonical handoff permitted a second code exchange")
	}
	if _, _, err := e.Verify(context.Background(), r.EventID, s); err == nil {
		t.Fatal("failed canonical handoff produced an authentication event")
	}
}

func TestBrokerCanonicalTokenResponse(t *testing.T) {
	e, f, _, _ := brokerSetup(t, "oidc")
	defer e.Close()
	valid := `{"access_token":"xxxxxxxxxxxxxxxxxxxx","token_type":"bearer","expires_in":240,"id_token":"yyyyyyyyyyyyyyyyyyyy","scope":"openid","not-before-policy":0}`
	f.rawResponse = valid
	if token, err := e.exchange(context.Background(), f.config, "code", strings.Repeat("v", 43)); err != nil || token != strings.Repeat("y", 20) {
		t.Fatalf("canonical broker exchange failed: %v", err)
	}
	for _, raw := range []string{
		`{"id_token":"yyyyyyyyyyyyyyyyyyyy"}`,
		strings.Replace(valid, `"expires_in":240`, `"expires_in":240.5`, 1),
		strings.Replace(valid, `"access_token":"xxxxxxxxxxxxxxxxxxxx"`, `"access_token":null`, 1),
		strings.Replace(valid, `"id_token":"yyyyyyyyyyyyyyyyyyyy"`, `"id_token":null`, 1),
		strings.Replace(valid, `"not-before-policy":0`, `"error":"invalid_grant"`, 1),
		valid + `{}`,
	} {
		f.rawResponse = raw
		if token, err := e.exchange(context.Background(), f.config, "code", strings.Repeat("v", 43)); err == nil || token != "" {
			t.Fatal("invalid broker response released an ID token")
		}
	}
}

func TestBrokerSAMLReadinessRequiresCurrentUsableSigningMaterial(t *testing.T) {
	e, f, s, _ := brokerSetup(t, "saml2")
	if err := e.Ready(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	original := f.config.SigningCertificates
	f.config.SigningCertificates = []string{"invalid-certificate"}
	if e.Ready(context.Background(), s) == nil {
		t.Fatal("malformed signing material reported ready")
	}
	f.config.SigningCertificates = original
	f.clock = f.clock.Add(2 * time.Hour)
	s.ValidUntil = f.clock.Add(10 * time.Minute)
	f.config.ValidUntil = s.ValidUntil
	if e.Ready(context.Background(), s) == nil {
		t.Fatal("expired signing material reported ready")
	}
}
