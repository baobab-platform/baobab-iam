package keycloak_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/federation"
	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/keycloak"
	"golang.org/x/net/html"
)

type liveEnterprise struct {
	mu       sync.Mutex
	s        federation.TrustSnapshot
	c        federation.BrokerConfiguration
	captured federation.ExternalPrincipal
}

func (f *liveEnterprise) Trust(context.Context, string) (federation.TrustSnapshot, error) {
	return f.s, nil
}
func (f *liveEnterprise) Reference(_ context.Context, w federation.ReferenceExpectation) (federation.ApprovedReference, error) {
	return federation.ApprovedReference{Expectation: w, Status: "APPROVED", NonSecret: true, ValidFrom: time.Now().Add(-time.Minute), ExpiresAt: f.s.ValidUntil}, nil
}
func (f *liveEnterprise) BrokerConfiguration(context.Context, federation.TrustSnapshot) (federation.BrokerConfiguration, error) {
	return f.c, nil
}
func (f *liveEnterprise) MapAssurance(_ context.Context, _ federation.TrustSnapshot, _ federation.ExternalPrincipal, a federation.Assurance) (federation.Assurance, error) {
	a.MappingStatus = "MAPPED"
	a.Level = "BAOBAB-A1"
	a.MappingEvidenceReference = "ref_ciliveevidence"
	return a, nil
}

// This test drives actual browser forms through two live pinned Keycloak realms,
// the compiled mapper, mTLS capture and the real authorization-code/PKCE exchange.
// Authority fixtures are explicitly not proof of CP/Staging activation.
func TestLiveKeycloakEnterpriseBroker(t *testing.T) {
	origin := os.Getenv("KEYCLOAK_ENTERPRISE_LIVE_URL")
	if origin == "" {
		t.Skip("requires pinned live Keycloak enterprise CI stack")
	}
	dir := os.Getenv("KEYCLOAK_ENTERPRISE_TLS_DIR")
	ca, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	defer client.CloseIdleConnections()
	admin := liveAdminToken(t, client, origin)
	adminRequest := func(method, path string, input any) {
		t.Helper()
		body, _ := json.Marshal(input)
		req, _ := http.NewRequest(method, origin+path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+admin)
		req.Header.Set("Content-Type", "application/json")
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			t.Fatalf("live fixture provisioning failed: %s %s status=%d", method, path, response.StatusCode)
		}
	}
	upstream := origin + "/realms/mp8-upstream"
	broker := origin + "/realms/mp8-broker"
	callback := "https://bff.example.test/callback"
	user := map[string]any{"username": "enterprise-user", "firstName": "Enterprise", "lastName": "Fixture", "email": "enterprise@example.test", "emailVerified": true, "enabled": true, "credentials": []any{map[string]any{"type": "password", "value": "fixture-only-user-password", "temporary": false}}}
	for _, name := range []string{"mp8-upstream", "mp8-broker"} {
		realm := map[string]any{"realm": name, "enabled": true, "sslRequired": "all", "accessTokenLifespan": 240}
		if name == "mp8-upstream" {
			realm["users"] = []any{user, map[string]any{"username": "enterprise-saml-user", "firstName": "SAML", "lastName": "Fixture", "email": "enterprise-saml@example.test", "emailVerified": true, "enabled": true, "credentials": []any{map[string]any{"type": "password", "value": "fixture-only-user-password", "temporary": false}}}}
		}
		adminRequest("POST", "/admin/realms", realm)
	}
	adminRequest("POST", "/admin/realms/mp8-upstream/clients", map[string]any{"clientId": "broker-upstream", "enabled": true, "publicClient": false, "secret": "fixture-only-upstream-secret", "standardFlowEnabled": true, "redirectUris": []string{broker + "/broker/enterprise-oidc/endpoint"}, "defaultClientScopes": []string{"profile", "email"}})
	noteMapper := map[string]any{"name": "upstream-evidence-digest", "protocol": "openid-connect", "protocolMapper": "oidc-usersessionmodel-note-mapper", "config": map[string]string{"user.session.note": "baobab_upstream_evidence_digest", "claim.name": "baobab_upstream_evidence_digest", "jsonType.label": "String", "id.token.claim": "true", "access.token.claim": "false", "userinfo.token.claim": "false"}}
	adminRequest("POST", "/admin/realms/mp8-broker/clients", map[string]any{"clientId": "enterprise-bff", "enabled": true, "publicClient": true, "standardFlowEnabled": true, "redirectUris": []string{callback}, "attributes": map[string]string{"pkce.code.challenge.method": "S256", "exclude.issuer.from.auth.response": "false"}, "protocolMappers": []any{noteMapper}})
	keys := liveJWKS(t, client, upstream)
	brokerKeys := liveJWKS(t, client, broker)
	var material struct {
		Keys []struct {
			X5C []string `json:"x5c"`
			Use string   `json:"use"`
			Alg string   `json:"alg"`
		} `json:"keys"`
	}
	json.Unmarshal(keys, &material)
	var signingPEM, signingDER string
	for _, k := range material.Keys {
		if k.Use == "sig" && k.Alg == "RS256" && len(k.X5C) > 0 {
			der, err := base64.StdEncoding.DecodeString(k.X5C[0])
			if err != nil {
				t.Fatal(err)
			}
			signingPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
			signingDER = k.X5C[0]
			break
		}
	}
	if signingPEM == "" {
		t.Fatal("live SAML signing certificate missing")
	}
	adminRequest("POST", "/admin/realms/mp8-upstream/clients", map[string]any{"clientId": broker, "protocol": "saml", "enabled": true, "redirectUris": []string{broker + "/broker/enterprise-saml/endpoint"}, "attributes": map[string]string{"saml.assertion.signature": "true", "saml.server.signature": "true", "saml.client.signature": "false", "saml.force.post.binding": "true", "saml_name_id_format": "persistent", "saml.authnstatement": "true", "saml.signature.algorithm": "RSA_SHA256"}})
	for _, protocol := range []string{"OIDC", "SAML2"} {
		t.Run(protocol, func(t *testing.T) {
			alias := "enterprise-oidc"
			uuid := "11111111-1111-4111-8111-111111111111"
			providerID := "oidc"
			idpConfig := map[string]string{"authorizationUrl": upstream + "/protocol/openid-connect/auth", "tokenUrl": upstream + "/protocol/openid-connect/token", "clientId": "broker-upstream", "clientSecret": "fixture-only-upstream-secret", "issuer": upstream, "useJwksUrl": "true", "jwksUrl": upstream + "/protocol/openid-connect/certs", "validateSignature": "true", "disableUserInfo": "true", "defaultScope": "openid profile email", "syncMode": "IMPORT", "storeTokenInSession": "false"}
			if protocol == "SAML2" {
				alias = "enterprise-saml"
				uuid = "22222222-2222-4222-8222-222222222222"
				providerID = "saml"
				idpConfig = map[string]string{"idpEntityId": upstream, "singleSignOnServiceUrl": upstream + "/protocol/saml", "nameIDPolicyFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", "validateSignature": "true", "signingCertificate": signingDER, "wantAssertionsSigned": "true", "wantAuthnRequestsSigned": "false", "postBindingResponse": "true", "postBindingAuthnRequest": "true", "syncMode": "IMPORT"}
			}
			adminRequest("POST", "/admin/realms/mp8-broker/identity-provider/instances", map[string]any{"alias": alias, "providerId": providerID, "enabled": true, "storeToken": false, "config": idpConfig})
			adminRequest("POST", "/admin/realms/mp8-broker/identity-provider/instances/"+alias+"/mappers", map[string]any{"name": "private-evidence", "identityProviderAlias": alias, "identityProviderMapper": "baobab-evidence-bridge", "config": map[string]string{"trust-id": uuid, "client-id": "enterprise-bff", "syncMode": "INHERIT"}})
			now := time.Now().UTC()
			binding := federation.Binding{ProviderID: "provider_cienterprise", EngineInstanceID: "ei_cienterprise", ConfigurationReference: "ref_ciliveconfig", TrustMaterialReference: "ref_cilivetrust"}
			trust := federation.Trust{ID: uuid, Protocol: protocol, UpstreamIssuer: upstream, OrganisationIDs: []string{"org_cisynthetic"}, EstateIDs: []string{"estate_ci"}, ProviderBinding: binding, Status: "ACTIVE", AssurancePolicyReference: "ref_ciassurance", AttributeMappingReference: "ref_ciattributes", ProvisioningPolicyReference: "ref_ciprovision", Revision: 1, CreatedAt: now.Add(-time.Minute), UpdatedAt: now, ActivatedAt: &now, ActivationEvidenceReference: "ref_ciactivation"}
			f := &liveEnterprise{s: federation.TrustSnapshot{Trust: trust, ApprovedRevision: 1, SnapshotID: "live-fixture-snapshot", ValidUntil: now.Add(10 * time.Minute)}}
			f.c = federation.BrokerConfiguration{TrustID: uuid, SnapshotID: f.s.SnapshotID, Revision: 1, Binding: binding, Settings: federation.BrokerSettings{Issuer: broker, ClientID: "enterprise-bff", AuthorizationEndpoint: broker + "/protocol/openid-connect/auth", TokenEndpoint: broker + "/protocol/openid-connect/token", RedirectURI: callback, ProviderRoute: alias, SigningAlgorithm: "RS256"}, BrokerJWKS: brokerKeys, Upstream: federation.OIDCConfiguration{TrustID: uuid, SnapshotID: f.s.SnapshotID, Revision: 1, Binding: binding, ClientID: "broker-upstream", SigningAlgorithm: "RS256", JWKS: keys, ValidUntil: f.s.ValidUntil}, SAML: federation.SAMLSettings{EntityID: broker, ACSURL: broker + "/broker/" + alias + "/endpoint"}, SigningCertificates: []string{signingPEM}, ValidUntil: f.s.ValidUntil}
			events, err := federation.OpenBrokerEvents(federation.BrokerEventsConfig{Path: filepath.Join(t.TempDir(), "broker.db"), Configuration: f, Mapper: f, Client: client, Now: time.Now, MaxLifetime: 15 * time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			defer events.Close()
			serverPair, err := tls.LoadX509KeyPair(filepath.Join(dir, "authority.crt"), filepath.Join(dir, "authority.key"))
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "0.0.0.0:9444")
			if err != nil {
				t.Fatal(err)
			}
			captureServer := &http.Server{ReadHeaderTimeout: 5 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverPair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/capture" || r.Header.Get("Authorization") != "Bearer fixture-only-bridge-bearer" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.TLS.PeerCertificates[0].Subject.CommonName != "bridge" {
					w.WriteHeader(403)
					return
				}
				var evidence federation.BrokerEvidence
				body, _ := io.ReadAll(io.LimitReader(r.Body, 131073))
				if len(body) > 131072 || json.Unmarshal(body, &evidence) != nil {
					w.WriteHeader(400)
					return
				}
				if err := events.Capture(r.Context(), f.s, evidence); err != nil {
					t.Errorf("live %s capture failed: %v", protocol, err)
					w.WriteHeader(403)
					return
				}
				w.WriteHeader(204)
			})}
			go captureServer.ServeTLS(listener, "", "")
			defer captureServer.Close()
			adapter := &keycloak.EnterpriseAdapter{Events: events, Governance: f, Configuration: f, ProviderID: binding.ProviderID, EngineInstanceID: binding.EngineInstanceID, Issuer: broker}
			secret := strings.Repeat("live-browser-private-", 3)
			challenge, err := adapter.BeginFederation(context.Background(), provider.EnterpriseLogin{TrustID: uuid, SessionDigest: liveDigest(secret)})
			if err != nil {
				t.Fatal(err)
			}
			username := "enterprise-user"
			if protocol == "SAML2" {
				username = "enterprise-saml-user"
			}
			result := liveBrowser(t, transport, challenge.AuthorizationURL, callback, username)
			if result.Get("state") != challenge.State {
				t.Fatal("live callback state changed")
			}
			_, err = adapter.CompleteFederation(context.Background(), provider.EnterpriseCallback{TrustID: uuid, EventID: challenge.EventID, State: challenge.State, BrowserSecret: secret, PKCEVerifier: challenge.PKCEVerifier, Code: result.Get("code"), Issuer: result.Get("iss")})
			if err != nil {
				t.Fatal("live broker completion", err)
			}
			principal, assurance, err := events.Verify(context.Background(), challenge.EventID, f.s)
			if err != nil {
				t.Fatal(err)
			}
			if principal.Issuer != upstream || assurance.Protocol != protocol || assurance.Level != "BAOBAB-A1" {
				t.Fatal("upstream evidence changed")
			}
			if protocol == "SAML2" && (assurance.UpstreamEvidence.SAML == nil || !strings.HasPrefix(principal.Subject, "saml2:persistent:")) {
				t.Fatal("SAML provenance absent")
			}
			if _, _, err = events.Verify(context.Background(), challenge.EventID, f.s); err == nil {
				t.Fatal("live event replay accepted")
			}
			t.Logf("actual Keycloak broker %s login, private mTLS evidence export, independent signatures, PKCE completion and replay denial passed", protocol)
		})
	}
}
func liveDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("sha256:%x", sum)
}
func liveAdminToken(t *testing.T, client *http.Client, origin string) string {
	t.Helper()
	form := url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {"admin"}, "password": {"fixture-only-admin-password"}}
	response, err := client.PostForm(origin+"/realms/master/protocol/openid-connect/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if json.NewDecoder(response.Body).Decode(&token) != nil || response.StatusCode != 200 || token.AccessToken == "" {
		t.Fatal("live fixture admin unavailable")
	}
	return token.AccessToken
}
func liveJWKS(t *testing.T, client *http.Client, issuer string) json.RawMessage {
	t.Helper()
	response, err := client.Get(issuer + "/protocol/openid-connect/certs")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 32769))
	if err != nil || response.StatusCode != 200 || len(raw) > 32768 {
		t.Fatal("live signing keys unavailable")
	}
	var keys struct {
		Keys []map[string]any `json:"keys"`
	}
	if json.Unmarshal(raw, &keys) != nil {
		t.Fatal("invalid live JWKS")
	}
	selected := []map[string]any{}
	for _, key := range keys.Keys {
		if key["alg"] == "RS256" && key["use"] == "sig" {
			selected = append(selected, key)
		}
	}
	data, _ := json.Marshal(map[string]any{"keys": selected})
	return data
}

func liveBrowser(t *testing.T, transport http.RoundTripper, start, callback, usernameValue string) url.Values {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Transport: transport, Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if strings.HasPrefix(r.URL.String(), callback) {
			return http.ErrUseLastResponse
		}
		if len(via) > 15 {
			return fmt.Errorf("too many browser redirects")
		}
		if r.URL.Scheme != "https" || r.URL.Host != "localhost:8443" {
			return fmt.Errorf("unexpected browser origin")
		}
		return nil
	}}
	next := start
	method := "GET"
	form := url.Values{}
	for step := 0; step < 12; step++ {
		var req *http.Request
		if method == "POST" {
			req, _ = http.NewRequest(method, next, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			req, _ = http.NewRequest(method, next, nil)
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		location := response.Header.Get("Location")
		if strings.HasPrefix(location, callback) {
			response.Body.Close()
			u, _ := url.Parse(location)
			if u.Query().Get("code") == "" {
				t.Fatal("live browser returned no code")
			}
			return u.Query()
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 262145))
		response.Body.Close()
		if err != nil || len(body) > 262144 || response.StatusCode != 200 {
			t.Fatalf("live browser failed step %d status %d", step, response.StatusCode)
		}
		document, err := html.Parse(bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		var action string
		fields := url.Values{}
		username := false
		var walk func(*html.Node)
		walk = func(n *html.Node) {
			if n.Type == html.ElementNode {
				attrs := map[string]string{}
				for _, a := range n.Attr {
					attrs[a.Key] = a.Val
				}
				if n.Data == "form" && action == "" {
					action = attrs["action"]
				}
				if n.Data == "input" && attrs["name"] != "" {
					fields.Set(attrs["name"], attrs["value"])
					if attrs["name"] == "username" {
						username = true
					}
				}
			}
			for child := n.FirstChild; child != nil; child = child.NextSibling {
				walk(child)
			}
		}
		walk(document)
		if action == "" {
			t.Fatalf("live browser has no actionable form at step %d", step)
		}
		u, _ := url.Parse(action)
		base, _ := url.Parse(response.Request.URL.String())
		resolved := base.ResolveReference(u)
		if resolved.Scheme != "https" || resolved.Host != "localhost:8443" {
			t.Fatal("unexpected form target")
		}
		if username {
			fields.Set("username", usernameValue)
			fields.Set("password", "fixture-only-user-password")
		}
		if _, ok := fields["firstName"]; ok {
			fields.Set("firstName", "Enterprise")
		}
		if _, ok := fields["lastName"]; ok {
			fields.Set("lastName", "Fixture")
		}
		if _, ok := fields["email"]; ok {
			fields.Set("email", usernameValue+"@example.test")
		}
		next = resolved.String()
		method = "POST"
		form = fields
	}
	t.Fatal("live browser exceeded form budget")
	return nil
}
