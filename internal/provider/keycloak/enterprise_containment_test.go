package keycloak_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider/keycloak"
)

const n06BrokerUser = "11111111-2222-4333-8444-555555555555"
const n06TrustID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
const n06SessionID = "XnbMW1Kj-6wi3jArVwvjjHIg"
const n06SubjectID = "dddddddd-eeee-4aaa-8bbb-ffffffffffff"
const n06Bearer = "fixture-only-restricted-admin-bearer"

type n06FederationReview struct {
	approve bool
}

func (a n06FederationReview) CurrentFederatedContainment(
	_ context.Context, _ keycloak.FederationContainmentTarget,
) (keycloak.FederationContainmentEvidence, error) {
	if !a.approve {
		return keycloak.FederationContainmentEvidence{}, errors.New("independent witness missing")
	}
	return keycloak.FederationContainmentEvidence{
		Approved: true, DistinctReviewer: true, CurrentTrust: true,
		ExactBoundIdentity: true, ObservedAt: time.Now().UTC(),
		OriginalReference: "ref_actualapprovedreview",
	}, nil
}

type n06FederationToken struct{}

func (n06FederationToken) CurrentAdminBearer(context.Context) (string, error) {
	return n06Bearer, nil
}
func TestN06FederatedBrokerSessionContainmentCurrentIdentityReadback(t *testing.T) {
	type config struct {
		approved     bool
		providerLink string
		subject      string
		surviving    bool
		noActive     bool
		wantSuccess  bool
		sessionID    string
	}
	for _, tc := range []struct {
		name  string
		value config
	}{
		{name: "current-link-and-revocation", value: config{approved: true, providerLink: "enterprise-oidc", subject: n06SubjectID, wantSuccess: true}},
		{name: "review-missing", value: config{approved: false, providerLink: "enterprise-oidc", subject: n06SubjectID}},
		{name: "provider-link-replaced", value: config{approved: true, providerLink: "different-enterprise", subject: n06SubjectID}},
		{name: "upstream-subject-replaced", value: config{approved: true, providerLink: "enterprise-oidc", subject: "another-upstream-identity"}},
		{name: "current-session-survives", value: config{approved: true, providerLink: "enterprise-oidc", subject: n06SubjectID, surviving: true}},
		{name: "no-actual-broker-session", value: config{approved: true, providerLink: "enterprise-oidc", subject: n06SubjectID, noActive: true}},
		{name: "malformed-broker-session", value: config{approved: true, providerLink: "enterprise-oidc", subject: n06SubjectID, sessionID: "../other"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logoutCalls := 0
			realm := "/admin/realms/mp8-broker/users/" + n06BrokerUser
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer "+n06Bearer {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == "GET" && r.URL.Path == realm+"/federated-identity":
					_ = json.NewEncoder(w).Encode([]map[string]string{
						{"identityProvider": tc.value.providerLink, "userId": tc.value.subject},
					})
				case r.Method == "GET" && r.URL.Path == realm+"/sessions":
					records := []map[string]string{}
					if !tc.value.noActive && (logoutCalls == 0 || tc.value.surviving) {
						sid := tc.value.sessionID
						if sid == "" {
							sid = n06SessionID
						}
						records = append(records, map[string]string{"id": sid, "userId": n06BrokerUser})
					}
					_ = json.NewEncoder(w).Encode(records)
				case r.Method == "POST" && r.URL.Path == realm+"/logout":
					logoutCalls++
					w.WriteHeader(http.StatusNoContent)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			containment := &keycloak.FederationLocalContainment{
				AdminOrigin: server.URL, BrokerRealm: "mp8-broker",
				Client: server.Client(), Tokens: n06FederationToken{},
				Reviewer: n06FederationReview{approve: tc.value.approved},
				Now:      time.Now, AllowTestLoopback: true,
			}
			target := keycloak.FederationContainmentTarget{
				TrustID: n06TrustID, UpstreamIssuer: "https://upstream.example.test",
				UpstreamSubject: n06SubjectID, BrokerUserID: n06BrokerUser,
				FederationAlias: "enterprise-oidc",
				ChangeReference: "ref_reviewedincident",
			}
			err := containment.RevokeBrokerSessions(context.Background(), target)
			if (err == nil) != tc.value.wantSuccess {
				t.Fatalf("wrong federation containment classification: %v", err)
			}
			if tc.value.wantSuccess && logoutCalls != 1 {
				t.Fatal("native Keycloak logout not invoked")
			}
			if !tc.value.approved || tc.value.subject != n06SubjectID ||
				tc.value.providerLink != "enterprise-oidc" || tc.value.noActive || tc.value.sessionID != "" {
				if logoutCalls != 0 {
					t.Fatal("unverified subject or absent sessions caused a native logout")
				}
			}
		})
	}
}
func TestN06FederatedBrokerContainmentRejectsScopeAndOriginSubstitution(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("unreviewed containment must not reach Keycloak")
	}))
	defer server.Close()
	base := keycloak.FederationContainmentTarget{
		TrustID: n06TrustID, UpstreamIssuer: "https://upstream.example.test",
		UpstreamSubject: n06SubjectID, BrokerUserID: n06BrokerUser,
		FederationAlias: "enterprise-oidc", ChangeReference: "ref_reviewedincident",
	}
	for _, tc := range []struct {
		name string
		edit func(*keycloak.FederationContainmentTarget)
	}{
		{"foreign-issuer", func(q *keycloak.FederationContainmentTarget) { q.UpstreamIssuer = "http://untrusted.local" }},
		{"foreign-realm-scope", func(q *keycloak.FederationContainmentTarget) { q.BrokerUserID = "../admin" }},
		{"unknown-trust", func(q *keycloak.FederationContainmentTarget) { q.TrustID = "not-a-trust" }},
		{"unreviewed-change", func(q *keycloak.FederationContainmentTarget) { q.ChangeReference = "" }},
		{"unexpected-provider-alias", func(q *keycloak.FederationContainmentTarget) { q.FederationAlias = "../../admin" }},
		{"missing-upstream", func(q *keycloak.FederationContainmentTarget) { q.UpstreamSubject = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := base
			tc.edit(&target)
			c := &keycloak.FederationLocalContainment{
				AdminOrigin: server.URL, BrokerRealm: "mp8-broker", Client: server.Client(),
				Tokens: n06FederationToken{}, Reviewer: n06FederationReview{approve: true},
				Now: time.Now, AllowTestLoopback: true,
			}
			if c.RevokeBrokerSessions(context.Background(), target) == nil {
				t.Fatal("malformed enterprise federation logout was accepted")
			}
		})
	}
	// The target's reviewed broker realm can never default to Keycloak master.
	c := &keycloak.FederationLocalContainment{AdminOrigin: server.URL, BrokerRealm: "master",
		Client: server.Client(), Tokens: n06FederationToken{},
		Reviewer: n06FederationReview{approve: true}, Now: time.Now, AllowTestLoopback: true}
	if c.RevokeBrokerSessions(context.Background(), base) == nil {
		t.Fatal("Keycloak master realm was admitted")
	}
	remote := &keycloak.FederationLocalContainment{
		AdminOrigin: "http://remote.invalid", BrokerRealm: "mp8-broker",
		Client: server.Client(), Tokens: n06FederationToken{},
		Reviewer: n06FederationReview{approve: true}, Now: time.Now, AllowTestLoopback: true,
	}
	if remote.RevokeBrokerSessions(context.Background(), base) == nil {
		t.Fatal("remote plain HTTP admin admitted")
	}
}
