package federation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

type brokerPortFixture struct{ calls int }

func (p *brokerPortFixture) BeginFederation(context.Context, provider.EnterpriseLogin) (provider.EnterpriseChallenge, error) {
	p.calls++
	return provider.EnterpriseChallenge{EventID: "fixture"}, nil
}
func (p *brokerPortFixture) CompleteFederation(context.Context, provider.EnterpriseCallback) (provider.EnterpriseEvent, error) {
	p.calls++
	return provider.EnterpriseEvent{EventID: "fixture"}, nil
}

type brokerActionAccess struct {
	denied  string
	actions []string
}

func (a *brokerActionAccess) AuthorizeAuthorityRequest(ctx context.Context, _ *http.Request, action string, _ ReferenceExpectation) (context.Context, error) {
	a.actions = append(a.actions, action)
	if action == a.denied {
		return nil, ErrDenied
	}
	return ctx, nil
}

func TestBrokerPrivateRoutesDenyUnadmittedWorkloadAndCrossOperationInput(t *testing.T) {
	e, _, s, _ := brokerSetup(t, "oidc")
	consumer, governance := setup(t, "oidc")
	for _, tc := range []struct{ name, denied, extra string }{
		{"authentication", "AUTHENTICATE", ""},
		{"action", "BROKER_BEGIN", ""},
		{"cross-operation", "", `,"Assertion":""`},
		{"case-alias", "", `,"sessiondigest":""`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			access := &brokerActionAccess{denied: tc.denied}
			port := &brokerPortFixture{}
			handler, err := NewServiceBrokerHandler(access, governance, port, e, consumer)
			if err != nil {
				t.Fatal(err)
			}
			body := `{"TrustID":"` + s.Trust.ID + `","SessionDigest":"` + secretDigest("browser") + `"` + tc.extra + `}`
			request := httptest.NewRequest("POST", "https://iam.example/internal/enterprise-federation/v1/begin", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusForbidden || port.calls != 0 {
				t.Fatal("private operation reached adapter without admission", response.Code)
			}
			if tc.denied == "AUTHENTICATE" && len(access.actions) != 1 {
				t.Fatal("unauthenticated request reached scoped authorization")
			}
		})
	}
}
