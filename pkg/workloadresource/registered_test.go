package workloadresource

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type n04Provider struct {
	calls int
	onRead func(int) error
}
func (p *n04Provider) CheckCapability(_ context.Context, key string) error {
	p.calls++
	if key != WorkloadIssueCapability {
		return ErrDenied
	}
	if p.onRead != nil {
		return p.onRead(p.calls)
	}
	return nil
}

type n04Resource struct {
	calls int
	onCall func() error
}
func (r *n04Resource) Authorize(_ context.Context, bearer string, op Operation) error {
	r.calls++
	if bearer != "signed-test-bearer-valid-for-control" || op.ContextID != "ctx_source" {
		return ErrDenied
	}
	if r.onCall != nil {
		return r.onCall()
	}
	return nil
}

type n04Operation struct{}
func (n04Operation) ResolveOperation(_ context.Context, _ *http.Request) (Operation, error) {
	return Operation{ContextID: "ctx_source", TenantID: "tn_owner", ResourceOperation: "evidence.search"}, nil
}

func TestN04RegisteredGateRechecksCurrentCPBeforeAndAfterResource(t *testing.T) {
	for _, tc := range []struct {
		name string
		firstDenied, secondDenied, resourceDenied bool
		wantCalls, wantResourceCalls int
		wantAllow bool
	}{
		{"current CP and native authorizer", false, false, false, 2, 1, true},
		{"CP registration absent", true, false, false, 1, 0, false},
		{"CP revoked between resource check and delivery", false, true, false, 2, 1, false},
		{"native business PEP refused", false, false, true, 1, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp := &n04Provider{onRead: func(call int) error {
				if call == 1 && tc.firstDenied || call == 2 && tc.secondDenied {
					return errors.New("registered CP source unavailable or denied")
				}
				return nil
			}}
			native := &n04Resource{onCall: func() error {
				if tc.resourceDenied {
					return ErrDenied
				}
				return nil
			}}
			gate, err := newRegisteredGate(native, cp)
			if err != nil {
				t.Fatal(err)
			}
			err = gate.Authorize(context.Background(), "signed-test-bearer-valid-for-control",
				Operation{ContextID: "ctx_source", TenantID: "tn_owner", ResourceOperation: "evidence.search"})
			if (err == nil) != tc.wantAllow || cp.calls != tc.wantCalls || native.calls != tc.wantResourceCalls {
				t.Fatalf("incorrect N04 gate: err=%v CP=%d native=%d", err, cp.calls, native.calls)
			}
		})
	}
}

func TestN04GateDeniesMissingAndCancelledDependencies(t *testing.T) {
	if _, err := NewRegisteredGate(nil, &n04Provider{}); err == nil {
		t.Fatal("missing token/CP/native resource gate accepted")
	}
	if _, err := newRegisteredGate(&n04Resource{}, (*n04Provider)(nil)); err == nil {
		t.Fatal("typed-nil CP authority admitted")
	}
	if _, err := newRegisteredGate((*n04Resource)(nil), &n04Provider{}); err == nil {
		t.Fatal("typed-nil native gate admitted")
	}
	native, cp := &n04Resource{}, &n04Provider{}
	gate, err := newRegisteredGate(native, cp)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if gate.Authorize(ctx, "signed-test-bearer-valid-for-control", Operation{ContextID:"ctx_source"}) == nil ||
		cp.calls != 0 || native.calls != 0 {
		t.Fatal("cancelled context reached CP or native gate")
	}
}

func TestN04HTTPAcceptsOnlyRegisteredDoubleCurrentCP(t *testing.T) {
	cp := &n04Provider{}
	resourceGate, _, _, _ := fixture(t)
	g, err := NewRegisteredGate(resourceGate, cp)
	if err != nil {
		t.Fatal(err)
	}
	nextCalled := false
	handler, err := NewMiddleware(g, n04Operation{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("raw bearer or browser cookie reached native engine")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatal(err)
	}
	send := func() int {
		request := httptest.NewRequest(http.MethodPost, "/v1/evidence", nil)
		request.Header.Set("Authorization", "Bearer signed-test-bearer-valid-for-control")
		request.Header.Set("Cookie", "session=fake")
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, request)
		return resp.Code
	}
	if got := send(); got != http.StatusNoContent || !nextCalled || cp.calls != 2 {
		t.Fatalf("registered HTTP acceptance failed: status=%d, cp calls=%d", got, cp.calls)
	}
	nextCalled = false
	cp.onRead = func(int) error { return ErrDenied }
	if got := send(); got != http.StatusForbidden || nextCalled || cp.calls != 3 {
		t.Fatalf("withdrawn CP support reached native owner: status=%d, cp calls=%d", got, cp.calls)
	}
}

func TestN04HTTPRefusesUnregisteredNilAuthorizer(t *testing.T) {
	_, err := NewMiddleware((*RegisteredGate)(nil), n04Operation{}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err == nil {
		t.Fatal("typed nil registered authorizer accepted")
	}
	if _, err := NewMiddleware(&n04Resource{}, n04Operation{},
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})); err == nil {
		t.Fatal("unverified unsigned fake resource was accepted as middleware")
	}
	internalOnly, err := newRegisteredGate(&n04Resource{}, &n04Provider{})
	if err != nil { t.Fatal(err) }
	if _, err := NewMiddleware(internalOnly, n04Operation{},
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})); err == nil {
		t.Fatal("unsigned internal fixture got deployed HTTP admission")
	}
}
