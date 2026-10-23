package tokenprofile

import (
	"strings"
	"testing"
)

// Synthetic only: no server application is registered or allocated the scope.
func nativeCommitmentConfig(change func(*Workload)) Config {
	w := Workload{Environment: "staging", CredentialType: "client_credentials", Status: "PROVISIONED",
		Scopes: []string{nativeCommitmentSubmitScope}, Audiences: []string{nativeCommitmentAudience}}
	if change != nil {
		change(&w)
	}
	return Config{Environment: "staging", SharedCommit: "1517429bcae601a1b0288ca0279e524ce48a3d77",
		Workloads: map[string]Workload{"synthetic-server-checkout": w}}
}

func TestNativeCommitmentSubmitterIsANarrowServerWorkload(t *testing.T) {
	config := nativeCommitmentConfig(nil)
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	valid := Evidence{ClientID: "synthetic-server-checkout", Subject: "synthetic-server-checkout", Grant: "client_credentials",
		RequestedScopes: []string{nativeCommitmentSubmitScope}, GrantedScopes: []string{nativeCommitmentSubmitScope},
		GrantedAudiences: []string{nativeCommitmentAudience}}
	claims, err := config.Claims(valid)
	if err != nil || claims["actor_type"] != "workload" || claims["scope"] != nativeCommitmentSubmitScope {
		t.Fatalf("claims = %v, %v", claims, err)
	}

	for name, tc := range map[string]struct {
		change func(*Workload)
		reason string
	}{
		"without the Trade audience": {func(w *Workload) { w.Audiences = []string{"baobab-control-plane"} }, "audience"},
		"an estate BFF": {func(w *Workload) {
			w.Scopes = append(w.Scopes, buyerHandoffScope)
			w.HumanTokenProfile = &HumanTokenProfile{Purpose: estateBFFBuyerPurpose, Audiences: []string{"baobab-trade"},
				Scopes: []string{"trade:buy"}}
			w.HumanScopeAudiences = map[string][]string{"trade:buy": {"baobab-trade"}}
		}, "estate BFF"},
	} {
		t.Run(name, func(t *testing.T) {
			err := nativeCommitmentConfig(tc.change).Validate()
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("an invalid native commitment submitter was not refused for its %s: %v", tc.reason, err)
			}
		})
	}
	for _, id := range []string{"pk_01synthetic", "Synthetic-Server", "s", "synthetic_server"} {
		t.Run("client id "+id, func(t *testing.T) {
			c := nativeCommitmentConfig(nil)
			c.Workloads = map[string]Workload{id: c.Workloads["synthetic-server-checkout"]}
			if err := c.Validate(); err == nil {
				t.Fatalf("%q was accepted as a native commitment submitter", id)
			}
		})
	}

	wide := nativeCommitmentConfig(func(w *Workload) {
		w.Scopes = append(w.Scopes, "context:resolve")
		w.Audiences = append(w.Audiences, "baobab-control-plane")
	})
	if err := wide.Validate(); err != nil {
		t.Fatal(err)
	}
	e := valid
	e.GrantedAudiences = []string{nativeCommitmentAudience, "baobab-control-plane"}
	if _, err := wide.Claims(e); err == nil {
		t.Fatal("a native commitment token was issued for a second audience")
	}
	e.GrantedAudiences = []string{"baobab-control-plane"}
	if _, err := wide.Claims(e); err == nil {
		t.Fatal("a native commitment token was issued for another resource")
	}
	e = valid
	e.RequestedScopes, e.GrantedScopes = []string{"context:resolve"}, []string{"context:resolve"}
	e.GrantedAudiences = []string{"baobab-control-plane"}
	if _, err := wide.Claims(e); err != nil {
		t.Fatalf("the workload's other scopes stopped working: %v", err)
	}
}
