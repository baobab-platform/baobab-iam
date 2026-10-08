package tokenprofile

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestCanonicalResponseSharedCorpus(t *testing.T) {
	raw, err := os.ReadFile("../../tests/fixtures/canonical-workload-response.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Valid    bool
		Response json.RawMessage
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for i, c := range cases {
		var response WorkloadTokenResponse
		if err := json.Unmarshal(c.Response, &response); (err == nil) != c.Valid {
			t.Fatalf("case %d validity mismatch", i)
		}
	}
	var decimal WorkloadTokenResponse
	if json.Unmarshal([]byte(`{"access_token":"xxxxxxxxxxxxxxxxxxxx","token_type":"Bearer","expires_in":6e1}`), &decimal) != nil {
		t.Fatal("JSON Schema integer form rejected")
	}
	for _, raw := range []string{
		`{"access_token":"xxxxxxxxxxxxxxxxxxxx","token_type":"Bearer","expires_in":60.000000000000001}`,
		`{"access_token":"xxxxxxxxxxxxxxxxxxxx","token_type":"Bearer","expires_in":60,"expires_in":61}`,
		`{"access_token":"xxxxxxxxxxxxxxxxxxxx","token_type":"Bearer","expires_in":60} {}`,
		`[]`,
	} {
		var response WorkloadTokenResponse
		if json.Unmarshal([]byte(raw), &response) == nil {
			t.Fatal("accepted invalid wire envelope")
		}
	}
}

func TestResponseScopeBinding(t *testing.T) {
	request := WorkloadTokenRequest{WorkloadID: "worker", Audience: "baobab-cp", Scopes: []string{"context:resolve", "billing:read"}}
	for _, scope := range []string{"billing:read context:resolve", "context:resolve", "context:resolve billing:read billing:read", "context:resolve billing:read extra:read", "context:resolve  billing:read", "context:resolve\tbilling:read"} {
		response := WorkloadTokenResponse{AccessToken: strings.Repeat("x", 20), TokenType: "Bearer", ExpiresIn: 60, Scope: &scope}
		if err := response.BindRequest(request); (err == nil) != (scope == "billing:read context:resolve") {
			t.Fatal("scope binding mismatch")
		}
	}
	response := WorkloadTokenResponse{AccessToken: strings.Repeat("x", 20), TokenType: "Bearer", ExpiresIn: 60}
	if response.BindRequest(request) == nil {
		t.Fatal("missing scope accepted")
	}
}
