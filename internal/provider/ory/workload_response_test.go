package ory

import (
	"encoding/json"
	"github.com/baobab-platform/baobab-iam/internal/tokenprofile"
	"strings"
	"testing"
)

func TestProjectCanonicalWorkloadResponse(t *testing.T) {
	request := tokenprofile.WorkloadTokenRequest{WorkloadID: "worker", Audience: "baobab-cp", Scopes: []string{"context:resolve"}}
	valid := `{"access_token":"xxxxxxxxxxxxxxxxxxxx","token_type":"bearer","expires_in":60,"scope":"context:resolve","refresh_token":"secret","provider_extension":true}`
	response, err := ProjectWorkloadTokenResponse([]byte(valid), request)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(response)
	if err != nil || strings.Contains(string(wire), "secret") || strings.Contains(string(wire), "provider_extension") || response.TokenType != "Bearer" {
		t.Fatal("protocol projection leaked extensions or lost canonical type")
	}
	for _, raw := range []string{
		strings.Replace(valid, `"bearer"`, `"MAC"`, 1),
		strings.Replace(valid, `"expires_in":60`, `"expires_in":"60"`, 1),
		strings.Replace(valid, `"expires_in":60`, `"expires_in":60.000000000000001`, 1),
		strings.Replace(valid, `"context:resolve"`, `"context:resolve billing:read"`, 1),
		strings.Replace(valid, `"refresh_token":"secret"`, `"error":"invalid_grant"`, 1),
		strings.Replace(valid, `"provider_extension":true`, `"provider_extension":true,"provider_extension":false`, 1),
		valid + ` {}`, `[]`,
	} {
		out, err := ProjectWorkloadTokenResponse([]byte(raw), request)
		if err == nil || out.AccessToken != "" {
			t.Fatal("invalid OAuth response accepted or credential returned on failure")
		}
	}
}
