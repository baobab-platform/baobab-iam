package humanauth

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOAuthHumanProjection(t *testing.T) {
	raw := `{"access_token":"xxxxxxxxxxxxxxxxxxxx","token_type":"bearer","expires_in":300,"id_token":"yyyyyyyyyyyyyyyyyyyy","refresh_token":"zzzzzzzzzzzzzzzzzzzz","scope":"openid","session_state":"provider-session","not-before-policy":0,"realm":"provider-only"}`
	response, err := ProjectOAuthResponse([]byte(raw))
	if err != nil || response.TokenType != "Bearer" || response.Scope != "openid" || response.IDToken != strings.Repeat("y", 20) || response.RefreshToken != strings.Repeat("z", 20) {
		t.Fatalf("canonical projection failed: %v", err)
	}
	wire, err := json.Marshal(response)
	if err != nil || strings.Contains(string(wire), "realm") || strings.Contains(string(wire), "not-before-policy") {
		t.Fatal("provider extension escaped canonical envelope")
	}
	for _, invalid := range []string{
		strings.Replace(raw, `"expires_in":300`, `"expires_in":300.000000000000001`, 1),
		strings.Replace(raw, `"expires_in":300`, `"expires_in":"300"`, 1),
		strings.Replace(raw, `"id_token":"yyyyyyyyyyyyyyyyyyyy"`, `"id_token":null`, 1),
		strings.Replace(raw, `"scope":"openid"`, `"scope":""`, 1),
		strings.Replace(raw, `"realm":"provider-only"`, `"realm":"a","realm":"b"`, 1),
		strings.Replace(raw, `"realm":"provider-only"`, `"error":"invalid_grant"`, 1),
		strings.Replace(raw, `"bearer"`, `"DPoP"`, 1),
		raw + `{}`,
		`[]`,
		strings.Repeat(" ", 65537),
	} {
		if out, err := ProjectOAuthResponse([]byte(invalid)); err == nil || out != (Response{}) {
			t.Fatal("invalid OAuth response produced canonical credentials")
		}
	}
}
