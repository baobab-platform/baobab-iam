package humanauth

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCanonicalHumanAuthenticationWireBoundary(t *testing.T) {
	challenge := strings.Repeat("a", 43)
	validRequest := `{"grant_type":"authorization_code","code_challenge":"` + challenge + `","code_challenge_method":"S256","redirect_uri":"https://estate.example/callback","state":"0123456789abcdef","nonce":"fedcba9876543210"}`
	validResponse := `{"access_token":"xxxxxxxxxxxxxxxxxxxx","token_type":"Bearer","expires_in":6e1,"id_token":"yyyyyyyyyyyyyyyyyyyy"}`
	var request Request
	var response Response
	if json.Unmarshal([]byte(validRequest), &request) != nil || json.Unmarshal([]byte(validResponse), &response) != nil {
		t.Fatal("valid canonical human authentication wire value rejected")
	}
	for _, raw := range []string{
		strings.Replace(validRequest, "S256", "plain", 1),
		strings.Replace(validRequest, challenge, "short", 1),
		strings.Replace(validRequest, `"nonce":"fedcba9876543210"`, `"realm":"master"`, 1),
		strings.Replace(validRequest, `"state":"0123456789abcdef"`, `"state":"short"`, 1),
		validRequest + ` {}`,
	} {
		if json.Unmarshal([]byte(raw), &request) == nil { t.Fatal("invalid canonical request accepted") }
	}
	for _, raw := range []string{
		strings.Replace(validResponse, `"Bearer"`, `"bearer"`, 1),
		strings.Replace(validResponse, `6e1`, `60.000000000000001`, 1),
		strings.Replace(validResponse, `6e1`, `"60"`, 1),
		strings.Replace(validResponse, `"id_token":"yyyyyyyyyyyyyyyyyyyy"`, `"realm":"master"`, 1),
		validResponse + ` {}`,
	} {
		if json.Unmarshal([]byte(raw), &response) == nil { t.Fatal("invalid canonical response accepted") }
	}
}
