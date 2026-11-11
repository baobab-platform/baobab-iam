package nativebff

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
)

// matchesDelegatedSubject checks that the exact bearer forwarded to CP carries
// the issuer and subject that the already-verified ID token / BFF session
// asserts. This comparison is NOT token verification or authorization:
// the independently authenticated CP endpoint still verifies the bearer,
// current lifecycle and canonical Principal mapping before granting evidence.
//
// Reject duplicate JSON properties: ambiguous JWT claim interpretation must
// never allow IAM and CP to compare different issuers or subjects.
func matchesDelegatedSubject(raw, issuer, subject string) bool {
	if issuer == "" || subject == "" || len(raw) < 16 || len(raw) > 8192 {
		return false
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payload) == 0 || len(payload) > 8192 {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(payload))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	var actualIssuer, actualSubject string
	for d.More() {
		keyToken, err := d.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok || seen[key] {
			return false
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return false
		}
		switch key {
		case "iss":
			if json.Unmarshal(value, &actualIssuer) != nil {
				return false
			}
		case "sub":
			if json.Unmarshal(value, &actualSubject) != nil {
				return false
			}
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		return false
	}
	if _, err := d.Token(); err != io.EOF {
		return false
	}
	return actualIssuer == issuer && actualSubject == subject
}
