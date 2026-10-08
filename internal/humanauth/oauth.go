package humanauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ProjectOAuthResponse converts a successful standards token response into the
// pinned human authentication envelope. Provider extensions are excluded and
// token_type is normalized according to OAuth's case-insensitive token type.
// The caller must separately verify signatures, issuer, audience, nonce and
// current authority; this projection does not authenticate any token.
func ProjectOAuthResponse(raw []byte) (Response, error) {
	var zero Response
	if len(raw) > 65536 {
		return zero, fmt.Errorf("OAuth response too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return zero, fmt.Errorf("OAuth response object required")
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return zero, fmt.Errorf("invalid OAuth property")
		}
		if _, exists := fields[key]; exists {
			return zero, fmt.Errorf("duplicate OAuth property")
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return zero, fmt.Errorf("invalid OAuth value")
		}
		fields[key] = value
	}
	if _, err := decoder.Token(); err != nil {
		return zero, fmt.Errorf("invalid OAuth object")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return zero, fmt.Errorf("trailing OAuth input")
	}
	if _, exists := fields["error"]; exists {
		return zero, fmt.Errorf("OAuth error is not a successful response")
	}
	var tokenType string
	if json.Unmarshal(fields["token_type"], &tokenType) != nil || !strings.EqualFold(tokenType, "bearer") {
		return zero, fmt.Errorf("unsupported OAuth token type")
	}
	canonical := map[string]json.RawMessage{"token_type": json.RawMessage(`"Bearer"`)}
	for _, key := range []string{"access_token", "expires_in", "id_token", "refresh_token", "scope", "session_state"} {
		if value, exists := fields[key]; exists {
			canonical[key] = value
		}
	}
	wire, err := json.Marshal(canonical)
	if err != nil {
		return zero, fmt.Errorf("cannot project OAuth response")
	}
	var response Response
	if json.Unmarshal(wire, &response) != nil {
		return zero, fmt.Errorf("OAuth response violates canonical human contract")
	}
	return response, nil
}
