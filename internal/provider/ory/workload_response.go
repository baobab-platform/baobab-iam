package ory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/baobab-platform/baobab-iam/internal/tokenprofile"
)

// ProjectWorkloadTokenResponse maps a successful OAuth response into the pinned
// canonical envelope. Extensions and refresh credentials never escape this
// boundary. This does not authenticate the access token or establish CP authority.
func ProjectWorkloadTokenResponse(raw []byte, admitted tokenprofile.WorkloadTokenRequest) (tokenprofile.WorkloadTokenResponse, error) {
	var zero tokenprofile.WorkloadTokenResponse
	if len(raw) > 1<<20 {
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
			return zero, fmt.Errorf("invalid OAuth response property")
		}
		if _, exists := fields[key]; exists {
			return zero, fmt.Errorf("duplicate OAuth response property")
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return zero, fmt.Errorf("invalid OAuth response value")
		}
		fields[key] = value
	}
	if _, err := decoder.Token(); err != nil {
		return zero, fmt.Errorf("invalid OAuth response object")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return zero, fmt.Errorf("trailing OAuth response input")
	}
	if _, exists := fields["error"]; exists {
		return zero, fmt.Errorf("OAuth error is not a successful response")
	}
	var tokenType string
	if json.Unmarshal(fields["token_type"], &tokenType) != nil || !strings.EqualFold(tokenType, "bearer") {
		return zero, fmt.Errorf("unsupported OAuth token type")
	}
	canonical := map[string]json.RawMessage{"token_type": json.RawMessage(`"Bearer"`)}
	for _, key := range []string{"access_token", "expires_in", "scope"} {
		if value, exists := fields[key]; exists {
			canonical[key] = value
		}
	}
	wire, err := json.Marshal(canonical)
	if err != nil {
		return zero, fmt.Errorf("cannot project OAuth response")
	}
	var response tokenprofile.WorkloadTokenResponse
	if json.Unmarshal(wire, &response) != nil || response.BindRequest(admitted) != nil {
		return zero, fmt.Errorf("OAuth response differs from canonical admitted intent")
	}
	return response, nil
}
