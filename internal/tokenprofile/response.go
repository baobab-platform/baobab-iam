package tokenprofile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"
	"unicode/utf8"
)

// WorkloadTokenResponse is the pinned Shared response envelope. Validating it
// does not authenticate its token or establish CP authority or consumption.
type WorkloadTokenResponse struct {
	AccessToken string  `json:"access_token"`
	TokenType   string  `json:"token_type"`
	ExpiresIn   int     `json:"expires_in"`
	Scope       *string `json:"scope,omitempty"`
}

func (r WorkloadTokenResponse) Validate() error {
	if utf8.RuneCountInString(r.AccessToken) < 20 || r.TokenType != "Bearer" || r.ExpiresIn < 60 || r.ExpiresIn > 86400 || (r.Scope != nil && *r.Scope == "") {
		return fmt.Errorf("invalid canonical workload token response")
	}
	return nil
}

// BindRequest requires an explicit exact granted scope set. Callers must supply
// the result of admission, and independently verify issuer/subject/audience and
// current authority before treating a credential as accepted.
func (r WorkloadTokenResponse) BindRequest(admitted WorkloadTokenRequest) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if err := admitted.Validate(); err != nil {
		return err
	}
	if len(admitted.Scopes) == 0 || r.Scope == nil {
		return fmt.Errorf("explicit admitted and granted scopes required")
	}
	scopes := strings.Split(*r.Scope, " ")
	if !sameSet(scopes, admitted.Scopes) {
		return fmt.Errorf("canonical response scope mismatch")
	}
	return nil
}

// UnmarshalJSON rejects unknown, duplicate, null and trailing properties rather
// than allowing OAuth extensions to silently enter the closed canonical shape.
func (r *WorkloadTokenResponse) UnmarshalJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return fmt.Errorf("canonical response object required")
	}
	var out WorkloadTokenResponse
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return fmt.Errorf("duplicate or invalid canonical response property")
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("invalid canonical response value")
		}
		switch key {
		case "access_token":
			err = json.Unmarshal(value, &out.AccessToken)
		case "token_type":
			err = json.Unmarshal(value, &out.TokenType)
		case "expires_in":
			var number float64
			err = json.Unmarshal(value, &number)
			if err == nil {
				if number < 60 || number > 86400 || math.Trunc(number) != number {
					return fmt.Errorf("invalid canonical response lifetime")
				}
				out.ExpiresIn = int(number)
			}
		case "scope":
			err = json.Unmarshal(value, &out.Scope)
		default:
			return fmt.Errorf("unknown canonical response property")
		}
		if err != nil {
			return fmt.Errorf("invalid canonical response type")
		}
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("invalid canonical response object")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing canonical response input")
	}
	if !seen["access_token"] || !seen["token_type"] || !seen["expires_in"] {
		return fmt.Errorf("required canonical response properties missing")
	}
	if err := out.Validate(); err != nil {
		return err
	}
	*r = out
	return nil
}

func (r WorkloadTokenResponse) MarshalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	type wire WorkloadTokenResponse
	return json.Marshal(wire(r))
}
