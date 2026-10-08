// Package humanauth implements the pinned Shared human authentication wire
// boundary. Provider routing, sessions and tenant authority remain outside it.
package humanauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"strconv"
	"unicode/utf8"
)

type Request struct {
	GrantType           string `json:"grant_type"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	ClientID            string `json:"client_id,omitempty"`
	RedirectURI         string `json:"redirect_uri,omitempty"`
	Scope               string `json:"scope,omitempty"`
	State               string `json:"state,omitempty"`
	Nonce               string `json:"nonce,omitempty"`
	ACRValues           string `json:"acr_values,omitempty"`
}

type Response struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	SessionState string `json:"session_state,omitempty"`
}

func (r Request) Validate() error {
	if r.GrantType != "authorization_code" || r.CodeChallengeMethod != "S256" || utf8.RuneCountInString(r.CodeChallenge) < 43 || utf8.RuneCountInString(r.CodeChallenge) > 128 || utf8.RuneCountInString(r.ClientID) > 255 || utf8.RuneCountInString(r.Scope) > 500 || utf8.RuneCountInString(r.ACRValues) > 500 {
		return fmt.Errorf("invalid canonical human authentication request")
	}
	for _, value := range []string{r.State, r.Nonce} {
		if value != "" && (utf8.RuneCountInString(value) < 16 || utf8.RuneCountInString(value) > 500) {
			return fmt.Errorf("invalid transaction binding")
		}
	}
	if r.RedirectURI != "" {
		parsed, err := url.ParseRequestURI(r.RedirectURI)
		if err != nil || !parsed.IsAbs() {
			return fmt.Errorf("invalid redirect URI")
		}
	}
	return nil
}

func (r Response) Validate() error {
	if utf8.RuneCountInString(r.AccessToken) < 20 || r.TokenType != "Bearer" || r.ExpiresIn < 60 || r.ExpiresIn > 86400 || (r.IDToken != "" && utf8.RuneCountInString(r.IDToken) < 20) || (r.RefreshToken != "" && utf8.RuneCountInString(r.RefreshToken) < 20) {
		return fmt.Errorf("invalid canonical human authentication response")
	}
	return nil
}

func decodeClosed(raw []byte, allowed map[string]func(json.RawMessage) error) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return fmt.Errorf("canonical object required")
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return fmt.Errorf("duplicate or invalid canonical property")
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("invalid canonical value")
		}
		decode, ok := allowed[key]
		if !ok || decode(value) != nil {
			return fmt.Errorf("unknown or invalid canonical property")
		}
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("invalid canonical object")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing canonical input")
	}
	return nil
}

func stringField(target *string, minimum, maximum int) func(json.RawMessage) error {
	return func(value json.RawMessage) error {
		if err := json.Unmarshal(value, target); err != nil || utf8.RuneCountInString(*target) < minimum || (maximum > 0 && utf8.RuneCountInString(*target) > maximum) {
			return fmt.Errorf("invalid string field")
		}
		return nil
	}
}

func (r *Request) UnmarshalJSON(raw []byte) error {
	var out Request
	fields := map[string]func(json.RawMessage) error{
		"grant_type":            func(v json.RawMessage) error { return json.Unmarshal(v, &out.GrantType) },
		"code_challenge":        func(v json.RawMessage) error { return json.Unmarshal(v, &out.CodeChallenge) },
		"code_challenge_method": func(v json.RawMessage) error { return json.Unmarshal(v, &out.CodeChallengeMethod) },
		"client_id":             stringField(&out.ClientID, 1, 255),
		"redirect_uri":          stringField(&out.RedirectURI, 1, 0),
		"scope":                 stringField(&out.Scope, 1, 500),
		"state":                 stringField(&out.State, 16, 500),
		"nonce":                 stringField(&out.Nonce, 16, 500),
		"acr_values":            stringField(&out.ACRValues, 1, 500),
	}
	if err := decodeClosed(raw, fields); err != nil || out.Validate() != nil {
		return fmt.Errorf("invalid canonical human authentication request")
	}
	*r = out
	return nil
}

func exactLifetime(value json.RawMessage) (int, error) {
	if len(value) == 0 || value[0] == '"' {
		return 0, fmt.Errorf("integer lifetime required")
	}
	var number json.Number
	if json.Unmarshal(value, &number) != nil {
		return 0, fmt.Errorf("integer lifetime required")
	}
	// Bound magnitude before allocating exact rational arithmetic. The rational
	// check below still rejects fractions that round to an integer in float64.
	magnitude, err := strconv.ParseFloat(number.String(), 64)
	if err != nil || magnitude < 60 || magnitude > 86400 {
		return 0, fmt.Errorf("lifetime outside canonical range")
	}
	rational, ok := new(big.Rat).SetString(number.String())
	if !ok || !rational.IsInt() || !rational.Num().IsInt64() {
		return 0, fmt.Errorf("integer lifetime required")
	}
	lifetime := rational.Num().Int64()
	if lifetime < 60 || lifetime > 86400 {
		return 0, fmt.Errorf("lifetime outside canonical range")
	}
	return int(lifetime), nil
}

func (r *Response) UnmarshalJSON(raw []byte) error {
	var out Response
	fields := map[string]func(json.RawMessage) error{
		"access_token": func(v json.RawMessage) error { return json.Unmarshal(v, &out.AccessToken) },
		"token_type":   func(v json.RawMessage) error { return json.Unmarshal(v, &out.TokenType) },
		"expires_in": func(v json.RawMessage) error {
			var err error
			out.ExpiresIn, err = exactLifetime(v)
			return err
		},
		"id_token":      stringField(&out.IDToken, 20, 0),
		"refresh_token": stringField(&out.RefreshToken, 20, 0),
		"scope":         stringField(&out.Scope, 1, 0),
		"session_state": func(v json.RawMessage) error { return json.Unmarshal(v, &out.SessionState) },
	}
	if err := decodeClosed(raw, fields); err != nil || out.Validate() != nil {
		return fmt.Errorf("invalid canonical human authentication response")
	}
	*r = out
	return nil
}

func (r Request) MarshalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	type wire Request
	return json.Marshal(wire(r))
}

func (r Response) MarshalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	type wire Response
	return json.Marshal(wire(r))
}
