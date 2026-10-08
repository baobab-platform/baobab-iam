package tokenprofile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
)

// WorkloadTokenRequest mirrors pinned Shared identity/v1/workload-token-request.
// Credentials, grant types, provider endpoints and CP business context belong
// outside the canonical request, in their independently governed bindings.
type WorkloadTokenRequest struct {
	WorkloadID string   `json:"workload_id"`
	Audience   string   `json:"audience"`
	Scopes     []string `json:"scopes,omitempty"`
}

var workloadKey = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
var scopeKey = regexp.MustCompile(`^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$`)

func (r WorkloadTokenRequest) Validate() error {
	if len(r.WorkloadID) > 63 || !workloadKey.MatchString(r.WorkloadID) || len(r.Audience) > 63 || !workloadKey.MatchString(r.Audience) || len(r.Scopes) > 32 {
		return fmt.Errorf("invalid canonical workload token request")
	}
	seen := map[string]bool{}
	for _, scope := range r.Scopes {
		if len(scope) > 63 || !scopeKey.MatchString(scope) || seen[scope] {
			return fmt.Errorf("invalid canonical workload token scopes")
		}
		seen[scope] = true
	}
	return nil
}

// WorkloadDefaults is an approved per-workload, per-audience scope policy.
// It is never derived from all allowed scopes or supplied by a token requester.
type WorkloadDefaults map[string]map[string][]string

// AdmitRequest checks canonical intent against provider-authenticated evidence
// after credential verification. A request, or this returned value, is not
// evidence of credential verification, CP binding authority or token acceptance.
// The existing Claims path remains available for PROVISIONED mechanics tests;
// canonical admission deliberately requires ACTIVE registration.
func (c Config) AdmitRequest(request WorkloadTokenRequest, defaults WorkloadDefaults, evidence Evidence) (WorkloadTokenRequest, error) {
	if err := c.Validate(); err != nil {
		return WorkloadTokenRequest{}, err
	}
	if err := request.Validate(); err != nil {
		return WorkloadTokenRequest{}, err
	}
	profile, ok := c.Workloads[request.WorkloadID]
	if !ok || profile.Status != "ACTIVE" || evidence.ClientID != request.WorkloadID || !slices.Contains(profile.Audiences, request.Audience) {
		return WorkloadTokenRequest{}, fmt.Errorf("canonical workload registration denied")
	}
	// Only omission uses defaults. An explicit empty list cannot silently acquire
	// configured scopes. Missing defaults fail closed rather than using all grants.
	if request.Scopes == nil {
		request.Scopes = slices.Clone(defaults[request.WorkloadID][request.Audience])
	}
	if len(request.Scopes) == 0 {
		return WorkloadTokenRequest{}, fmt.Errorf("canonical workload scopes required")
	}
	if err := request.Validate(); err != nil {
		return WorkloadTokenRequest{}, err
	}
	if !sameSet(evidence.RequestedScopes, request.Scopes) || !sameSet(evidence.GrantedScopes, request.Scopes) || !sameSet(evidence.GrantedAudiences, []string{request.Audience}) {
		return WorkloadTokenRequest{}, fmt.Errorf("canonical workload intent differs from authenticated grant")
	}
	// Preserve exact credential type, issuer/subject binding and granted scope
	// enforcement from the executable token-profile hook; no independent bypass.
	if _, err := c.Claims(evidence); err != nil {
		return WorkloadTokenRequest{}, err
	}
	request.Scopes = slices.Clone(request.Scopes)
	return request, nil
}

// UnmarshalJSON preserves the closed Shared wire contract, including duplicate
// rejection and the distinction between omitted scopes and an explicit list.
func (r *WorkloadTokenRequest) UnmarshalJSON(raw []byte) error {
	if len(raw) > 4096 {
		return fmt.Errorf("canonical request too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return fmt.Errorf("canonical request object required")
	}
	var out WorkloadTokenRequest
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
			return fmt.Errorf("invalid canonical property value")
		}
		switch key {
		case "workload_id":
			err = json.Unmarshal(value, &out.WorkloadID)
		case "audience":
			err = json.Unmarshal(value, &out.Audience)
		case "scopes":
			err = json.Unmarshal(value, &out.Scopes)
		default:
			return fmt.Errorf("unknown canonical property")
		}
		if err != nil {
			return fmt.Errorf("invalid canonical property type")
		}
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("invalid canonical object")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing canonical input")
	}
	if !seen["workload_id"] || !seen["audience"] {
		return fmt.Errorf("required canonical properties missing")
	}
	if err := out.Validate(); err != nil {
		return err
	}
	*r = out
	return nil
}

func (r WorkloadTokenRequest) MarshalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	values := map[string]any{"workload_id": r.WorkloadID, "audience": r.Audience}
	if r.Scopes != nil {
		values["scopes"] = r.Scopes
	}
	return json.Marshal(values)
}
