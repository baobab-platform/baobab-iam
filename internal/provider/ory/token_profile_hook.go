package ory

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/baobab-platform/baobab-iam/internal/tokenprofile"
)

// NewTokenProfileHook is a private Hydra v26.2.0 integration, not a public
// token endpoint or resource-server verifier. Its authenticated sender is Hydra,
// after Hydra has verified the client or assertion. It never trusts body claims
// from an unauthenticated caller and never logs the credential-bearing payload.
func NewTokenProfileHook(config tokenprofile.Config, key string) (http.Handler, error) {
	return newTokenProfileHook(config, key, false)
}

// NewCanonicalTokenProfileHook admits the canonical intent reconstructed from
// Hydra's authenticated callback fields. It requires ACTIVE registration
// and exact one-resource intent; mechanics-only PROVISIONED admission is absent.
func NewCanonicalTokenProfileHook(config tokenprofile.Config, key string) (http.Handler, error) {
	return newTokenProfileHook(config, key, true)
}

func newTokenProfileHook(config tokenprofile.Config, key string, canonical bool) (http.Handler, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("token hook authentication key must contain at least 32 bytes")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	// Snapshot caller configuration so later map/slice mutation cannot change policy.
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("encode token profile configuration")
	}
	var snapshot tokenprofile.Config
	if err := json.Unmarshal(encoded, &snapshot); err != nil {
		return nil, fmt.Errorf("snapshot token profile configuration")
	}
	expected := sha256.Sum256([]byte(key))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		actual := sha256.Sum256([]byte(r.Header.Get("X-Baobab-Token-Hook-Key")))
		if subtle.ConstantTimeCompare(actual[:], expected[:]) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body struct {
			Session struct {
				ClientID string `json:"client_id"`
				Identity struct {
					Subject string `json:"subject"`
				} `json:"id_token"`
			} `json:"session"`
			Request struct {
				ClientID        string              `json:"client_id"`
				RequestedScopes []string            `json:"requested_scopes"`
				GrantedScopes   []string            `json:"granted_scopes"`
				GrantedAudience []string            `json:"granted_audience"`
				Grants          []string            `json:"grant_types"`
				Payload         map[string][]string `json:"payload"`
			} `json:"request"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		if decoder.Decode(&body) != nil || decoder.Decode(new(any)) != io.EOF {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(body.Request.Grants) != 1 || body.Request.ClientID == "" || body.Session.ClientID != body.Request.ClientID {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		e := tokenprofile.Evidence{ClientID: body.Request.ClientID, Subject: body.Session.Identity.Subject, Grant: body.Request.Grants[0], RequestedScopes: body.Request.RequestedScopes, GrantedScopes: body.Request.GrantedScopes, GrantedAudiences: body.Request.GrantedAudience}
		if e.Grant == tokenprofile.FederatedGrant {
			assertions := body.Request.Payload["assertion"]
			if len(assertions) != 1 {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			parts := strings.Split(assertions[0], ".")
			if len(parts) != 3 {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			var assertion struct {
				Issuer  string `json:"iss"`
				Subject string `json:"sub"`
			}
			if err != nil || json.Unmarshal(payload, &assertion) != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			// These fields describe the assertion verified by the authenticated Hydra
			// sender. They are checked against separately governed exact bindings.
			e.AssertionIssuer, e.AssertionSubject = assertion.Issuer, assertion.Subject
		}
		if canonical {
			// Pinned Hydra sanitizes payload to assertion only. Its granted audience
			// and requested scopes are the available authenticated intent boundary.
			audiences, scopes := body.Request.GrantedAudience, body.Request.RequestedScopes
			if len(audiences) != 1 || len(scopes) == 0 {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			request := tokenprofile.WorkloadTokenRequest{WorkloadID: e.ClientID, Audience: audiences[0], Scopes: scopes}
			if _, err := snapshot.AdmitRequest(request, nil, e); err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
		claims, err := snapshot.Claims(e)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"session": map[string]any{"access_token": claims}})
	}), nil
}
