package tokenprofile

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
)

// ConsentSealClaim is the access-token session field through which governed
// buyer consent hands its decision to the token hook. The hook verifies it
// and never copies it into a token.
const ConsentSealClaim = "baobab_human_consent"

// MinConsentSealKeyBytes bounds the IAM-held key shared by governed consent
// and the token hook. It is never the hook's authentication key.
const MinConsentSealKeyBytes = 32

// HumanConsentSeal is governed buyer consent's authenticated record of the
// audience it granted (ADR-SHARED-042 section 14, CAA-03).
//
// Hydra (v26.2.0, observed live) calls the token hook on a code exchange
// before it copies the consent grant onto the request, and it does not bound
// a consent-granted audience by the client's registration. Without the seal
// the hook could not tell a governed grant from one accepted directly through
// the private admin API. The seal binds the consent request (the identifier
// Hydra records on the session as consent_challenge), client, subject, scopes
// and audience under an IAM-held key, so only governed consent can produce a
// grant the hook will issue for.
type HumanConsentSeal struct {
	Audience []string `json:"audience"`
	Seal     string   `json:"seal"`
}

// SealHumanConsent seals one governed consent decision.
func SealHumanConsent(key []byte, consentRequestID, clientID, subject string, scopes, audience []string) (HumanConsentSeal, error) {
	message, err := consentSealMessage(consentRequestID, clientID, subject, scopes, audience)
	if err != nil || len(key) < MinConsentSealKeyBytes {
		return HumanConsentSeal{}, fmt.Errorf("cannot seal human consent")
	}
	return HumanConsentSeal{Audience: slices.Clone(audience), Seal: consentMAC(key, message)}, nil
}

// verifyHumanConsent reports whether seal is the governed record of exactly
// this consent request, client, subject, scope set and audience.
func verifyHumanConsent(key []byte, seal *HumanConsentSeal, consentRequestID, clientID, subject string, scopes, audience []string) bool {
	if seal == nil || len(key) < MinConsentSealKeyBytes || !slices.Equal(seal.Audience, audience) {
		return false
	}
	message, err := consentSealMessage(consentRequestID, clientID, subject, scopes, audience)
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(seal.Seal), []byte(consentMAC(key, message)))
}

// consentSealMessage is the canonical sealed form. Scope order is not part of
// the decision, so scopes are sorted; audience keeps profile order, which
// HumanConsent fixes. Every value must already be canonical.
func consentSealMessage(consentRequestID, clientID, subject string, scopes, audience []string) (string, error) {
	sorted := slices.Clone(scopes)
	slices.Sort(sorted)
	for _, value := range append(append([]string{consentRequestID, clientID, subject}, sorted...), audience...) {
		if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, " \t\r\n\x00") {
			return "", fmt.Errorf("noncanonical consent value")
		}
	}
	if len(sorted) == 0 || len(audience) == 0 {
		return "", fmt.Errorf("incomplete consent decision")
	}
	return strings.Join([]string{"baobab-iam/human-consent/v1", consentRequestID, clientID, subject,
		strings.Join(sorted, " "), strings.Join(audience, " ")}, "\x00"), nil
}

func consentMAC(key []byte, message string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
