package federation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/assurance"
)

// SessionRiskReader consumes an independently operated security authority.
// CP authorization and independent privileged approval have separate owners.
type SessionRiskReader struct {
	authority *HTTPAuthority
	now       func() time.Time
}

func NewSessionRiskReader(authority *HTTPAuthority, now func() time.Time) (*SessionRiskReader, error) {
	if authority == nil || now == nil {
		return nil, ErrInvalid
	}
	return &SessionRiskReader{authority: authority, now: now}, nil
}

type sessionRiskQuery struct {
	Issuer    string              `json:"issuer"`
	Subject   string              `json:"subject"`
	SessionID string              `json:"session_id"`
	Operation assurance.Operation `json:"operation"`
	Nonce     string              `json:"nonce"`
}

type sessionRiskObservation struct {
	sessionRiskQuery
	Level                  string    `json:"level"`
	ObservedAt             time.Time `json:"observed_at"`
	RecoveryState          string    `json:"recovery_state"`
	RecoveryCheckedThrough time.Time `json:"recovery_checked_through"`
	RiskReference          string    `json:"risk_reference"`
	RecoveryReference      string    `json:"recovery_reference"`
}

func (r *SessionRiskReader) CurrentRisk(ctx context.Context, key assurance.CurrentSessionKey, operation assurance.Operation) (assurance.Risk, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || key.Issuer == "" || key.Subject == "" ||
		key.SessionID == "" || len(key.Issuer) > 512 || len(key.Subject) > 256 || len(key.SessionID) > 256 ||
		!operation.Valid() {
		return assurance.Risk{}, ErrInvalid
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return assurance.Risk{}, ErrUnavailable
	}
	query := sessionRiskQuery{key.Issuer, key.Subject, key.SessionID, operation, hex.EncodeToString(nonce[:])}
	started := r.now().UTC()
	var observation sessionRiskObservation
	if err := r.authority.call(ctx, "/internal/iam/v1/session-risk/observe", query, &observation); err != nil {
		return assurance.Risk{}, err
	}
	now := r.now().UTC()
	if ctx.Err() != nil || now.Before(started) || observation.sessionRiskQuery != query ||
		observation.ObservedAt.Before(started) || observation.ObservedAt.After(now) ||
		now.Sub(observation.ObservedAt) > 30*time.Second ||
		observation.RecoveryCheckedThrough.IsZero() ||
		observation.RecoveryCheckedThrough.After(observation.ObservedAt) ||
		now.Sub(observation.RecoveryCheckedThrough) > 30*time.Second ||
		!validRiskReference(observation.RiskReference) || !validRiskReference(observation.RecoveryReference) {
		return assurance.Risk{}, ErrUnverified
	}
	switch observation.Level {
	case "low", "medium", "high", "critical":
	default:
		return assurance.Risk{}, ErrUnverified
	}
	switch observation.RecoveryState {
	case "clear", "hold", "suspicious":
	default:
		return assurance.Risk{}, ErrUnverified
	}
	// Both sources share the evaluator's freshness window. Report the older
	// observation so a later check never extends the recovery cursor's life.
	return assurance.Risk{
		ObservedAt:           observation.RecoveryCheckedThrough,
		Level:                observation.Level,
		RecoveryStateChecked: true,
		RecoverySuspicious:   observation.RecoveryState != "clear",
	}, nil
}

var riskReference = regexp.MustCompile(`^ref_[a-z0-9_-]{8,128}$`)

func validRiskReference(value string) bool {
	return riskReference.MatchString(value)
}

var _ assurance.RiskReader = (*SessionRiskReader)(nil)
