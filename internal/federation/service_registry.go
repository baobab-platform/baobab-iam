package federation

import (
	"slices"
	"time"
)

// CanonicalWorkloadSnapshot is a finite deployment projection of Shared's
// workload registry, distinct from infrastructure-owned certificate bindings.
// The publisher must use the reviewed Shared pin; operators cannot promote
// PROVISIONED entries merely by marking a certificate admission Active.
type CanonicalWorkloadSnapshot struct {
	SharedCommit string                       `json:"shared_commit"`
	Environment  string                       `json:"environment"`
	IssuedAt     time.Time                    `json:"issued_at"`
	ValidUntil   time.Time                    `json:"valid_until"`
	Workloads    map[string]CanonicalWorkload `json:"workloads"`
}
type CanonicalWorkload struct {
	Status           string   `json:"status"`
	Environment      string   `json:"environment"`
	AllowedAudiences []string `json:"allowed_audiences"`
	AllowedScopes    []string `json:"allowed_scopes"`
}

func (a *ServiceAccess) canonicalAdmission(subject, audience string, now time.Time) error {
	var s CanonicalWorkloadSnapshot
	if a.CanonicalRegistryPath == "" || a.Environment == "" || LoadServiceDocument(a.CanonicalRegistryPath, &s) != nil {
		return ErrUnavailable
	}
	if len(s.SharedCommit) != 40 || s.Environment != a.Environment || s.IssuedAt.IsZero() || s.IssuedAt.After(now) || !now.Before(s.ValidUntil) || s.ValidUntil.Sub(s.IssuedAt) > 15*time.Minute || s.Workloads == nil {
		return ErrUnverified
	}
	for _, r := range s.SharedCommit {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return ErrInvalid
		}
	}
	w, ok := s.Workloads[subject]
	if !ok || w.Status != "ACTIVE" || w.Environment != a.Environment || !slices.Contains(w.AllowedAudiences, audience) || !slices.Contains(w.AllowedScopes, "federation-authority:read") {
		return ErrDenied
	}
	return nil
}
