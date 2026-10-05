package federation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCanonicalAdmissionRejectsLifecycleScopeEnvironmentAndStaleness(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "registry.json")
	a := &ServiceAccess{CanonicalRegistryPath: path, Environment: "staging"}
	base := CanonicalWorkloadSnapshot{SharedCommit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Environment: "staging", IssuedAt: now.Add(-time.Minute), ValidUntil: now.Add(time.Minute), Workloads: map[string]CanonicalWorkload{"service": {Status: "ACTIVE", Environment: "staging", AllowedAudiences: []string{"iam"}, AllowedScopes: []string{"federation-authority:read"}}}}
	for name, mutate := range map[string]func(*CanonicalWorkloadSnapshot){
		"active": func(*CanonicalWorkloadSnapshot) {},
		"revoked": func(s *CanonicalWorkloadSnapshot) {
			w := s.Workloads["service"]
			w.Status = "REVOKED"
			s.Workloads["service"] = w
		},
		"provisioned": func(s *CanonicalWorkloadSnapshot) {
			w := s.Workloads["service"]
			w.Status = "PROVISIONED"
			s.Workloads["service"] = w
		},
		"environment": func(s *CanonicalWorkloadSnapshot) { s.Environment = "production" },
		"audience": func(s *CanonicalWorkloadSnapshot) {
			w := s.Workloads["service"]
			w.AllowedAudiences = []string{"cp"}
			s.Workloads["service"] = w
		},
		"scope": func(s *CanonicalWorkloadSnapshot) {
			w := s.Workloads["service"]
			w.AllowedScopes = []string{"context:resolve"}
			s.Workloads["service"] = w
		},
		"expired":   func(s *CanonicalWorkloadSnapshot) { s.ValidUntil = now },
		"future":    func(s *CanonicalWorkloadSnapshot) { s.IssuedAt = now.Add(time.Second) },
		"unbounded": func(s *CanonicalWorkloadSnapshot) { s.ValidUntil = now.Add(time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(base)
			var s CanonicalWorkloadSnapshot
			json.Unmarshal(raw, &s)
			mutate(&s)
			raw, _ = json.Marshal(s)
			os.WriteFile(path, raw, 0600)
			err := a.canonicalAdmission("service", "iam", now)
			if (err == nil) != (name == "active") {
				t.Fatalf("err=%v", err)
			}
		})
	}
	os.Remove(path)
	if a.canonicalAdmission("service", "iam", now) == nil {
		t.Fatal("missing authority allowed")
	}
}
