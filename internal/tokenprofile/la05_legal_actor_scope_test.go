package tokenprofile

import "testing"

// LA-05B: publishing a transport scope definition is not issuing authority.
// The caller, approved workload profile, provider evidence and audience must
// ALL agree before the scope can ever appear in an admitted workload token.
func TestLA05LegalActorScopeNotGrantedByDefinitionOrDefaults(t *testing.T) {
 c, request, evidence := canonicalFixture()
 request.Scopes = []string{"context:resolve", "legal-actor:assess"}
 evidence.RequestedScopes = []string{"context:resolve", "legal-actor:assess"}
 evidence.GrantedScopes = []string{"context:resolve", "legal-actor:assess"}
 if _, err := c.AdmitRequest(request, nil, evidence); err == nil {
  t.Fatal("unregistered workload obtained legal actor assessor scope")
 }
 // Registration does NOT automatically put a newly registered privileged
 // scope into any implicit audience defaults.
 profile := c.Workloads["worker"]
 profile.Scopes = append(profile.Scopes, "legal-actor:assess")
 c.Workloads["worker"] = profile
 defaults := WorkloadDefaults{"worker": {"baobab-cp": {"context:resolve"}}}
 request.Scopes = nil
 evidence.RequestedScopes = []string{"context:resolve"}
 evidence.GrantedScopes = []string{"context:resolve"}
 admitted, err := c.AdmitRequest(request, defaults, evidence)
 if err != nil { t.Fatal(err) }
 if len(admitted.Scopes)!=1 || admitted.Scopes[0]!="context:resolve" {
  t.Fatal("legal actor scope was auto-granted by profile registration")
 }
 // Explicit cross-layer enrolment can be admitted ONLY when the currently
 // authenticated provider evidence matches an approved scope set.
 request.Scopes = []string{"context:resolve", "legal-actor:assess"}
 evidence.RequestedScopes = []string{"context:resolve", "legal-actor:assess"}
 evidence.GrantedScopes = []string{"context:resolve", "legal-actor:assess"}
 if _,err:=c.AdmitRequest(request,nil,evidence);err!=nil{
  t.Fatalf("explicit admitted scope failed despite matching trusted evidence: %v",err)
 }
}
