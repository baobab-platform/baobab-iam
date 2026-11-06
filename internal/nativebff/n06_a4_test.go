package nativebff

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/assurance"
)

type n06A4Hardware struct{
	valid bool
	observed time.Time
}
func (h n06A4Hardware) CurrentDeviceAttestation(_ context.Context,_ assurance.CurrentSessionKey,_ []byte)(CurrentHardwareAttestation,error) {
	return CurrentHardwareAttestation{
		ExactDeviceKey:h.valid,HardwareAttestationVerified:h.valid,
		PinnedTrustRootVerified:h.valid,NonExportablePrivateKeyVerified:h.valid,
		OriginalReference:"ref_origindeviceevidence",ObservedAt:h.observed,
	},nil
}
type n06A4Approval struct{
	valid bool
	observed time.Time
}
func (h n06A4Approval) CurrentPrivilegedApproval(_ context.Context,_ assurance.CurrentSessionKey,
	_ assurance.Operation,_,_ string)(A4PrivilegedApproval,error) {
	return A4PrivilegedApproval{
		ExactSession:h.valid,CurrentPrivilege:h.valid,IndependentReviewer:h.valid,
		SameOperation:h.valid,OriginalReference:"ref_origincpreviewer",
		ObservedAt:h.observed,
	},nil
}
type n06A4Risk struct{value assurance.Risk}
func (r n06A4Risk) CurrentRisk(context.Context,assurance.CurrentSessionKey,assurance.Operation)(assurance.Risk,error) {
	return r.value,nil
}

func n06A4Fixture(t *testing.T)(*A4Verifier,A4Request){
	t.Helper()
	f:=makeA3Fixture(t)
	when:=f.v.Now()
	original:=f.v.Kratos.(a3Current).evidence
	original.PasskeyUsed=true
	original.UserVerified=true
	original.OriginBound=true
	original.Methods=[]string{"webauthn"}
	original.ObservedAt=when
	original.AuthenticatedAt=when.Add(-10*time.Second)
	private,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
	if err!=nil {t.Fatal("synthetic signer unavailable")}
	public,err:=x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err!=nil {t.Fatal("ephemeral public signing key")}
	request:=A4Request{
		Session:f.challenges.item.Session,Operation:assurance.GrantPrivileged,
		A3:original,ChallengeID:f.challenges.item.ID,
		DevicePublicKeyDER:public,RequesterReference:"ref_independentrequester",
		IndependentReviewerReference:"ref_differentreviewer",
	}
	digest:=sha256.Sum256(a4Transcript(request.Session,request.Operation,f.challenges.item.Nonce))
	request.HardwareSignatureDER,err=ecdsa.SignASN1(rand.Reader,private,digest[:])
	if err!=nil {t.Fatal("synthetic device assertion unavailable")}
	v:=&A4Verifier{
		Challenges:f.challenges,Hardware:n06A4Hardware{valid:true,observed:when},
		Approvals:n06A4Approval{valid:true,observed:when},
		Risk:n06A4Risk{assurance.Risk{ObservedAt:when,Level:"low",PrivilegedContextVerified:true}},
		Policy:assurance.DefaultDevelopmentPolicy(),
		Now:func()time.Time{return when},
	}
	return v,request
}
func TestN06A4SignedHardwareAndDistinctReviewIsAuthenticationOnly(t *testing.T) {
	v,request:=n06A4Fixture(t)
	evidence,err:=v.Verify(context.Background(),request)
	if err!=nil || !evidence.HardwareBound || !evidence.PasskeyUsed ||
		!evidence.UserVerified || !evidence.OriginBound {
		t.Fatal("strict synthetic A4 signature/attestation/reviewer conformance rejected")
	}
	if _,err:=v.Verify(context.Background(),request);err==nil {
		t.Fatal("signed hardware privilege transaction was replayed")
	}
}
func TestN06A4DeniesWithoutIndependentHardwareAndPrivilege(t *testing.T){
	cases:=map[string]func(*A4Verifier,*A4Request){
		"privileged-self-approval":func(_ *A4Verifier,r *A4Request){
			r.IndependentReviewerReference=r.RequesterReference
		},
		"browser-fabricated-A3":func(_ *A4Verifier,r *A4Request){r.A3.PasskeyUsed=false},
		"not-user-verified":func(_ *A4Verifier,r *A4Request){r.A3.UserVerified=false},
		"wrong-session":func(_ *A4Verifier,r *A4Request){r.Session.Subject="other-subject"},
		"wrong-operation":func(_ *A4Verifier,r *A4Request){r.Operation=assurance.OrdinaryBuyer},
		"tampered-signature":func(_ *A4Verifier,r *A4Request){r.HardwareSignatureDER[6]^=0x80},
		"wrong-hardware":func(v *A4Verifier,_ *A4Request){
			verified:=v.Hardware.(n06A4Hardware)
			verified.valid=false
			v.Hardware=verified
		},
		"missing-independent-review":func(v *A4Verifier,_ *A4Request){
			approved:=v.Approvals.(n06A4Approval)
			approved.valid=false
			v.Approvals=approved
		},
		"critical-risk":func(v *A4Verifier,_ *A4Request){
			risk:=v.Risk.(n06A4Risk)
			risk.value.Level="critical"
			v.Risk=risk
		},
		"post-recovery-risk":func(v *A4Verifier,_ *A4Request){
			risk:=v.Risk.(n06A4Risk)
			risk.value.RecoverySuspicious=true
			v.Risk=risk
		},
		"unwitnessed-context":func(v *A4Verifier,_ *A4Request){
			risk:=v.Risk.(n06A4Risk)
			risk.value.PrivilegedContextVerified=false
			v.Risk=risk
		},
		"stale-device-attestation":func(v *A4Verifier,_ *A4Request){
			h:=v.Hardware.(n06A4Hardware)
			h.observed=h.observed.Add(-10*time.Minute)
			v.Hardware=h
		},
	}
	for name,mutate:=range cases {
		t.Run(name,func(t *testing.T){
			v,request:=n06A4Fixture(t)
			mutate(v,&request)
			if _,err:=v.Verify(context.Background(),request);err==nil {
				t.Fatal("A4 admitted missing or untrusted independent hardware/privileged proof")
			}
		})
	}
}
