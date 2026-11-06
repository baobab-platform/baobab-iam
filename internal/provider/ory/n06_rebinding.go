package ory

// N06 recovery / credential rebinding is a security-management operation.
// It intentionally NEVER creates an IAM A3/A4 success or CP legal permission.
// The approved first phase invalidates old 2FA credentials/sessions, leaving
// the native identity disabled under an independently witnessed recovery hold.
import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

var errCredentialRebindDenied = errors.New("ory: current independently approved credential rebinding required")
var rebindUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var rebindRef = regexp.MustCompile(`^ref_[a-z0-9_-]{8,128}$`)

type NativeCredentialRebindEvidence struct {
	OriginalRecoveryReference string
	RequestedByReference string
	IndependentReviewerReference string
	CurrentSecurityDecisionReference string
	Issuer string
	Subject string
	ObservedAt time.Time
	HoldUntil time.Time
	Approved bool
	DistinctReviewer bool
	CurrentSecurityHold bool
}
type NativeCredentialRebindAuthority interface {
	CurrentWebAuthnRebind(context.Context, provider.ExternalSubject) (NativeCredentialRebindEvidence,error)
}
type NativeCredentialRebindResult struct {
	IdentityDisabled bool
	AllSessionsRevoked bool
	OldWebAuthnRemoved bool
	RecoveryHoldObserved bool
	NativeReenrolmentRequired bool
}

// CredentialRebind operations MUST only be called by a scoped, IAM-managed
// service client with private Kratos Admin transport and separate securityops
// authority. The caller supplies the stable issuer/subject, not a provider
// credential, approver bool, or browser-selected trust scope.
func (a *Adapter) BeginNativeWebAuthnRebind(ctx context.Context, subject provider.ExternalSubject,
	authority NativeCredentialRebindAuthority, now func() time.Time,
) (NativeCredentialRebindResult,error) {
	none:=NativeCredentialRebindResult{}
	if a==nil || ctx==nil || ctx.Err()!=nil || authority==nil || now==nil ||
		a.requireIssuer(subject)!=nil || !rebindUUID.MatchString(subject.Subject) {
		return none,errCredentialRebindDenied
	}
	witness,err:=authority.CurrentWebAuthnRebind(ctx,subject)
	current:=now().UTC()
	if err!=nil || !witness.Approved || !witness.DistinctReviewer ||
		!witness.CurrentSecurityHold ||
		witness.Issuer!=subject.Issuer || witness.Subject!=subject.Subject ||
		!rebindRef.MatchString(witness.OriginalRecoveryReference) ||
		!rebindRef.MatchString(witness.RequestedByReference) ||
		!rebindRef.MatchString(witness.IndependentReviewerReference) ||
		!rebindRef.MatchString(witness.CurrentSecurityDecisionReference) ||
		witness.RequestedByReference==witness.IndependentReviewerReference ||
		witness.ObservedAt.IsZero() || witness.ObservedAt.After(current) ||
		current.Sub(witness.ObservedAt)>2*time.Minute ||
		witness.HoldUntil.Before(current.Add(24*time.Hour)) {
		return none,errCredentialRebindDenied
	}
	before,err:=a.currentRebindIdentity(ctx,subject.Subject)
	if err!=nil || before.State!="active" || !before.hasWebAuthn() ||
		before.hasPasskey() || before.ID!=subject.Subject {
		// Kratos passkey credentials are not administratively deletable
		// through this API. Do NOT silently claim that WebAuthn deletion
		// removes a separate passkey or restores A3.
		return none,errCredentialRebindDenied
	}
	if a.kratos.setIdentityActive(ctx,subject.Subject,false)!=nil {
		return none,errCredentialRebindDenied
	}
	// A failure from here onward is an UNKNOWN security outcome, not
	// permission to enable the identity again. The security hold persists.
	if a.kratos.revokeSessions(ctx,subject.Subject)!=nil {
		return none,errCredentialRebindDenied
	}
	if !a.noCurrentNativeSessions(ctx,subject.Subject) {
		return none,errCredentialRebindDenied
	}
	endpoint:="/admin/identities/"+url.PathEscape(subject.Subject)+"/credentials/webauthn"
	_,status,err:=a.rebindHTTP(ctx,http.MethodDelete,endpoint)
	if err!=nil || status!=http.StatusNoContent {
		return none,errCredentialRebindDenied
	}
	after,err:=a.currentRebindIdentity(ctx,subject.Subject)
	if err!=nil || after.ID!=subject.Subject ||
		after.State!="inactive" || after.hasWebAuthn() || after.hasPasskey() ||
		!a.noCurrentNativeSessions(ctx,subject.Subject) {
		return none,errCredentialRebindDenied
	}
	return NativeCredentialRebindResult{
		IdentityDisabled:true, AllSessionsRevoked:true,
		OldWebAuthnRemoved:true,RecoveryHoldObserved:true,
		NativeReenrolmentRequired:true,
	},nil
}

type rebindIdentity struct{
	ID string `json:"id"`
	State string `json:"state"`
	Credentials map[string]struct{
		Config struct{
			Credentials []json.RawMessage `json:"credentials"`
		} `json:"config"`
	} `json:"credentials"`
}
func (r rebindIdentity) hasWebAuthn() bool {
	c,ok:=r.Credentials["webauthn"]
	return ok && len(c.Config.Credentials)>0
}
func (r rebindIdentity) hasPasskey() bool {
	c,ok:=r.Credentials["passkey"]
	return ok && len(c.Config.Credentials)>0
}
func (a *Adapter) currentRebindIdentity(ctx context.Context, id string) (rebindIdentity,error) {
	var item rebindIdentity
	raw,status,err:=a.rebindHTTP(ctx,http.MethodGet,
		"/admin/identities/"+url.PathEscape(id)+
		"?include_credential=webauthn&include_credential=passkey")
	if err!=nil || status!=http.StatusOK || json.Unmarshal(raw,&item)!=nil {
		return item,errCredentialRebindDenied
	}
	return item,nil
}
func (a *Adapter) noCurrentNativeSessions(ctx context.Context, id string) bool {
	raw,status,err:=a.rebindHTTP(ctx,http.MethodGet,
		"/admin/identities/"+url.PathEscape(id)+"/sessions?active=true")
	if err!=nil || status!=http.StatusOK {
		return false
	}
	var sessions []json.RawMessage
	return json.Unmarshal(raw,&sessions)==nil && len(sessions)==0
}
func (a *Adapter) rebindHTTP(ctx context.Context,method,route string)([]byte,int,error) {
	// The origin comes exclusively from reviewed adapter config; scope and
	// ID are encoded, never constructed from browser-controlled URLs.
	req,err:=http.NewRequestWithContext(ctx,method,
		strings.TrimRight(a.cfg.KratosAdminURL,"/")+route,nil)
	if err!=nil {return nil,0,errCredentialRebindDenied}
	req.Header.Set("Accept","application/json")
	req.Header.Set("Cache-Control","no-store")
	client:=*a.http
	client.CheckRedirect=func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}
	if client.Timeout==0 || client.Timeout>10*time.Second {client.Timeout=10*time.Second}
	res,err:=client.Do(req)
	if err!=nil{return nil,0,errCredentialRebindDenied}
	defer res.Body.Close()
	if res.StatusCode!=http.StatusOK && res.StatusCode!=http.StatusNoContent {
		return nil,res.StatusCode,errCredentialRebindDenied
	}
	// Refuse incomplete or paginated active-session reads.
	if res.Header.Get("Link")!="" {
		return nil,res.StatusCode,errCredentialRebindDenied
	}
	if res.StatusCode==http.StatusNoContent{return nil,res.StatusCode,nil}
	media,_,err:=mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err!=nil || media!="application/json" {return nil,0,errCredentialRebindDenied}
	data,err:=io.ReadAll(io.LimitReader(res.Body,131073))
	if err!=nil || len(data)>131072 {return nil,0,errCredentialRebindDenied}
	return data,res.StatusCode,nil
}
