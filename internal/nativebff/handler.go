// Package nativebff is the server-only browser boundary for the governed
// Kratos/Hydra human handoff (ADR-IAM-0023, ADR-IAM-0033, EA-DEV DEV-03/05).
// It neither creates CP Principals nor grants any tenant/domain authority.
package nativebff

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/humanauth"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	transactionCookie = "__Host-baobab-native-txn"
	sessionCookie = "__Host-baobab-native-session"
	maxTransactionAge = 5 * time.Minute
	maxSessionAge = 30 * time.Minute
)

type Handoff interface {
	AcceptLogin(context.Context, string, ory.NativeSessionCredential, humanauth.Request) (string, error)
	AcceptConsent(context.Context, string, ory.NativeSessionCredential, humanauth.Request, bool) (string, error)
}

// Principal is CP's resolved existing human mapping, never inferred from
// ID token email, domain, groups, user-controlled tenant, or the estate.
type Principal struct { ID string }

// PrincipalResolver must perform fresh, independently authenticated CP
// exact issuer+subject resolution and check current lifecycle on every read.
type PrincipalResolver interface {
	ResolveHuman(context.Context, string, string, string) (Principal, error)
}

// Revoker revokes provider access/refresh tokens (not just local cookies).
// The Kratos browser session has a separate provider logout/revocation lifecycle.
type Revoker interface {
	Revoke(context.Context, humanauth.Response) error
}

type IDVerifier interface {
	Verify(context.Context, string, string) (string, error)
}

type Transaction struct {
	Intent humanauth.Request `json:"intent"`
	Verifier string `json:"verifier"`
	CSRF string `json:"csrf"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Session struct {
	Subject string `json:"subject"`
	Issuer string `json:"issuer"`
	PrincipalID string `json:"principal_id"`
	CSRF string `json:"csrf"`
	ExpiresAt time.Time `json:"expires_at"`
	Tokens humanauth.Response `json:"tokens"`
}

// Store must atomically burn a transaction before exchanging a code and
// delete a session on logout. The persistent implementation encrypts records.
type Store interface {
	PutTransaction(context.Context, string, Transaction) error
	ReadTransaction(context.Context, string) (Transaction, error)
	TakeTransaction(context.Context, string) (Transaction, error)
	PutSession(context.Context, string, Session) error
	ReadSession(context.Context, string) (Session, error)
	DeleteSession(context.Context, string) error
}

type Config struct {
	PublicOrigin, Issuer, ClientID, ClientSecret, RedirectURI, Scope string
	KratosSessionCookieName string
	Now func() time.Time
	Handoff Handoff
	CP PrincipalResolver
	Revoker Revoker
	Store Store
	HTTPClient *http.Client
	Verifier IDVerifier
	AccessAudience, AccessScope string
	// Only disposable loopback tests may inject an ID verifier or use HTTP.
	AllowTestLoopback bool
}

type Handler struct {
	c Config
	verify IDVerifier
	access IDVerifier
	client *http.Client
	origin *url.URL
	issuer *url.URL
}

func originURL(s string, allowTest bool) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("invalid configured origin")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if !allowTest || u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return nil, errors.New("browser origin requires HTTPS")
		}
	}
	return u, nil
}

// New requires a configured private storage, a genuine provider-handoff
// service and current CP authority. No in-memory production fallback exists.
func New(c Config) (*Handler, error) {
	origin, err := originURL(c.PublicOrigin, c.AllowTestLoopback)
	if err != nil { return nil, err }
	issuer, err := originURL(c.Issuer, c.AllowTestLoopback)
	if err != nil { return nil, err }
	redirect := strings.TrimRight(c.PublicOrigin, "/") + "/auth/callback"
	if c.RedirectURI != redirect || c.ClientID == "" || len(c.ClientID) > 255 || len(c.ClientSecret) < 32 ||
		c.Now == nil || c.Handoff == nil || c.CP == nil || c.Revoker == nil || c.Store == nil ||
		c.KratosSessionCookieName != "ory_kratos_session" || c.AccessAudience == "" || c.AccessScope == "" {
		return nil, errors.New("incomplete confidential native BFF configuration")
	}
	scopes := strings.Fields(c.Scope)
	if len(scopes) == 0 || scopes[0] != "openid" || len(scopes) > 12 { return nil, errors.New("invalid configured scopes") }
	seen := make(map[string]bool)
	for _, scope := range scopes {
		if seen[scope] || strings.TrimSpace(scope) == "" { return nil, errors.New("duplicate scope") }
		seen[scope] = true
	}
	if c.Scope != strings.Join(scopes, " ") { return nil, errors.New("noncanonical scope list") }
	if c.Verifier != nil && !c.AllowTestLoopback { return nil, errors.New("production requires cryptographic ID verification") }
	client := &http.Client{Timeout: 10*time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if c.AllowTestLoopback && c.HTTPClient != nil { client.Transport = c.HTTPClient.Transport }
	if !c.AllowTestLoopback && c.HTTPClient != nil { return nil, errors.New("production browser provider transport cannot be injected") }
	var verifier IDVerifier
	if c.Verifier != nil { verifier = c.Verifier } else {
		verifier = &signedIDVerifier{
			issuer: strings.TrimRight(c.Issuer, "/"),
			clientID: c.ClientID,
			keys: oidc.NewRemoteKeySet(context.Background(), strings.TrimRight(c.Issuer, "/")+"/.well-known/jwks.json"),
		}
	}
	access := &signedAccessVerifier{issuer: strings.TrimRight(c.Issuer, "/"), audience:c.AccessAudience, scope:c.AccessScope, keys:oidc.NewRemoteKeySet(context.Background(), strings.TrimRight(c.Issuer,"/")+"/.well-known/jwks.json")}
	return &Handler{c:c,verify:verifier,access:access,client:client,origin:origin,issuer:issuer}, nil
}

type signedIDVerifier struct { issuer, clientID string; keys oidc.KeySet }
func (v *signedIDVerifier) Verify(ctx context.Context, raw, nonce string) (string, error) {
	if raw == "" || nonce == "" || len(raw) > 16384 { return "", errors.New("missing ID token or nonce") }
	id, err := oidc.NewVerifier(v.issuer, v.keys, &oidc.Config{
		ClientID:v.clientID, SupportedSigningAlgs:[]string{"RS256"},
	}).Verify(ctx,raw)
	if err != nil || id.Subject == "" || id.Nonce == "" || subtle.ConstantTimeCompare([]byte(id.Nonce),[]byte(nonce)) != 1 {
		return "", errors.New("invalid signed ID token")
	}
	return id.Subject, nil
}

type signedAccessVerifier struct { issuer, audience, scope string; keys oidc.KeySet }
func (v *signedAccessVerifier) Verify(ctx context.Context, raw, subject string) (string,error) {
	if len(raw)<20 || len(raw)>16384 || subject=="" {return "",errors.New("missing human access token")}
	verified,err:=oidc.NewVerifier(v.issuer,v.keys,&oidc.Config{ClientID:v.audience,SupportedSigningAlgs:[]string{"RS256"}}).Verify(ctx,raw)
	if err!=nil || verified.Subject!=subject {return "",errors.New("human access token subject mismatch")}
	var claims struct {
		ActorType string `json:"actor_type"`
		Scope string `json:"scope"`
	}
	if verified.Claims(&claims)!=nil || claims.ActorType!="human" || !strings.Contains(" "+claims.Scope+" "," "+v.scope+" ") {
		return "",errors.New("human access token scope or actor invalid")
	}
	return verified.Subject,nil
}
func randomValue() (string,error) {
	var bytes [32]byte
	if _,err:=rand.Read(bytes[:]);err!=nil {return "",err}
	return base64.RawURLEncoding.EncodeToString(bytes[:]),nil
}
func cookie(w http.ResponseWriter, name, value string, age int, sameSite http.SameSite) {
	http.SetCookie(w,&http.Cookie{Name:name,Value:value,Path:"/",Secure:true,HttpOnly:true,SameSite:sameSite,MaxAge:age})
}
func expireCookie(w http.ResponseWriter, name string, mode http.SameSite) {
	cookie(w,name,"",-1,mode)
}
func (h *Handler) fail(w http.ResponseWriter, status int) {
	http.Error(w,http.StatusText(status),status)
}
func (h *Handler) noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control","no-store")
	w.Header().Set("Pragma","no-cache")
	w.Header().Set("X-Content-Type-Options","nosniff")
	w.Header().Set("Referrer-Policy","no-referrer")
	w.Header().Set("Content-Security-Policy","default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
}
func (h *Handler) postOrigin(r *http.Request) bool {
	values:=r.Header.Values("Origin")
	return len(values)==1 && values[0]==strings.TrimRight(h.c.PublicOrigin,"/")
}
func exactQuery(query url.Values, required ...string) bool {
	if len(query)!=len(required) {return false}
	for _,k:=range required {if len(query[k])!=1 || query.Get(k)=="" {return false}}
	return true
}
func (h *Handler) tx(r *http.Request) (string,Transaction,error) {
	c,err:=r.Cookie(transactionCookie);if err!=nil||len(c.Value)!=43 {return "",Transaction{},errors.New("transaction cookie missing")}
	tx,err:=h.c.Store.ReadTransaction(r.Context(),c.Value)
	if err!=nil || !h.c.Now().Before(tx.ExpiresAt) {return "",Transaction{},errors.New("transaction expired")}
	return c.Value,tx,nil
}
func (h *Handler) kratos(r *http.Request) (ory.NativeSessionCredential,error) {
	c,err:=r.Cookie(h.c.KratosSessionCookieName)
	if err!=nil || c.Value=="" || len(c.Value)>2048 || strings.ContainsAny(c.Value," \r\n;") {
		return ory.NativeSessionCredential{},errors.New("verified Kratos browser session required")
	}
	return ory.NativeSessionCredential{Cookie:c.Name+"="+c.Value},nil
}
func (h *Handler) routes() http.Handler {
	mux:=http.NewServeMux()
	mux.HandleFunc("POST /auth/start",h.start)
	mux.HandleFunc("GET /auth/login",h.login)
	mux.HandleFunc("GET /auth/consent",h.consentPage)
	mux.HandleFunc("POST /auth/consent",h.consent)
	mux.HandleFunc("GET /auth/callback",h.callback)
	mux.HandleFunc("GET /auth/session",h.session)
	mux.HandleFunc("POST /auth/logout",h.logout)
	return mux
}
func (h *Handler) ServeHTTP(w http.ResponseWriter,r *http.Request) {
	h.noStore(w)
	if r.TLS==nil && !h.c.AllowTestLoopback {h.fail(w,http.StatusUpgradeRequired);return}
	h.routes().ServeHTTP(w,r)
}

func (h *Handler) start(w http.ResponseWriter,r *http.Request) {
	if !h.postOrigin(r)||r.URL.RawQuery!="" {h.fail(w,403);return}
	id,e1:=randomValue();verifier,e2:=randomValue();state,e3:=randomValue();nonce,e4:=randomValue();csrf,e5:=randomValue()
	if e1!=nil||e2!=nil||e3!=nil||e4!=nil||e5!=nil {h.fail(w,503);return}
	digest:=sha256.Sum256([]byte(verifier))
	intent:=humanauth.Request{
		GrantType:"authorization_code",ClientID:h.c.ClientID,RedirectURI:h.c.RedirectURI,
		Scope:h.c.Scope,State:state,Nonce:nonce,
		CodeChallenge:base64.RawURLEncoding.EncodeToString(digest[:]),CodeChallengeMethod:"S256",
	}
	if intent.Validate()!=nil {h.fail(w,503);return}
	tx:=Transaction{Intent:intent,Verifier:verifier,CSRF:csrf,ExpiresAt:h.c.Now().Add(maxTransactionAge)}
	if h.c.Store.PutTransaction(r.Context(),id,tx)!=nil {h.fail(w,503);return}
	cookie(w,transactionCookie,id,int(maxTransactionAge.Seconds()),http.SameSiteLaxMode)
	values:=url.Values{"response_type":{"code"},"client_id":{intent.ClientID},"redirect_uri":{intent.RedirectURI},
		"scope":{intent.Scope},"state":{intent.State},"nonce":{intent.Nonce},
		"code_challenge":{intent.CodeChallenge},"code_challenge_method":{"S256"}}
	http.Redirect(w,r,strings.TrimRight(h.c.Issuer,"/")+"/oauth2/auth?"+values.Encode(),http.StatusSeeOther)
}
func (h *Handler) login(w http.ResponseWriter,r *http.Request) {
	if !exactQuery(r.URL.Query(),"login_challenge") {h.fail(w,400);return}
	_,tx,err:=h.tx(r);if err!=nil {h.fail(w,401);return}
	cred,err:=h.kratos(r);if err!=nil {h.fail(w,401);return}
	dest,err:=h.c.Handoff.AcceptLogin(r.Context(),r.URL.Query().Get("login_challenge"),cred,tx.Intent)
	if err!=nil||!h.safeHydra(dest) {h.fail(w,403);return}
	http.Redirect(w,r,dest,http.StatusSeeOther)
}
func (h *Handler) safeHydra(dest string) bool {
	u,err:=url.Parse(dest)
	return err==nil && u.User==nil && u.Fragment=="" && u.Scheme==h.issuer.Scheme &&
		u.Host==h.issuer.Host && u.Path=="/oauth2/auth"
}
var consentForm=template.Must(template.New("consent").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Authorize access</title>
<h1>Authorize access</h1><p>Application: {{.Client}}</p><p>Requested scopes: {{.Scopes}}</p>
<form method="post" action="/auth/consent?consent_challenge={{.Challenge}}">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<button type="submit" name="approve" value="yes">Allow</button></form></html>`))
func (h *Handler) consentPage(w http.ResponseWriter,r *http.Request) {
	if !exactQuery(r.URL.Query(),"consent_challenge") {h.fail(w,400);return}
	_,tx,err:=h.tx(r);if err!=nil {h.fail(w,401);return}
	if _,err=h.kratos(r);err!=nil {h.fail(w,401);return}
	w.Header().Set("Content-Type","text/html; charset=utf-8")
	_ = consentForm.Execute(w,struct{Client,Scopes,Challenge,CSRF string}{
		tx.Intent.ClientID,tx.Intent.Scope,r.URL.Query().Get("consent_challenge"),tx.CSRF,
	})
}
func (h *Handler) consent(w http.ResponseWriter,r *http.Request) {
	if !h.postOrigin(r)||!exactQuery(r.URL.Query(),"consent_challenge") {h.fail(w,403);return}
	_,tx,err:=h.tx(r);if err!=nil {h.fail(w,401);return}
	r.Body=http.MaxBytesReader(w,r.Body,4096)
	if r.ParseForm()!=nil || len(r.PostForm)!=2 || len(r.PostForm["csrf"])!=1 ||
		len(r.PostForm["approve"])!=1 || r.PostForm.Get("approve")!="yes" ||
		subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")),[]byte(tx.CSRF))!=1 {
		h.fail(w,403);return
	}
	cred,err:=h.kratos(r);if err!=nil {h.fail(w,401);return}
	dest,err:=h.c.Handoff.AcceptConsent(r.Context(),r.URL.Query().Get("consent_challenge"),cred,tx.Intent,true)
	if err!=nil||!h.safeHydra(dest) {h.fail(w,403);return}
	http.Redirect(w,r,dest,http.StatusSeeOther)
}
func (h *Handler) callback(w http.ResponseWriter,r *http.Request) {
	if !exactQuery(r.URL.Query(),"code","state") {h.fail(w,400);return}
	id,tx,err:=h.tx(r);if err!=nil {h.fail(w,401);return}
	if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("state")),[]byte(tx.Intent.State))!=1 {h.fail(w,403);return}
	// Irreversible and single-use even if the provider or CP later times out.
	tx,err=h.c.Store.TakeTransaction(r.Context(),id)
	expireCookie(w,transactionCookie,http.SameSiteLaxMode)
	if err!=nil||!h.c.Now().Before(tx.ExpiresAt) {h.fail(w,403);return}
	tokens,err:=h.exchange(r.Context(),r.URL.Query().Get("code"),tx)
	if err!=nil {h.fail(w,403);return}
	sub,err:=h.verify.Verify(r.Context(),tokens.IDToken,tx.Intent.Nonce)
	if err!=nil {h.fail(w,403);return}
	if _,err=h.access.Verify(r.Context(),tokens.AccessToken,sub);err!=nil {h.fail(w,403);return}
	principal,err:=h.c.CP.ResolveHuman(r.Context(),strings.TrimRight(h.c.Issuer,"/"),sub,tokens.AccessToken)
	if err!=nil||principal.ID=="" {h.fail(w,403);return}
	sessionID,err:=randomValue();if err!=nil {h.fail(w,503);return}
	csrf,err:=randomValue();if err!=nil {h.fail(w,503);return}
	lifetime:=time.Duration(tokens.ExpiresIn)*time.Second
	if lifetime>maxSessionAge {lifetime=maxSessionAge}
	session:=Session{Subject:sub,Issuer:strings.TrimRight(h.c.Issuer,"/"),PrincipalID:principal.ID,CSRF:csrf,ExpiresAt:h.c.Now().Add(lifetime),Tokens:tokens}
	if h.c.Store.PutSession(r.Context(),sessionID,session)!=nil {h.fail(w,503);return}
	cookie(w,sessionCookie,sessionID,int(lifetime.Seconds()),http.SameSiteStrictMode)
	http.Redirect(w,r,"/",http.StatusSeeOther)
}
func (h *Handler) exchange(ctx context.Context,code string,tx Transaction)(humanauth.Response,error) {
	var zero humanauth.Response
	if len(code)<8||len(code)>4096||strings.ContainsAny(code," 
") {return zero,errors.New("invalid authorization code")}
	form:=url.Values{"grant_type":{"authorization_code"},"code":{code},"redirect_uri":{h.c.RedirectURI},"code_verifier":{tx.Verifier}}
	req,err:=http.NewRequestWithContext(ctx,"POST",strings.TrimRight(h.c.Issuer,"/")+"/oauth2/token",strings.NewReader(form.Encode()))
	if err!=nil {return zero,err}
	req.Header.Set("Content-Type","application/x-www-form-urlencoded")
	req.SetBasicAuth(h.c.ClientID,h.c.ClientSecret)
	resp,err:=h.client.Do(req);if err!=nil {return zero,errors.New("OAuth token service unavailable")}
	defer resp.Body.Close()
	raw,err:=io.ReadAll(io.LimitReader(resp.Body,65537))
	if err!=nil||len(raw)>65536||resp.StatusCode!=200 {return zero,errors.New("OAuth code exchange denied")}
	tokens,err:=humanauth.ProjectOAuthResponse(raw)
	if err!=nil||tokens.IDToken==""||tokens.Validate()!=nil {return zero,errors.New("canonical OAuth response denied")}
	return tokens,nil
}
func (h *Handler) authenticated(r *http.Request)(string,Session,error) {
	c,err:=r.Cookie(sessionCookie);if err!=nil||len(c.Value)!=43 {return "",Session{},errors.New("session missing")}
	s,err:=h.c.Store.ReadSession(r.Context(),c.Value)
	if err!=nil||s.Issuer!=strings.TrimRight(h.c.Issuer,"/")||s.Subject==""||s.PrincipalID==""||!h.c.Now().Before(s.ExpiresAt) {
		return "",Session{},errors.New("session invalid")
	}
	// CP is the canonical authority on every read, never a cached browser grant.
	p,err:=h.c.CP.ResolveHuman(r.Context(),s.Issuer,s.Subject,s.Tokens.AccessToken)
	if err!=nil||p.ID==""||p.ID!=s.PrincipalID {return "",Session{},errors.New("current CP mapping denied")}
	return c.Value,s,nil
}
func (h *Handler) session(w http.ResponseWriter,r *http.Request) {
	if r.URL.RawQuery!="" {h.fail(w,400);return}
	_,s,err:=h.authenticated(r);if err!=nil {h.fail(w,401);return}
	w.Header().Set("Content-Type","application/json")
	_ = json.NewEncoder(w).Encode(struct{
		Authenticated bool `json:"authenticated"`
		PrincipalID string `json:"principal_id"`
		CSRF string `json:"csrf"`
	}{true,s.PrincipalID,s.CSRF})
}
func (h *Handler) logout(w http.ResponseWriter,r *http.Request) {
	if !h.postOrigin(r)||r.URL.RawQuery!="" {h.fail(w,403);return}
	id,s,err:=h.authenticated(r);if err!=nil {h.fail(w,401);return}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")),[]byte(s.CSRF))!=1 {h.fail(w,403);return}
	// Delete the BFF session first; uncertainty must never restore it.
	err=h.c.Store.DeleteSession(r.Context(),id)
	if err!=nil {h.fail(w,503);return}
	expireCookie(w,sessionCookie,http.SameSiteStrictMode)
	if err=h.c.Revoker.Revoke(r.Context(),s.Tokens);err!=nil {
		// Local logout took effect, but remote token status is still UNKNOWN.
		h.fail(w,503);return
	}
	w.WriteHeader(http.StatusNoContent)
}

var _ http.Handler = (*Handler)(nil)
var _ Handoff = (*ory.GovernedNativeHumanHandoff)(nil)
