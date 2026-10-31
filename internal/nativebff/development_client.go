package nativebff

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// DevelopmentEstateClient is a real Hydra OAuth client, NOT a CP client,
// a canonical provider support, a business grant or a protected registration.
// A bounded development lease under ADR-SHARED-043 authorizes this isolated
// provider-only operation; protected environments have a separate ceremony.
type DevelopmentEstateClient struct {
	Environment string
	Estate string
	RunID string
	RedirectURI string
	PublicOrigin string
	ClientSecret string
	ExpiresAt time.Time
}
type DevelopmentClientRegistry struct {
	adminOrigin string
	client *http.Client
	now func() time.Time
}

func NewDevelopmentClientRegistry(adminOrigin string, client *http.Client, now func()time.Time)(*DevelopmentClientRegistry,error){
	u,err:=url.Parse(adminOrigin)
	if err!=nil||u.Hostname()==""||u.User!=nil||u.Fragment!=""||u.RawQuery!=""||
		(u.Path!=""&&u.Path!="/")||now==nil{
		return nil,errors.New("invalid Hydra development admin origin")
	}
	ip:=net.ParseIP(u.Hostname())
	if ip==nil || !ip.IsLoopback() || u.Scheme!="http" && u.Scheme!="https"{
		return nil,errors.New("development admin requires HTTPS or exact loopback")
	}
	// Only exact loopback fixture transport may be injected.
	if client!=nil && !(ip!=nil&&ip.IsLoopback()){
		return nil,errors.New("external Hydra admin transport cannot be injected")
	}
	if client==nil{
		client=&http.Client{Timeout:6*time.Second,
			CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse},
			Transport:&http.Transport{Proxy:nil,TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS12}}}
	}
	return &DevelopmentClientRegistry{strings.TrimRight(adminOrigin,"/"),client,now},nil
}

func validRunID(s string)bool{
	if len(s)!=32{return false}
	for _,c:=range s{if c<'0'||c>'9'&&c<'a'||c>'f'{return false}}
	return true
}
func (r *DevelopmentClientRegistry) name(l DevelopmentEstateClient)(string,error){
	if r==nil||r.now==nil||l.Environment!="development"||l.Estate!="zuribeans"||!validRunID(l.RunID)||
		len(l.ClientSecret)<32||strings.TrimSpace(l.ClientSecret)!=l.ClientSecret||
		strings.ContainsAny(l.ClientSecret," \t\r\n")||l.ExpiresAt.Sub(r.now())<=0||
		l.ExpiresAt.Sub(r.now())>time.Hour{
		return "",errors.New("unapproved bounded synthetic estate lease")
	}
	redirect,err:=url.Parse(l.RedirectURI)
    if err!=nil||redirect.Hostname()==""||redirect.Path!="/auth/callback"||
        redirect.RawQuery!=""||redirect.Fragment!=""||redirect.User!=nil||
        redirect.Scheme!="https" && !(redirect.Scheme=="http" &&
            redirect.Host=="127.0.0.1:3000") {
        return "",errors.New("unapproved development estate callback")
    }
    // The lease is issued by the development owner, not from a request URL.
    // The exact deployed first-party origin is required to match the callback.
    // HTTPS may use a private development host; plaintext is strict loopback.
    if l.PublicOrigin==""||l.PublicOrigin+"/auth/callback"!=l.RedirectURI{
        return "",errors.New("reviewed first-party callback origin mismatch")
    }
	return "baobab-dev-zuribeans-native-browser-bff",nil
}
func (r *DevelopmentClientRegistry) request(ctx context.Context,method,path string,in any)(int,[]byte,error){
	var payload []byte
	var err error
	if in!=nil {payload,err=json.Marshal(in);if err!=nil{return 0,nil,errors.New("invalid client registration")}}
	req,err:=http.NewRequestWithContext(ctx,method,r.adminOrigin+path,bytes.NewReader(payload))
	if err!=nil{return 0,nil,errors.New("invalid Hydra client request")}
	req.Header.Set("Accept","application/json")
	req.Header.Set("Content-Type","application/json")
	req.Header.Set("Cache-Control","no-store")
	resp,err:=r.client.Do(req)
	if err!=nil{return 0,nil,errors.New("Hydra client registry unavailable")}
	defer resp.Body.Close()
	raw,err:=io.ReadAll(io.LimitReader(resp.Body,65537))
	if err!=nil||len(raw)>65536{return 0,nil,errors.New("invalid Hydra client registry response")}
	return resp.StatusCode,raw,nil
}

// CreateDevelopment creates a *real* confidential client through Hydra Admin,
// reads it back independently and refuses a broadened/wrong provider profile.
// It does not create or infer any CP human, client binding or legal authority.
func (r *DevelopmentClientRegistry) CreateDevelopment(ctx context.Context,l DevelopmentEstateClient)(string,error){
	if ctx==nil||ctx.Err()!=nil{return "",errors.New("development lease unavailable")}
	id,err:=r.name(l);if err!=nil{return "",err}
	body:=map[string]any{
		"client_id":id,"client_secret":l.ClientSecret,
        "metadata":map[string]string{"development_run_id":l.RunID,
            "environment":"development","estate":"zuribeans"},
		"grant_types":[]string{"authorization_code"},
		"response_types":[]string{"code"},
		"scope":"openid trade:buy",
		"audience":[]string{"baobab-trade"},
		"redirect_uris":[]string{l.RedirectURI},
		"token_endpoint_auth_method":"client_secret_basic",
		"subject_type":"public",
		"skip_consent":false,
	}
	status,_,err:=r.request(ctx,http.MethodPost,"/admin/clients",body)
	if err!=nil||status!=http.StatusCreated{return "",errors.New("Hydra client not registered")}
	// A partially created/ambiguous client cannot be silently adopted.
	if err=r.Readback(ctx,id,l.RedirectURI,l.RunID);err!=nil{
		return "",errors.New("Hydra client readback failed; explicit teardown required")
	}
	return id,nil
}

func (r *DevelopmentClientRegistry) Readback(ctx context.Context,id,redirect,runID string)error{
	if r==nil||id!="baobab-dev-zuribeans-native-browser-bff"||!validRunID(runID){return errors.New("outside synthetic development client scope")}
	status,raw,err:=r.request(ctx,http.MethodGet,"/admin/clients/"+url.PathEscape(id),nil)
	if err!=nil||status!=http.StatusOK{return errors.New("registered client unreadable")}
	var v struct {
		ID string `json:"client_id"`
		GrantTypes []string `json:"grant_types"`
		ResponseTypes []string `json:"response_types"`
		Scope string `json:"scope"`
		Audience []string `json:"audience"`
		RedirectURIs []string `json:"redirect_uris"`
		Method string `json:"token_endpoint_auth_method"`
		SubjectType string `json:"subject_type"`
		SkipConsent bool `json:"skip_consent"`
        Metadata map[string]string `json:"metadata"`
	}
	if json.Unmarshal(raw,&v)!=nil||v.ID!=id||
		!slices.Equal(v.GrantTypes,[]string{"authorization_code"})||
		!slices.Equal(v.ResponseTypes,[]string{"code"})||
		v.Scope!="openid trade:buy"||
		!slices.Equal(v.Audience,[]string{"baobab-trade"})||
		!slices.Equal(v.RedirectURIs,[]string{redirect})||
		v.Method!="client_secret_basic"||v.SkipConsent||v.SubjectType!="public"||
        len(v.Metadata)!=3 || v.Metadata["environment"]!="development"||
        v.Metadata["estate"]!="zuribeans"||v.Metadata["development_run_id"]!=runID{
		return errors.New("Hydra client profile drift")
	}
	return nil
}

// DeleteDevelopment performs actual Hydra Delete plus independent 404 readback.
// Only this run-owned name is accepted; it cannot remove protected clients.
func (r *DevelopmentClientRegistry) DeleteDevelopment(ctx context.Context,id,runID string)error{
    if r==nil||id!="baobab-dev-zuribeans-native-browser-bff"||!validRunID(runID){
        return errors.New("development client teardown outside scope")
    }
    // A globally canonical client ID is safe only inside one isolated Hydra
    // development issuer. Do not delete a client owned by another lease.
    status,raw,err:=r.request(ctx,http.MethodGet,"/admin/clients/"+url.PathEscape(id),nil)
    if err!=nil||status!=http.StatusOK{return errors.New("Hydra client lease unreadable")}
    var current struct {
        ID string `json:"client_id"`
        Metadata map[string]string `json:"metadata"`
    }
    if json.Unmarshal(raw,&current)!=nil||current.ID!=id||
        len(current.Metadata)!=3||current.Metadata["environment"]!="development"||
        current.Metadata["estate"]!="zuribeans"||
        current.Metadata["development_run_id"]!=runID{
        return errors.New("Hydra client owned by another lease")
    }
    status,_,err=r.request(ctx,http.MethodDelete,"/admin/clients/"+url.PathEscape(id),nil)
    if err!=nil||status!=http.StatusNoContent && status!=http.StatusOK{return errors.New("Hydra client teardown unconfirmed")}
    status,_,err=r.request(ctx,http.MethodGet,"/admin/clients/"+url.PathEscape(id),nil)
    if err!=nil||status!=http.StatusNotFound{return errors.New("Hydra client still visible after delete")}
    return nil
}
