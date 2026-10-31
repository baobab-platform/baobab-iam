package nativebff

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

// HydraSubjectSessionsRevoker owns IAM-private issuer-admin session withdrawal.
// These two Hydra endpoints remove remembered login and consent sessions for
// the exact signed Kratos subject. Login-session revocation alone does NOT
// invalidate OAuth tokens. Even consent-session deletion cannot certify
// stateless JWT bearer withdrawal at CP/Trade: verify issuer status at the
// protected resource independently before declaring global logout complete.
type HydraSubjectSessionsRevoker struct {
	origin string
	client *http.Client
}
type HydraSubjectSessionsConfig struct {
	AdminOrigin string
	Roots *x509.CertPool
}
func NewHydraSubjectSessionsRevoker(config HydraSubjectSessionsConfig)(*HydraSubjectSessionsRevoker,error){
	origin,err:=originURL(config.AdminOrigin,false)
	if err!=nil||origin.Scheme!="https"||config.Roots==nil{
		return nil,errors.New("private verified Hydra administration required")
	}
	return &HydraSubjectSessionsRevoker{
		origin:config.AdminOrigin,
		client:&http.Client{
			Timeout:5*time.Second,
			CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse},
			Transport:&http.Transport{Proxy:nil,TLSClientConfig:&tls.Config{RootCAs:config.Roots,MinVersion:tls.VersionTLS12}},
		},
	},nil
}
func (h *HydraSubjectSessionsRevoker) RevokeSubjectSessions(ctx context.Context,subject string)error {
	if h==nil||ctx==nil||ctx.Err()!=nil||!isUUID(subject){return errors.New("invalid OAuth subject")}
	// Consent first: revocation may be completed partially. Never silently
	// interpret a timeout as consent or token withdrawal success.
	for _,endpoint:=range []string{"/admin/oauth2/auth/sessions/consent","/admin/oauth2/auth/sessions/login"} {
		values:=url.Values{"subject":{subject}}
		if endpoint=="/admin/oauth2/auth/sessions/consent" {values.Set("all","true")}
		request,err:=http.NewRequestWithContext(ctx,http.MethodDelete,h.origin+endpoint+"?"+values.Encode(),nil)
		if err!=nil{return errors.New("invalid Hydra session revocation")}
		request.Header.Set("Accept","application/json")
		request.Header.Set("Cache-Control","no-store")
		response,err:=h.client.Do(request)
		if err!=nil{return errors.New("Hydra subject revocation outcome unknown")}
		_,_ = io.Copy(io.Discard,io.LimitReader(response.Body,512))
		_ = response.Body.Close()
		if response.StatusCode!=http.StatusNoContent&&response.StatusCode!=http.StatusOK{
			return errors.New("Hydra subject revocation not confirmed")
		}
	}
	return nil
}
var _ OAuthSubjectSessionRevoker = (*HydraSubjectSessionsRevoker)(nil)
