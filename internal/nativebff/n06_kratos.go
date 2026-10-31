package nativebff

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/assurance"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

// KratosN06Provider is the actual current-session AAL1/AAL2 reader. It does
// not falsely promote passkey enrollment or an unaudited WebAuthn method name
// to A3: a separate RP-origin/UV assertion verifier must be qualified first.
type KratosN06Provider struct {
	origin string
	client *http.Client
	now func()time.Time
}
func NewKratosN06Provider(origin string, roots *x509.CertPool, now func()time.Time,
	allowTestLoopback bool,testClient *http.Client)(*KratosN06Provider,error){
	u,err:=originURL(origin,allowTestLoopback)
	if err!=nil || now==nil || (!allowTestLoopback&&(roots==nil||len(roots.Subjects())==0||testClient!=nil)) {
		return nil,errors.New("N06 exact trusted Kratos origin and roots required")
	}
	client:=&http.Client{
		Timeout:5*time.Second,
		CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse},
		Transport:&http.Transport{Proxy:nil,TLSClientConfig:&tls.Config{
			MinVersion:tls.VersionTLS12,RootCAs:roots}},
	}
	if allowTestLoopback&&testClient!=nil {client.Transport=testClient.Transport}
	return &KratosN06Provider{origin:strings.TrimRight(u.String(),"/"),client:client,now:now},nil
}
func (k *KratosN06Provider) CurrentNativeAuthentication(
	ctx context.Context,cred ory.NativeSessionCredential,
)(assurance.CurrentSessionKey,assurance.Evidence,error){
	var none assurance.CurrentSessionKey
	var empty assurance.Evidence
	if k==nil||ctx==nil||ctx.Err()!=nil||cred.SessionToken!=""||
		!strings.HasPrefix(cred.Cookie,"ory_kratos_session=")||
		len(cred.Cookie)<25||len(cred.Cookie)>2048||
		strings.ContainsAny(cred.Cookie,";\r\n ") {
		return none,empty,errors.New("N06 approved Kratos browser cookie required")
	}
	req,err:=http.NewRequestWithContext(ctx,http.MethodGet,k.origin+"/sessions/whoami",nil)
	if err!=nil{return none,empty,errors.New("N06 Kratos request refused")}
	req.Header.Set("Cookie",cred.Cookie)
	req.Header.Set("Accept","application/json")
	req.Header.Set("Cache-Control","no-store")
	response,err:=k.client.Do(req)
	if err!=nil{return none,empty,errors.New("N06 trusted Kratos session unavailable")}
	defer response.Body.Close()
	media,_,err:=mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err!=nil||media!="application/json"||response.StatusCode!=http.StatusOK{
		return none,empty,errors.New("N06 Kratos session not confirmed")
	}
	raw,err:=io.ReadAll(io.LimitReader(response.Body,32769))
	if err!=nil||len(raw)>32768{return none,empty,errors.New("N06 oversized provider proof")}
	var row struct {
		ID string `json:"id"`
		Active bool `json:"active"`
		ExpiresAt time.Time `json:"expires_at"`
		AuthenticatedAt time.Time `json:"authenticated_at"`
		AAL string `json:"authenticator_assurance_level"`
		Methods []struct {Method string `json:"method"`} `json:"authentication_methods"`
		Identity struct {
			ID string `json:"id"`
			State string `json:"state"`
		} `json:"identity"`
	}
	d:=json.NewDecoder(bytes.NewReader(raw))
	if err:=d.Decode(&row);err!=nil||d.Decode(new(any))!=io.EOF{
		return none,empty,errors.New("N06 malformed provider proof")
	}
	now:=k.now().UTC()
	if !row.Active||row.Identity.State!="active"||row.ID==""||row.Identity.ID==""||
		row.AAL!="aal1"&&row.AAL!="aal2"||
		row.AuthenticatedAt.IsZero()||row.AuthenticatedAt.After(now)||
		!row.ExpiresAt.After(now)||len(row.Methods)>12||len(row.Methods)==0 {
		return none,empty,errors.New("N06 inactive or incomplete Kratos session")
	}
	methods:=make([]string,0,len(row.Methods))
	for _,m:=range row.Methods {
		if m.Method==""||len(m.Method)>40{return none,empty,errors.New("N06 unknown Kratos authenticator method")}
		methods=append(methods,m.Method)
	}
	key:=assurance.CurrentSessionKey{
		Issuer:k.origin,Subject:row.Identity.ID,SessionID:row.ID,
	}
	evidence:=assurance.Evidence{
		Issuer:key.Issuer,Subject:key.Subject,SessionID:key.SessionID,
		ObservedAt:now,AuthenticatedAt:row.AuthenticatedAt,
		AAL:row.AAL,Methods:methods,
		// No raw WebAuthn attestation or RP user-verification proof in
		// this Kratos session response. Therefore NEVER award A3/A4.
		PasskeyUsed:false,UserVerified:false,OriginBound:false,
		HardwareBound:false,
	}
	return key,evidence,nil
}
var _ N06ProviderProof=(*KratosN06Provider)(nil)
