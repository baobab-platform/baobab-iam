package workloadresource

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RFC7662Introspector obtains current access-token status directly from a
// protected issuer introspection endpoint. It is not an IAM token proxy.
// The resource's separately registered introspection client is configured
// through a protected secret boundary, never a browser or token claim.
type RFC7662Introspector struct {
	endpoint string
	clientID string
	secret string
	client *http.Client
}

func NewRFC7662Introspector(endpoint, clientID, secret string, roots *x509.CertPool) (*RFC7662Introspector, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || u.Path == "" ||
		clientID == "" || strings.TrimSpace(clientID) != clientID ||
		len(secret) < 32 || strings.TrimSpace(secret) != secret {
		return nil, ErrDenied
	}
	return &RFC7662Introspector{
		endpoint: endpoint, clientID: clientID, secret: secret,
		client: &http.Client{Timeout: 8*time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12, RootCAs: roots,
			}},
		},
	}, nil
}

func decodeUnique(raw []byte) (map[string]json.RawMessage, error) {
	if len(raw) > 16384 { return nil, ErrDenied }
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') { return nil, ErrDenied }
	values := make(map[string]json.RawMessage)
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok { return nil, ErrDenied }
		if _, exists := values[key]; exists { return nil, ErrDenied }
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, ErrDenied
		}
		values[key] = value
	}
	if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
		return nil, ErrDenied
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) { return nil, ErrDenied }
	return values, nil
}
func audienceField(value json.RawMessage) ([]string, error) {
	var one string
	if json.Unmarshal(value, &one) == nil {
		if one == "" { return nil, ErrDenied }
		return []string{one}, nil
	}
	var many []string
	if json.Unmarshal(value, &many) != nil || len(many) == 0 || !distinct(many) {
		return nil, ErrDenied
	}
	for _, entry := range many { if entry == "" { return nil, ErrDenied } }
	return many, nil
}

func (i *RFC7662Introspector) ReadCurrent(ctx context.Context, bearer string) (LiveStatus, error) {
	if i == nil || ctx == nil || ctx.Err() != nil || len(bearer) < 20 ||
		len(bearer) > 16384 || strings.TrimSpace(bearer) != bearer {
		return LiveStatus{}, ErrDenied
	}
	form := url.Values{"token": {bearer}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.endpoint, strings.NewReader(form.Encode()))
	if err != nil { return LiveStatus{}, ErrDenied }
	req.SetBasicAuth(i.clientID, i.secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	resp, err := i.client.Do(req)
	if err != nil { return LiveStatus{}, ErrDenied }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { return LiveStatus{}, ErrDenied }
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16385))
	if err != nil || len(raw) > 16384 { return LiveStatus{}, ErrDenied }
	values, err := decodeUnique(raw)
	if err != nil { return LiveStatus{}, ErrDenied }
	var active bool
	var iss, sub, clientID, scope string
	var exp int64
	if json.Unmarshal(values["active"], &active) != nil || !active ||
		json.Unmarshal(values["iss"], &iss) != nil ||
		json.Unmarshal(values["sub"], &sub) != nil ||
		json.Unmarshal(values["client_id"], &clientID) != nil ||
		json.Unmarshal(values["scope"], &scope) != nil ||
		json.Unmarshal(values["exp"], &exp) != nil || exp <= 0 {
		return LiveStatus{}, ErrDenied
	}
	audience, err := audienceField(values["aud"])
	if err != nil || iss == "" || sub == "" || clientID == "" || scope == "" {
		return LiveStatus{}, ErrDenied
	}
	return LiveStatus{Active: true, Issuer: iss, Subject: sub, ClientID: clientID,
		Audience: audience, Scopes: strings.Fields(scope), ExpiresAt: time.Unix(exp, 0).UTC()}, nil
}
var _ IssuerStatusReader = (*RFC7662Introspector)(nil)
