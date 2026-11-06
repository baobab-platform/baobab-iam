package keycloak

// Keycloak remains the enterprise OIDC/SAML *federation* broker. This
// narrow admin operation terminates only one independently bound broker
// identity's local sessions. It cannot change native Kratos identities,
// Hydra clients, CP grants, a Tenant or an upstream enterprise IdP session.
import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var errFederatedContainment = errors.New("keycloak: current independently reviewed federation containment required")
var realmName = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
var brokerUserID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var referenceName = regexp.MustCompile(`^ref_[a-z0-9_-]{8,128}$`)

type FederationContainmentTarget struct {
	TrustID         string
	UpstreamIssuer  string
	UpstreamSubject string
	BrokerUserID    string
	FederationAlias string
	ChangeReference string
}
type FederationContainmentEvidence struct {
	Approved           bool
	DistinctReviewer   bool
	CurrentTrust       bool
	ExactBoundIdentity bool
	ObservedAt         time.Time
	OriginalReference  string
}
type FederationContainmentReviewer interface {
	CurrentFederatedContainment(context.Context, FederationContainmentTarget) (FederationContainmentEvidence, error)
}
type FederationAdminTokenSource interface {
	CurrentAdminBearer(context.Context) (string, error)
}
type FederationLocalContainment struct {
	AdminOrigin       string
	BrokerRealm       string
	Client            *http.Client
	Tokens            FederationAdminTokenSource
	Reviewer          FederationContainmentReviewer
	Now               func() time.Time
	AllowTestLoopback bool
}

func (c *FederationLocalContainment) trusted() bool {
	if c == nil || c.Client == nil || c.Tokens == nil || c.Reviewer == nil ||
		c.Now == nil || !realmName.MatchString(c.BrokerRealm) ||
		c.BrokerRealm == "master" {
		return false
	}
	u, err := url.Parse(c.AdminOrigin)
	if err != nil || u == nil || u.User != nil || u.Fragment != "" ||
		u.RawQuery != "" || (u.Path != "" && u.Path != "/") || u.Host == "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	return c.AllowTestLoopback && u.Scheme == "http" && u.Hostname() == "127.0.0.1"
}
func (c *FederationLocalContainment) call(ctx context.Context, bearer, method, endpoint string) ([]byte, int, error) {
	// The server must not be allowed to redirect a privileged admin token.
	client := *c.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 || client.Timeout > 10*time.Second {
		client.Timeout = 10 * time.Second
	}
	req, err := http.NewRequestWithContext(ctx, method,
		strings.TrimRight(c.AdminOrigin, "/")+endpoint, nil)
	if err != nil {
		return nil, 0, errFederatedContainment
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	res, err := client.Do(req)
	if err != nil {
		return nil, 0, errFederatedContainment
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNoContent {
		return nil, res.StatusCode, errFederatedContainment
	}
	if res.StatusCode == http.StatusNoContent {
		return nil, res.StatusCode, nil
	}
	media, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return nil, 0, errFederatedContainment
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 65537))
	if err != nil || len(body) > 65536 {
		return nil, 0, errFederatedContainment
	}
	return body, res.StatusCode, nil
}
func (c *FederationLocalContainment) sessions(ctx context.Context, bearer, user string) (map[string]bool, error) {
	raw, status, err := c.call(ctx, bearer, http.MethodGet,
		"/admin/realms/"+url.PathEscape(c.BrokerRealm)+"/users/"+url.PathEscape(user)+"/sessions")
	if err != nil || status != http.StatusOK {
		return nil, errFederatedContainment
	}
	var data []struct {
		ID     string `json:"id"`
		UserID string `json:"userId"`
	}
	if json.Unmarshal(raw, &data) != nil || len(data) > 100 {
		return nil, errFederatedContainment
	}
	seen := make(map[string]bool, len(data))
	for _, session := range data {
		if !brokerUserID.MatchString(session.ID) || (session.UserID != "" && session.UserID != user) || seen[session.ID] {
			return nil, errFederatedContainment
		}
		seen[session.ID] = true
	}
	return seen, nil
}

// RevokeBrokerSessions validates the actual live broker-local federated
// identity link before making any state change, then observes real active
// sessions, requests current Keycloak user logout, and rereads the sessions.
// No upstream IdP or CP logout is claimed.
func (c *FederationLocalContainment) RevokeBrokerSessions(
	ctx context.Context, target FederationContainmentTarget,
) error {
	if ctx == nil || ctx.Err() != nil || !c.trusted() ||
		!brokerUserID.MatchString(target.TrustID) ||
		!brokerUserID.MatchString(target.BrokerUserID) ||
		!realmName.MatchString(target.FederationAlias) ||
		target.FederationAlias == "master" ||
		!referenceName.MatchString(target.ChangeReference) ||
		len(target.UpstreamSubject) < 3 || len(target.UpstreamSubject) > 512 {
		return errFederatedContainment
	}
	issuer, err := url.Parse(target.UpstreamIssuer)
	if err != nil || issuer == nil || issuer.Scheme != "https" ||
		issuer.Hostname() == "" || issuer.User != nil || issuer.Fragment != "" ||
		issuer.RawQuery != "" {
		return errFederatedContainment
	}
	evidence, err := c.Reviewer.CurrentFederatedContainment(ctx, target)
	now := c.Now().UTC()
	if err != nil || !evidence.Approved || !evidence.DistinctReviewer ||
		!evidence.CurrentTrust || !evidence.ExactBoundIdentity ||
		!referenceName.MatchString(evidence.OriginalReference) ||
		evidence.ObservedAt.IsZero() || evidence.ObservedAt.After(now) ||
		now.Sub(evidence.ObservedAt) > time.Minute {
		return errFederatedContainment
	}
	token, err := c.Tokens.CurrentAdminBearer(ctx)
	if err != nil || len(token) < 20 || len(token) > 8192 ||
		strings.ContainsAny(token, " \r\n\t") {
		return errFederatedContainment
	}
	prefix := "/admin/realms/" + url.PathEscape(c.BrokerRealm) + "/users/" +
		url.PathEscape(target.BrokerUserID)
	original, status, err := c.call(ctx, token, http.MethodGet, prefix+"/federated-identity")
	if err != nil || status != http.StatusOK {
		return errFederatedContainment
	}
	var federated []struct {
		IdentityProvider string `json:"identityProvider"`
		UserID           string `json:"userId"`
	}
	if json.Unmarshal(original, &federated) != nil || len(federated) > 20 {
		return errFederatedContainment
	}
	matched := 0
	for _, link := range federated {
		if link.IdentityProvider == target.FederationAlias &&
			len(link.UserID) == len(target.UpstreamSubject) &&
			subtle.ConstantTimeCompare([]byte(link.UserID), []byte(target.UpstreamSubject)) == 1 {
			matched++
		}
	}
	if matched != 1 {
		return fmt.Errorf("federation_link_unverified: %w", errFederatedContainment)
	}
	before, err := c.sessions(ctx, token, target.BrokerUserID)
	if err != nil {
		return fmt.Errorf("original_broker_session_read_invalid: %w", errFederatedContainment)
	}
	if len(before) == 0 {
		return fmt.Errorf("original_broker_session_absent: %w", errFederatedContainment)
	}
	_, status, err = c.call(ctx, token, http.MethodPost, prefix+"/logout")
	if err != nil || status != http.StatusNoContent {
		return fmt.Errorf("provider_broker_logout_unverified: %w", errFederatedContainment)
	}
	after, err := c.sessions(ctx, token, target.BrokerUserID)
	if err != nil || len(after) != 0 {
		return fmt.Errorf("provider_broker_session_survived: %w", errFederatedContainment)
	}
	return nil
}
