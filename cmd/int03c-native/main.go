// Command int03c-native is an isolated IAM-owned admin bridge for the two
// Accepted Shared #354 development-only INT-03C proof workloads. It never grants
// canonical authority, issues bearer tokens, or marks NAB-03 accepted.
//
// Normal product provisioning explicitly rejects these names. Only this
// disposable bridge can reach the maintained Ory provider port, and only
// after re-reading IAM's exact committed Shared registry pin on "create".
// On recovery the registry may already be HELD: an existing run may still
// destroy *its own* marked clients without pretending to activate new ones.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

const (
	consumer  = "baobab-int03c-issuer-owner"
	validator = "baobab-int03c-issuer-verifier"
	markerKey = "int03c_run_id"
)

var runPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var names = map[string]struct{}{consumer: {}, validator: {}}

type nativePlan struct {
	Schema            string                              `json:"schema"`
	State             string                              `json:"state"`
	IdentitiesCreated bool                                `json:"identities_created"`
	Qualified         bool                                `json:"qualified"`
	Specs             []provider.WorkloadProvisioningSpec `json:"provisioning_specs"`
}

type client struct {
	ID        string            `json:"client_id"`
	Grants    []string          `json:"grant_types"`
	Responses []string          `json:"response_types"`
	Scopes    string            `json:"scope"`
	Audiences []string          `json:"audience"`
	Method    string            `json:"token_endpoint_auth_method"`
	Metadata  map[string]string `json:"metadata"`
	Lifetime  string            `json:"client_credentials_grant_access_token_lifespan"`
	Redirects []string          `json:"redirect_uris"`
	Logout    []string          `json:"post_logout_redirect_uris"`
	CORS      []string          `json:"allowed_cors_origins"`
	JWKSURI   string            `json:"jwks_uri"`
	JWKS      json.RawMessage   `json:"jwks"`
}
type native struct {
	adapter *ory.Adapter
	client  *http.Client
	admin   string
	runID   string
}

func exactSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	a = append([]string(nil), a...)
	b = append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func requiredSpec(s provider.WorkloadProvisioningSpec) bool {
	if s.LogicalClientID != consumer && s.LogicalClientID != validator {
		return false
	}
	return s.AuthMethod == provider.WorkloadAuthClientSecret &&
		s.LifecycleStatus == provider.WorkloadStatusProvisioned &&
		s.RequireNew && s.AccessTokenTTLSeconds == 60 &&
		len(s.Metadata) == 2 &&
		s.Metadata["environment"] == "development" &&
		s.Metadata["owner"] == "baobab-platform/infrastructure" &&
		exactSet(s.AllowedScopes, []string{"context:resolve"}) &&
		exactSet(s.Audiences, []string{"baobab-control-plane"})
}

// loadCanonicalPlan delegates governance to IAM's existing fixture preparer,
// which requires a clean committed IAM lock and the pinned immutable Shared
// registry blob. A supplied JSON plan alone cannot authorise provisioning.
func loadCanonicalPlan(ctx context.Context, checkout string) (nativePlan, error) {
	var p nativePlan
	dir, err := os.MkdirTemp("", "int03-native-plan-")
	if err != nil {
		return p, errors.New("private native plan directory unavailable")
	}
	defer os.RemoveAll(dir)
	// Preparer requires an absent leaf; the parent directory is temporary.
	output := filepath.Join(dir, "plan")
	cmd := exec.CommandContext(ctx, "python3", "scripts/int03c_native_fixture.py", "native-plan", "--shared-checkout", checkout, "--output", output)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return p, errors.New("canonical pinned registry does not authorise the two fixtures")
	}
	raw, err := os.ReadFile(filepath.Join(output, "native-plan.json"))
	if err != nil || len(raw) > 65536 {
		return p, errors.New("native plan unavailable or unbounded")
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, errors.New("native plan invalid")
	}
	if p.Schema != "iam.int03c.native-plan.v1" || p.State != "PREPARED_NOT_PROVISIONED" || p.IdentitiesCreated || p.Qualified || len(p.Specs) != 2 {
		return p, errors.New("native plan boundary differs")
	}
	seen := map[string]bool{}
	for _, s := range p.Specs {
		if !requiredSpec(s) || seen[s.LogicalClientID] {
			return p, errors.New("native plan authority differs")
		}
		seen[s.LogicalClientID] = true
	}
	if !seen[consumer] || !seen[validator] {
		return p, errors.New("native plan incomplete")
	}
	return p, nil
}
func (n *native) request(ctx context.Context, method, name string) (*client, int, error) {
	if _, ok := names[name]; !ok {
		return nil, 0, errors.New("unapproved client")
	}
	endpoint := n.admin + "/admin/clients/" + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return nil, 0, errors.New("admin request invalid")
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return nil, 0, errors.New("private issuer administration unreachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, 404, nil
	}
	if method == http.MethodDelete {
		if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
			return nil, resp.StatusCode, errors.New("issuer deletion rejected")
		}
		return nil, resp.StatusCode, nil
	}
	if resp.StatusCode != 200 {
		return nil, resp.StatusCode, errors.New("issuer administrative read-back rejected")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16385))
	if err != nil || len(raw) > 16384 {
		return nil, resp.StatusCode, errors.New("issuer read-back unbounded")
	}
	// Unknown security-affecting fields are checked on creation by IAM's
	// provider adapter. Recovery reads only the marker before destructive ops.
	var c client
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, resp.StatusCode, errors.New("issuer read-back malformed")
	}
	return &c, 200, nil
}
func (n *native) owned(ctx context.Context, name string) (*client, error) {
	c, status, err := n.request(ctx, http.MethodGet, name)
	if err != nil {
		return nil, err
	}
	if status == 404 {
		return nil, nil
	}
	if c.ID != name || c.Metadata[markerKey] != n.runID {
		return nil, errors.New("issuer client not owned by this disposable run")
	}
	return c, nil
}
func checkCreation(c *client, s provider.WorkloadProvisioningSpec) error {
	if c == nil || c.ID != s.LogicalClientID ||
		!exactSet(c.Grants, []string{"client_credentials"}) || len(c.Responses) > 0 ||
		!exactSet(strings.Fields(c.Scopes), s.AllowedScopes) || !exactSet(c.Audiences, s.Audiences) ||
		c.Method != "client_secret_post" || c.Lifetime != "1m0s" &&
		c.Lifetime != "60s" || len(c.Redirects) > 0 || len(c.Logout) > 0 || len(c.CORS) > 0 ||
		c.JWKSURI != "" || (len(c.JWKS) > 0 && string(bytes.TrimSpace(c.JWKS)) != "null") ||
		len(c.Metadata) != len(s.Metadata) {
		return errors.New("independent issuer security read-back differs")
	}
	for k, v := range s.Metadata {
		if c.Metadata[k] != v {
			return errors.New("issuer owner/authority read-back differs")
		}
	}
	return nil
}

// create is fail-closed when a client exists, even if the marker belongs to
// this run. An accepted POST followed by network failure is recovered by the
// independent destroy action, NEVER by blindly retrying creation.
func (n *native) create(ctx context.Context, s provider.WorkloadProvisioningSpec, secretsDir string) error {
	existing, status, err := n.request(ctx, http.MethodGet, s.LogicalClientID)
	if err != nil {
		return err
	}
	if status != 404 || existing != nil {
		return errors.New("fresh-only client already exists")
	}
	s.Metadata[markerKey] = n.runID
	if err := s.Validate(); err != nil {
		return errors.New("native workload spec refused")
	}
	created, err := n.adapter.ProvisionWorkload(ctx, s)
	if err != nil {
		return errors.New("native provision or adapter read-back failed; recover owner journal")
	}
	// Force an independent second GET beyond IAM adapter's own post-create GET.
	observed, err := n.owned(ctx, s.LogicalClientID)
	if err != nil {
		return err
	}
	if err := checkCreation(observed, s); err != nil {
		return err
	}
	if created == nil || created.LogicalClientID != s.LogicalClientID || len(created.ClientSecret) < 32 {
		return errors.New("provisioned issuer credential unavailable")
	}
	return privateSecret(secretsDir, s.LogicalClientID, created.ClientSecret)
}
func privateSecret(dir, name, secret string) error {
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return errors.New("private secret directory required")
	}
	dest := filepath.Join(dir, name+".secret")
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("exclusive secret handoff refused")
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(dest)
		}
	}()
	if _, err := f.WriteString(secret + "\n"); err != nil {
		return errors.New("private credential write failed")
	}
	if err := f.Sync(); err != nil {
		return errors.New("private credential fsync failed")
	}
	if err := f.Close(); err != nil {
		return errors.New("private credential close failed")
	}
	ok = true
	return nil
}
func (n *native) revoke(ctx context.Context, name string) error {
	c, err := n.owned(ctx, name)
	if err != nil {
		return err
	}
	if c == nil {
		return nil
	} // absent is already deprovisioned
	if err := n.adapter.RevokeWorkload(ctx, provider.ProviderWorkloadReference{LogicalClientID: name}); err != nil {
		return errors.New("provider issuance revoke failed")
	}
	observed, err := n.owned(ctx, name)
	if err != nil {
		return err
	}
	if observed == nil || len(observed.Grants) != 0 {
		return errors.New("issuer continued granting workload after revoke")
	}
	return nil
}
func (n *native) destroy(ctx context.Context, name string) error {
	// Crash recovery must not depend on the creation-time registry still being
	// OPEN, but MUST prove the exact per-run marker before any mutation.
	c, err := n.owned(ctx, name)
	if err != nil {
		return err
	}
	if c == nil {
		return nil
	}
	if err := n.revoke(ctx, name); err != nil {
		return err
	}
	// Re-read after revocation to catch ownership changes between operations.
	c, err = n.owned(ctx, name)
	if err != nil {
		return err
	}
	if c == nil {
		return nil
	}
	_, _, err = n.request(ctx, http.MethodDelete, name)
	if err != nil {
		return err
	}
	c, status, err := n.request(ctx, http.MethodGet, name)
	if err != nil || status != 404 || c != nil {
		return errors.New("issuer trust destruction not independently observed")
	}
	return nil
}
func validateOrigins(admin, kratos, issuer string) error {
	u, err := url.Parse(admin)
	if err != nil || u.Scheme != "https" || u.Hostname() != "hydra.int03.test" || u.Port() != "" && u.Port() != "4445" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return errors.New("issuer admin origin not the disposable TLS private endpoint")
	}
	for _, v := range []string{kratos, issuer} {
		if v == "" {
			return errors.New("native identity runtime missing")
		}
	}
	// Never let disposable client metadata claim a protected or arbitrary issuer.
	// Kratos is required by the Ory adapter but is only a private companion here.
	origin, err := url.Parse(issuer)
	if err != nil || origin.Scheme != "https" || origin.Hostname() != "hydra.int03.test" ||
		origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" ||
		origin.Path != "" && origin.Path != "/" {
		return errors.New("disposable issuer origin refused")
	}
	identity, err := url.Parse(kratos)
	if err != nil || identity.User != nil || identity.RawQuery != "" || identity.Fragment != "" ||
		identity.Path != "" && identity.Path != "/" ||
		!((identity.Scheme == "http" && identity.Hostname() == "kratos") ||
			(identity.Scheme == "https" && identity.Hostname() == "kratos.int03.test")) {
		return errors.New("disposable Kratos companion origin refused")
	}
	return nil
}
func makeNative(admin, kratos, issuer, ca, runID string) (*native, error) {
	if !runPattern.MatchString(runID) {
		return nil, errors.New("run ID is not a private 128-bit nonce")
	}
	if err := validateOrigins(admin, kratos, issuer); err != nil {
		return nil, err
	}
	root, err := os.ReadFile(ca)
	if err != nil || len(root) > 65536 {
		return nil, errors.New("disposable issuer CA unavailable")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(root) {
		return nil, errors.New("disposable issuer CA invalid")
	}
	clientHTTP := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	adapter, err := ory.NewAdapter(ory.Config{KratosAdminURL: kratos, HydraAdminURL: strings.TrimSuffix(admin, "/"), PublicIssuer: issuer, HTTPClient: clientHTTP, RequestTimeout: 15 * time.Second})
	if err != nil {
		return nil, errors.New("native IAM adapter refused")
	}
	return &native{adapter: adapter, client: clientHTTP, admin: strings.TrimSuffix(admin, "/"), runID: runID}, nil
}
func main() {
	action := flag.String("action", "", "create|revoke|destroy|supervise")
	name := flag.String("name", "", "one exact INT-03C proof identity")
	runID := flag.String("run-id", "", "disposable 128-bit run marker")
	admin := flag.String("hydra-admin", "", "private TLS Hydra admin URL")
	kratos := flag.String("kratos-admin", "", "private Kratos admin URL")
	issuer := flag.String("issuer", "", "disposable Hydra issuer")
	ca := flag.String("ca", "", "private run CA bundle")
	checkout := flag.String("shared-checkout", "", "clean committed Shared checkout")
	secretDir := flag.String("secrets-dir", "", "existing private 0700 directory")
	deadline := flag.String("deadline", "", "immutable RFC3339 run deadline")
	leaseFile := flag.String("lease-file", "", "independent watchdog heartbeat in owner-private run directory")
	flag.Parse()
	fail := func() { fmt.Fprintln(os.Stderr, "INT03C_NATIVE_OPERATION_REFUSED"); os.Exit(1) }
	if os.Getenv("BAOBAB_INT03C_NATIVE_DISPOSABLE") != "1" {
		fail()
	}
	if _, ok := names[*name]; !ok {
		fail()
	}
	if *action != "create" && *action != "revoke" && *action != "destroy" && *action != "supervise" {
		fail()
	}
	n, err := makeNative(*admin, *kratos, *issuer, *ca, *runID)
	if err != nil {
		fail()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	switch *action {
    case "supervise":
        if *name != consumer || *deadline == "" || *leaseFile == "" {
            fail()
        }
        if err := superviseDeadline(context.Background(), n, *leaseFile, *deadline); err != nil {
            fail()
        }
        fmt.Println("INT03C_DEADLINE_SUPERVISED_DESTROY_READBACK_VERIFIED")
	case "create":
        // Issuance may only start while the independent watchdog is
        // demonstrably alive and bound to this exact run and deadline.
        // The daemon is launched by a separately supervised disposable
        // runtime, not by the issuer-creating process itself.
        if err := verifyLiveLease(*leaseFile, *runID, *deadline, time.Now().UTC()); err != nil {
            fail()
        }
		until, err := time.Parse(time.RFC3339, *deadline)
		if err != nil || time.Until(until) <= 60*time.Second || time.Until(until) > 90*time.Minute {
			fail()
		}
		plan, err := loadCanonicalPlan(ctx, *checkout)
		if err != nil {
			fail()
		}
		for _, s := range plan.Specs {
			if s.LogicalClientID == *name {
				if err := n.create(ctx, s, *secretDir); err != nil {
					fail()
				}
				fmt.Println("INT03C_NATIVE_CREATED_READBACK_VERIFIED")
				return
			}
		}
		fail()
	case "revoke":
		if err := n.revoke(ctx, *name); err != nil {
			fail()
		}
		fmt.Println("INT03C_NATIVE_REVOKED_READBACK_VERIFIED")
	case "destroy":
		if err := n.destroy(ctx, *name); err != nil {
			fail()
		}
		fmt.Println("INT03C_NATIVE_DESTROYED_READBACK_VERIFIED")
	}
}
