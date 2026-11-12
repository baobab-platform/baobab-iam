// Command provision-people-dev uses the native Ory provider adapter to
// provision an explicitly accepted Shared DEVELOPMENT People reader.
// It DOES NOT infer employer/provider scope, activate statutory processing,
// or create a CP grant/choice. Source policy and two independently trusted
// reviewer signatures are prerequisites to any IAM-side mutation.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

const (
	clientID     = "baobab-erp-people-reader-dev"
	sharedCommit = "c0d3dd935e4b635fd38f113b280a220e552bc908"
	audience     = "baobab-control-plane"
	scopeContext = "context:resolve"
	scopeRead    = "people:provider:read"
)

type Plan struct {
	WorkloadID      string   `json:"workload_id"`
	SharedCommit    string   `json:"shared_commit"`
	Environment     string   `json:"environment"`
	Audiences       []string `json:"audiences"`
	Scopes          []string `json:"scopes"`
	CredentialType  string   `json:"credential_type"`
	TokenTTLSeconds int      `json:"token_ttl_seconds"`
}

func approvedPlan() Plan {
	return Plan{clientID, sharedCommit, "development", []string{audience},
		[]string{scopeContext, scopeRead}, "client_credentials", 120}
}
func planDigest(p Plan) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

type Signature struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}
type Approval struct {
	WorkloadID   string    `json:"workload_id"`
	SharedCommit string    `json:"shared_commit"`
	PlanDigest   string    `json:"plan_digest"`
	ExpiresAt    string    `json:"expires_at"`
	Maker        Signature `json:"maker"`
	Checker      Signature `json:"checker"`
}
type TrustedReviewer struct {
	Role      string `json:"role"`
	PublicKey string `json:"public_key"`
}
type Keyring struct {
	Reviewers map[string]TrustedReviewer `json:"reviewers"`
}

func signatureText(a Approval) string {
	return "BAOBAB-PEOPLE-DEV-v1\n" + a.WorkloadID + "\n" + a.SharedCommit + "\n" +
		a.PlanDigest + "\n" + a.ExpiresAt + "\n"
}
func verifyApproval(plan Plan, approval Approval, trust Keyring, now time.Time) error {
	digest, err := planDigest(plan)
	if err != nil {
		return err
	}
	deadline, err := time.Parse(time.RFC3339, approval.ExpiresAt)
	if err != nil || !deadline.After(now) || deadline.After(now.Add(24*time.Hour)) {
		return errors.New("People development approval expired or too long-lived")
	}
	if approval.WorkloadID != plan.WorkloadID || approval.SharedCommit != plan.SharedCommit ||
		approval.PlanDigest != digest || approval.Maker.KeyID == approval.Checker.KeyID ||
		approval.Maker.KeyID == "" || approval.Checker.KeyID == "" {
		return errors.New("People development approval does not bind the exact Shared plan and distinct reviewers")
	}
	for _, candidate := range []struct {
		signature Signature
		role      string
	}{
		{approval.Maker, "MAKER"}, {approval.Checker, "CHECKER"},
	} {
		reviewer, ok := trust.Reviewers[candidate.signature.KeyID]
		if !ok || reviewer.Role != candidate.role {
			return errors.New("People development approver not in independently trusted keyring")
		}
		key, err := base64.StdEncoding.DecodeString(reviewer.PublicKey)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return errors.New("People development trusted reviewer key invalid")
		}
		sig, err := base64.StdEncoding.DecodeString(candidate.signature.Signature)
		if err != nil || !ed25519.Verify(ed25519.PublicKey(key), []byte(signatureText(approval)), sig) {
			return errors.New("People development approval signature invalid")
		}
	}
	return nil
}
func loadJSON(path string, target any) error {
	if !filepath.IsAbs(path) || path == "" {
		return errors.New("an absolute private approval/keyring file path is required")
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return errors.New("approval and trust keys must be private files (0600)")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 32769))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("trailing private governance data")
	}
	return nil
}
func privateAdmin(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return errors.New("invalid private Hydra administrative endpoint")
	}
	// The developer port-forward/Compose private network must terminate on
	// loopback. A public management plane is never a provisioning option.
	h := u.Hostname()
	ip := net.ParseIP(h)
	if u.Scheme != "http" || (h != "localhost" && (ip == nil || !ip.IsLoopback())) {
		return errors.New("Hydra admin must be loopback-only HTTP through a private port forward")
	}
	return nil
}
func run(getenv func(string) string, out io.Writer, now time.Time) error {
	if getenv("BAOBAB_ENVIRONMENT") != "development" {
		return errors.New("People dev issuer is forbidden outside development")
	}
	plan := approvedPlan()
	digest, _ := planDigest(plan)
	action := getenv("PEOPLE_DEV_ACTION")
	switch action {
	case "plan":
		return json.NewEncoder(out).Encode(map[string]any{"plan": plan, "plan_digest": digest,
			"requires_independent_signatures": true, "credential_issued": false})
	case "apply", "revoke":
	default:
		return errors.New("PEOPLE_DEV_ACTION must be plan, apply or revoke")
	}
	var a Approval
	var keys Keyring
	if err := loadJSON(getenv("PEOPLE_DEV_APPROVAL_FILE"), &a); err != nil {
		return fmt.Errorf("load approval: %w", err)
	}
	if err := loadJSON(getenv("PEOPLE_DEV_TRUSTED_KEYS_FILE"), &keys); err != nil {
		return fmt.Errorf("load trust: %w", err)
	}
	if err := verifyApproval(plan, a, keys, now); err != nil {
		return err
	}
	if err := privateAdmin(getenv("ORY_HYDRA_ADMIN_URL")); err != nil {
		return err
	}
	issuer := getenv("ORY_PUBLIC_ISSUER")
	if issuer == "" || !strings.HasPrefix(issuer, "https://") {
		return errors.New("explicit HTTPS Ory issuer required")
	}
	adapter, err := ory.NewAdapter(ory.Config{KratosAdminURL: getenv("ORY_HYDRA_ADMIN_URL"),
		HydraAdminURL: getenv("ORY_HYDRA_ADMIN_URL"), PublicIssuer: issuer, RequestTimeout: 15 * time.Second})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if action == "revoke" {
		if err := adapter.DisableWorkload(ctx, provider.ProviderWorkloadReference{LogicalClientID: clientID}); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]string{
			"workload_id": clientID, "issuer_state": "DISABLED", "canonical_status": "UNCHANGED",
		})
	}
	path := getenv("PEOPLE_DEV_CREDENTIAL_FILE")
	if !filepath.IsAbs(path) || path == "" || strings.Contains(path, "/.git/") {
		return errors.New("absolute external secret-custody path required")
	}
	stat, err := os.Stat(filepath.Dir(path))
	if err != nil || stat.Mode().Perm()&0077 != 0 {
		return errors.New("credential custody directory must exist and deny group/other")
	}
	// Reserve before any remote mutation: never overwrite or leak a prior key.
	dest, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		dest.Close()
		if !keep {
			os.Remove(path)
		}
	}()
	identity, err := adapter.ProvisionWorkload(ctx, provider.WorkloadProvisioningSpec{
		LogicalClientID: clientID, DisplayName: "Baobab People development provider reader",
		AllowedScopes: []string{scopeContext, scopeRead}, Audiences: []string{audience},
		AccessTokenTTLSeconds: 120, RequireNew: true, AuthMethod: provider.WorkloadAuthClientSecret,
		LifecycleStatus: provider.WorkloadStatusProvisioned,
		Metadata: map[string]string{"registry_commit": sharedCommit, "plan_digest": digest,
			"approval_expires_at": a.ExpiresAt, "environment": "development"},
	})
	if err != nil {
		return err
	}
	if identity == nil || identity.ProviderClientID != clientID || len(identity.ClientSecret) < 24 {
		return errors.New("Ory client creation did not return a private credential; revoke before retry")
	}
	if _, err := dest.WriteString(identity.ClientSecret + "\n"); err != nil {
		return err
	}
	if err := dest.Sync(); err != nil {
		return err
	}
	keep = true
	return json.NewEncoder(out).Encode(map[string]string{
		"workload_id": clientID, "provider_client_id": identity.ProviderClientID,
		"issuer_state": "PROVISIONED", "canonical_status": "UNCHANGED",
		"secret_custody_file": path, "approved_shared_commit": sharedCommit,
	})
}
func main() {
	if err := run(os.Getenv, os.Stdout, time.Now().UTC()); err != nil {
		fmt.Fprintln(os.Stderr, "provision-people-dev: request refused")
		os.Exit(2)
	}
}
