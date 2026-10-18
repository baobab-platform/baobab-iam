// Command c4-03-qualify exercises the existing production IAM-to-CP runtime
// composition with real, separately authorized read-only credentials. It does
// not create or activate identities, grants, clients, tenants or workloads.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/federation"
	"github.com/baobab-platform/baobab-iam/internal/provider"
)

const evidenceSchema = "baobab-c4-03-live-authority/v1"

var shaPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)

var requiredChecks = []string{
	"cp_context_acquired", "current_capability_resolved", "current_capability_reresolved",
	"wrong_capability_denied", "invalid_caller_credential_denied",
	"unavailable_cp_denied", "expired_evidence_denied", "cancelled_supervisor_denied",
}

// Evidence is a closed, token-free account of only this first C4-03 authority
// gate. A PASS is NOT a claim of real Hydra issuance or protected CP consumption.
type Evidence struct {
	Schema            string          `json:"schema"`
	SourceCommit      string          `json:"source_commit"`
	Result            string          `json:"result"`
	Checks            map[string]bool `json:"checks"`
	ActualCP          bool            `json:"actual_cp_queried"`
	HydraIssuance     bool            `json:"hydra_issuance_proven"`
	ProtectedResource bool            `json:"protected_resource_proven"`
	Revocation        bool            `json:"real_revocation_proven"`
	ProductionReady   bool            `json:"production_ready"`
}

func newEvidence(sha string) (Evidence, error) {
	if !shaPattern.MatchString(sha) {
		return Evidence{}, errors.New("invalid source commit")
	}
	r := Evidence{Schema: evidenceSchema, SourceCommit: sha, Result: "FAIL", Checks: make(map[string]bool, len(requiredChecks))}
	for _, k := range requiredChecks {
		r.Checks[k] = false
	}
	return r, nil
}
func (r *Evidence) close() {
	r.Result = "FAIL"
	// Claims beyond this read-only gate are not accepted in v1.
	r.HydraIssuance = false
	r.ProtectedResource = false
	r.Revocation = false
	r.ProductionReady = false
	if len(r.Checks) != len(requiredChecks) || !r.ActualCP {
		return
	}
	for _, k := range requiredChecks {
		if !r.Checks[k] {
			return
		}
	}
	r.Result = "PASS"
}

type invalidToken struct{}

func (invalidToken) Token(context.Context) (string, error) {
	return "c4-03-invalid-synthetic-credential", nil
}

// qualify uses the exact C4-02 production factory and its supervised context,
// not a cloned resolver or mock CP. Every negative intentionally fails closed.
func qualify(parent context.Context, c federation.RuntimeComposition, tlsConfig *tls.Config, sha string) Evidence {
	r, err := newEvidence(sha)
	if err != nil {
		return Evidence{Schema: evidenceSchema, Result: "FAIL"}
	}
	ctx, cancel := context.WithCancel(parent)
	dispatch, supervisor, err := federation.StartRuntimeComposition(ctx, c, provider.CapabilityWorkloadTokenIssue, tlsConfig)
	if err != nil {
		cancel()
		return r
	}
	r.Checks["cp_context_acquired"] = true
	check := func() bool {
		call, stop := context.WithTimeout(ctx, 8*time.Second)
		defer stop()
		return dispatch.CheckCapability(call, provider.CapabilityWorkloadTokenIssue) == nil
	}
	r.Checks["current_capability_resolved"] = check()
	if !r.Checks["current_capability_resolved"] {
		cancel()
		<-supervisor.Done()
		return r
	}
	r.Checks["current_capability_reresolved"] = check()
	if !r.Checks["current_capability_reresolved"] {
		cancel()
		<-supervisor.Done()
		return r
	}
	r.ActualCP = true
	// The factory must refuse use of its workload gate to authorize a human.
	call, stop := context.WithTimeout(ctx, 8*time.Second)
	r.Checks["wrong_capability_denied"] = dispatch.CheckCapability(call, provider.CapabilityHumanAuthentication) != nil
	stop()
	// The synthetic invalid bearer is never substituted for, or written into,
	// the actual IAM deployment credential file.
	bad, err := federation.NewHTTPAuthority(c.CPOrigin, invalidToken{}, tlsConfig)
	if err == nil {
		call, stop = context.WithTimeout(ctx, 8*time.Second)
		_, err = bad.AcquireRuntimeContext(call, c.ContextTarget, time.Now)
		r.Checks["invalid_caller_credential_denied"] = err != nil
		stop()
	}
	// Transport-outage simulation uses an unreachable loopback TLS endpoint;
	// it never interrupts the real CP or claims to have tested CP failover.
	down, err := federation.NewHTTPAuthority("https://127.0.0.1:1", invalidToken{}, tlsConfig)
	if err == nil {
		call, stop = context.WithTimeout(ctx, 5*time.Second)
		_, err = down.AcquireRuntimeContext(call, c.ContextTarget, time.Now)
		r.Checks["unavailable_cp_denied"] = err != nil
		stop()
	}
	// A future observation clock must refuse today's current CP evidence.
	// This is an expiry negative, not a CP clock or artifact mutation.
	scope := federation.Scope{OrganisationID: c.ContextTarget.OrganisationID, EstateID: c.EstateID}
	target := federation.RuntimeAuthorityTarget{
		ProviderID: c.ProviderID, EngineInstanceID: c.EngineInstanceID, Scope: scope,
		RuntimeCapability:      "WORKLOAD_TOKEN_ISSUANCE",
		ConfigurationReference: c.ConfigurationReference, SecurityDomainReference: c.SecurityDomainReference,
	}
	old, err := federation.NewHTTPRuntimeAuthority(c.CPOrigin,
		federation.FileAuthorityTokens{Path: c.RuntimeTokenFile}, tlsConfig, target,
		func() time.Time { return time.Now().Add(5 * 365 * 24 * time.Hour) })
	if err == nil {
		call, stop = context.WithTimeout(ctx, 8*time.Second)
		_, err = old.RuntimeBinding(call, c.ProviderID, c.EngineInstanceID, scope, target.RuntimeCapability)
		r.Checks["expired_evidence_denied"] = err != nil
		stop()
	}
	cancel()
	<-supervisor.Done()
	// A returned context after worker shutdown must never authorize reuse.
	after, finish := context.WithTimeout(context.Background(), 2*time.Second)
	r.Checks["cancelled_supervisor_denied"] = dispatch.CheckCapability(after, provider.CapabilityWorkloadTokenIssue) != nil
	finish()
	r.close()
	return r
}

// Publish JSON and SHA-256 together through one fsynced directory rename. No
// exception, context handle, token, CP response or identity enters the files.
func publish(directory string, r Evidence) error {
	if directory == "" || r.Schema != evidenceSchema || !shaPattern.MatchString(r.SourceCommit) {
		return errors.New("invalid evidence input")
	}
	r.close()
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	pending, err := os.MkdirTemp(directory, ".pending-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(pending)
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	write := func(name string, data []byte) error {
		f, err := os.OpenFile(filepath.Join(pending, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		if _, err = f.Write(data); err != nil {
			f.Close()
			return err
		}
		if err = f.Sync(); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	}
	if err = write("receipt.json", data); err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	if err = write("receipt.sha256", []byte(hex.EncodeToString(digest[:])+"  receipt.json\n")); err != nil {
		return err
	}
	d, err := os.Open(pending)
	if err != nil {
		return err
	}
	if err = d.Sync(); err != nil {
		d.Close()
		return err
	}
	if err = d.Close(); err != nil {
		return err
	}
	nonce := make([]byte, 12)
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	return os.Rename(pending, filepath.Join(directory, "run-"+hex.EncodeToString(nonce)))
}

func main() {
	configPath := flag.String("runtime-config", "", "protected reviewed CP runtime JSON")
	caPath := flag.String("cp-ca-file", "", "optional CP TLS root PEM")
	evidenceDir := flag.String("evidence-dir", "", "private sanitized receipt directory")
	source := flag.String("source-commit", "", "exact checkout SHA")
	fullFile := flag.String("full-config", "", "protected C4-03B–E registered live fixture configuration; optional")
	flag.Parse()
	if *configPath == "" || *evidenceDir == "" {
		fmt.Fprintln(os.Stderr, "FAIL C4-03 missing configuration or output")
		os.Exit(2)
	}
	var cfg federation.RuntimeComposition
	if federation.LoadServiceDocument(*configPath, &cfg) != nil {
		fmt.Fprintln(os.Stderr, "FAIL C4-03 unsafe composition")
		os.Exit(2)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if *caPath != "" {
		bytes, err := os.ReadFile(*caPath)
		roots := x509.NewCertPool()
		if err != nil || !roots.AppendCertsFromPEM(bytes) {
			fmt.Fprintln(os.Stderr, "FAIL C4-03 invalid CP CA")
			os.Exit(2)
		}
		tlsConfig.RootCAs = roots
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	r := qualify(ctx, cfg, tlsConfig, *source)
	if err := publish(*evidenceDir, r); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL C4-03 evidence publication")
		os.Exit(1)
	}
	fmt.Println(r.Result, "C4-03 read-only CP authority qualification; sanitized evidence retained")
	if r.Result != "PASS" {
		os.Exit(1)
	}
	if *fullFile != "" {
		// The full-run input MUST match the already accepted C4-03A workload
		// composition. A second config must not silently change CP authority.
		var live liveConfig
		if federation.LoadServiceDocument(*fullFile, &live) != nil || live.Workload != cfg {
			fmt.Fprintln(os.Stderr, "FAIL C4-03B–E protected fixture mismatch")
			os.Exit(2)
		}
		fullCtx, stop := context.WithTimeout(context.Background(), 5*time.Minute)
		defer stop()
		full := qualifyFull(fullCtx, live, *caPath, *source, *evidenceDir, os.Stdin, os.Stdout)
		if err := publishFull(filepath.Join(*evidenceDir, "full"), full); err != nil {
			fmt.Fprintln(os.Stderr, "FAIL C4-03B–E evidence publication")
			os.Exit(1)
		}
		fmt.Println(full.Result, "C4-03B–E registered-provider/CP qualification; sanitized evidence retained")
		if full.Result != "PASS" {os.Exit(1)}
	}
}
