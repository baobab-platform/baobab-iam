package ory_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/migration"
	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

type foundationTraits struct { email string }

func (f foundationTraits) LoadHumanTraits(context.Context, migration.ProviderBinding, string) (map[string]any, error) {
	return map[string]any{"email": f.email}, nil
}

// TestLiveFoundation proves provider mechanics using disposable synthetic fixtures.
// It never establishes CP mappings, workload activation or credential-import support.
func TestLiveFoundation(t *testing.T) {
	if os.Getenv("ORY_FOUNDATION") != "1" {
		t.Skip("set ORY_FOUNDATION=1 with the isolated Ory foundation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin := envOr("ORY_KRATOS_ADMIN_URL", "http://127.0.0.1:4434")
	public := envOr("ORY_KRATOS_PUBLIC_URL", "http://127.0.0.1:4433")
	issuer := envOr("ORY_PUBLIC_ISSUER", "http://127.0.0.1:4444")
	client := &http.Client{Timeout: 10*time.Second}
	adapter, err := ory.NewAdapter(ory.Config{KratosAdminURL: admin, HydraAdminURL: envOr("ORY_HYDRA_ADMIN_URL", "http://127.0.0.1:4445"), PublicIssuer: issuer, HTTPClient: client})
	if err != nil { t.Fatal(err) }
	ready, err := adapter.CheckReady(ctx)
	if err != nil || !ready.OK() { t.Fatalf("foundation not ready: %v", err) }
	seed := make([]byte, 24)
	if _, err := rand.Read(seed); err != nil { t.Fatal(err) }
	unique := hex.EncodeToString(seed)
	passwordSeed := make([]byte, 32)
	if _, err := rand.Read(passwordSeed); err != nil { t.Fatal(err) }
	password := "Aa!9-" + hex.EncodeToString(passwordSeed)
	cleanup := func(id string) {
		t.Cleanup(func() {
			cleanupCtx, done := context.WithTimeout(context.Background(), 10*time.Second)
			defer done()
			foundationRequest(t, cleanupCtx, client, http.MethodDelete, admin+"/admin/identities/"+id, nil, "", http.StatusNoContent, nil)
		})
	}
	t.Run("authorized-human-migration-and-lifecycle", func(t *testing.T) {
		svc := &migration.Service{Store: migration.NewMemoryStore()}
		bridge, err := migration.NewProvisionBridge(svc, issuer, adapter, adapter)
		if err != nil { t.Fatal(err) }
		bridge.HumanTraits = foundationTraits{email: "migration-"+unique+"@baobab.invalid"}
		record := &migration.Record{MigrationID: "foundation-"+unique, CanonicalIdentityID: "fixture-only-canonical",
			Source: migration.ProviderBinding{Provider: "fixture", Issuer: "https://fixture.invalid", Subject: unique},
			IdentityClass: migration.ClassTestOrNonProd, CredentialStrategy: migration.StrategyControlledReEnrolment, MigrationState: migration.StateDiscovered}
		if err := svc.Register(ctx, record); err != nil { t.Fatal(err) }
		result, err := bridge.Provision(ctx, record.MigrationID)
		if err != nil { t.Fatal(err) }
		cleanup(result.ProviderSubject)
		if result.Record.MigrationState != migration.StateProvisioned { t.Fatal("bridge did not reach PROVISIONED") }
		subject := provider.ExternalSubject{Issuer: issuer, Subject: result.ProviderSubject}
		identity, err := adapter.GetIdentity(ctx, subject)
		if err != nil || identity.Status != provider.IdentityStatusActive { t.Fatalf("read active identity failed: %v", err) }
		if err := adapter.DisableIdentity(ctx, subject); err != nil { t.Fatal(err) }
		identity, err = adapter.GetIdentity(ctx, subject)
		if err != nil || identity.Status != provider.IdentityStatusDisabled { t.Fatalf("disable not observed: %v", err) }
		if err := adapter.EnableIdentity(ctx, subject); err != nil { t.Fatal(err) }
		identity, err = adapter.GetIdentity(ctx, subject)
		if err != nil || identity.Status != provider.IdentityStatusActive { t.Fatalf("enable not observed: %v", err) }
	})
	t.Run("real-session-revocation", func(t *testing.T) {
		var flow struct { ID string `json:"id"` }
		foundationRequest(t, ctx, client, http.MethodGet, public+"/self-service/registration/api", nil, "", http.StatusOK, &flow)
		var registered struct {
			SessionToken string `json:"session_token"`
			Identity struct { ID string `json:"id"` } `json:"identity"`
		}
		foundationRequest(t, ctx, client, http.MethodPost, public+"/self-service/registration?flow="+flow.ID,
			map[string]any{"method":"password", "password":password, "traits":map[string]any{"email":"session-"+unique+"@baobab.invalid"}}, "", http.StatusOK, &registered)
		if registered.Identity.ID == "" || registered.SessionToken == "" { t.Fatal("registration did not issue identity and session") }
		cleanup(registered.Identity.ID)
		foundationRequest(t, ctx, client, http.MethodGet, public+"/sessions/whoami", nil, registered.SessionToken, http.StatusOK, nil)
		if err := adapter.RevokeSessions(ctx, provider.ExternalSubject{Issuer:issuer, Subject:registered.Identity.ID}); err != nil { t.Fatal(err) }
		foundationRequest(t, ctx, client, http.MethodGet, public+"/sessions/whoami", nil, registered.SessionToken, http.StatusUnauthorized, nil)
	})
}

func foundationRequest(t *testing.T, ctx context.Context, client *http.Client, method, url string, body any, token string, expected int, target any) {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil { t.Fatal("encode fixture request") }
	}
	request, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(payload))
	if err != nil { t.Fatal("construct fixture request") }
	request.Header.Set("Content-Type", "application/json")
	if token != "" { request.Header.Set("X-Session-Token", token) }
	response, err := client.Do(request)
	if err != nil { t.Fatal("fixture transport failure") }
	defer response.Body.Close()
	// Never log request/response bodies: they may contain passwords or session tokens.
	if response.StatusCode != expected {
		var diagnostic struct {
			UI struct { Messages []struct { ID int `json:"id"` } `json:"messages"`; Nodes []struct { Messages []struct { ID int `json:"id"` } `json:"messages"` } `json:"nodes"` } `json:"ui"`
		}
		_ = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&diagnostic)
		var ids []int
		for _, message := range diagnostic.UI.Messages { ids = append(ids, message.ID) }
		for _, node := range diagnostic.UI.Nodes { for _, message := range node.Messages { ids = append(ids, message.ID) } }
		t.Fatalf("fixture %s expected HTTP %d, received %d; Ory message IDs %v", method, expected, response.StatusCode, ids)
	}
	if target != nil {
		if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(target); err != nil { t.Fatal("decode fixture response") }
	}
}
