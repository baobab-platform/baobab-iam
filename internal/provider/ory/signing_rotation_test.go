package ory_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

type n06ReviewedJWKS struct {
	retirement bool
	observations []string
}
func (a *n06ReviewedJWKS) ApproveSigningKeyOperation(_ context.Context, _ ory.HydraSigningRotationPlan, action string) error {
	a.observations = append(a.observations, action)
	if action == "ADD" || action == "RETIRE_AFTER_OLD_TOKEN_EXPIRY" && a.retirement {
		return nil
	}
	return errors.New("independent old-token expiry/consumer witness missing")
}

func TestN06HydraJWKSMutationRequiresRealIssuerReadbackAndIndependentRetirement(t *testing.T) {
	t.Setenv("ORY_FOUNDATION", "1")
	const set = "baobab-development-n06"
	const oldKid = "old-n06-key-100"
	const newKid = "new-n06-key-200"
	var keys []map[string]string
	keys = append(keys, map[string]string{"kid":oldKid,"alg":"RS256","use":"sig"})
	adds, deletes := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/keys/"+set && r.URL.Path != "/admin/keys/"+set+"/"+oldKid {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"keys":keys})
		case http.MethodPost:
			adds++
			var spec map[string]string
			_ = json.NewDecoder(r.Body).Decode(&spec)
			if spec["alg"]!="RS256"||spec["use"]!="sig"||spec["kid"]!=newKid {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			keys=append(keys,map[string]string{"kid":newKid,"alg":"RS256","use":"sig"})
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"keys":keys})
		case http.MethodDelete:
			deletes++
			var left []map[string]string
			for _, item := range keys {
				if item["kid"] != oldKid { left = append(left, item) }
			}
			keys=left
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w,r)
		}
	}))
	defer server.Close()
	adapter, err := ory.NewAdapter(ory.Config{
		KratosAdminURL:server.URL,HydraAdminURL:server.URL,
		PublicIssuer:server.URL,HTTPClient:server.Client(),
	})
	if err != nil { t.Fatal(err) }
	plan:=ory.HydraSigningRotationPlan{
		SetID:set,OldKID:oldKid,NewKID:newKid,
		ReviewedChangeReference:"ref_authorizedrotation",
	}
	witness:=&n06ReviewedJWKS{}
	out,err:=adapter.AddHydraSigningKey(context.Background(),plan,witness)
	if err!=nil || !out.OldStillPublished || !out.NewPublished || out.IssuerJWKSObserved ||
		adds!=1 || len(keys)!=2 {
		t.Fatalf("Hydra native add/overlap not independently observed: %v",err)
	}
	if adapter.RetireHydraSigningKey(context.Background(),plan,witness)==nil || deletes!=0 {
		t.Fatal("old key retired without independent expiry/consumer witness")
	}
	witness.retirement=true
	if err:=adapter.RetireHydraSigningKey(context.Background(),plan,witness);err!=nil ||
		deletes!=1 || len(keys)!=1 || keys[0]["kid"]!=newKid {
		t.Fatalf("old key retirement or subsequent provider readback missing: %v",err)
	}
	if len(witness.observations)!=3 ||
		witness.observations[0]!="ADD" ||
		witness.observations[1]!="RETIRE_AFTER_OLD_TOKEN_EXPIRY" ||
		witness.observations[2]!="RETIRE_AFTER_OLD_TOKEN_EXPIRY" {
		t.Fatal("rotation reviewer invocation sequence drift")
	}
}

func TestN06HydraSigningRotationRefusesUnreviewedMutations(t *testing.T) {
	t.Setenv("ORY_FOUNDATION", "1")
	adapter,err:=ory.NewAdapter(ory.Config{
		KratosAdminURL:"http://127.0.0.1:54321",
		HydraAdminURL:"http://127.0.0.1:54321",
		PublicIssuer:"http://127.0.0.1:54321",
	})
	if err!=nil {t.Fatal(err)}
	valid:=ory.HydraSigningRotationPlan{
		SetID:"baobab-development-n06",OldKID:"old-key-100",
		NewKID:"new-key-200",ReviewedChangeReference:"ref_authorizedrotation",
	}
	for name,change:=range map[string]func(*ory.HydraSigningRotationPlan){
		"unreviewed-set":func(p *ory.HydraSigningRotationPlan){p.SetID="hydra.default-private-key"},
		"same-kid":func(p *ory.HydraSigningRotationPlan){p.NewKID=p.OldKID},
		"invalid-kid":func(p *ory.HydraSigningRotationPlan){p.NewKID="../escape"},
		"missing-change":func(p *ory.HydraSigningRotationPlan){p.ReviewedChangeReference=""},
		"production-unrecognized":func(p *ory.HydraSigningRotationPlan){p.SetID="production-signing-key"},
	} {
		t.Run(name,func(t *testing.T){
			p:=valid
			change(&p)
			if _,err:=adapter.AddHydraSigningKey(context.Background(),p,&n06ReviewedJWKS{});err==nil {
				t.Fatal("unreviewed native key mutation accepted")
			}
			if err:=adapter.RetireHydraSigningKey(context.Background(),p,&n06ReviewedJWKS{});err==nil {
				t.Fatal("unreviewed key retirement accepted")
			}
		})
	}
	if _,err:=adapter.AddHydraSigningKey(context.Background(),valid,nil);err==nil {
		t.Fatal("missing independent reviewer accepted")
	}
	// Neither source API nor the reviewed plan may construct remote plain HTTP
	// signing endpoints even if the caller sets the test-environment flag.
	production,err:=ory.NewAdapter(ory.Config{
		KratosAdminURL:"http://remote.invalid:4434",
		HydraAdminURL:"http://remote.invalid:4445",
		PublicIssuer:"http://remote.invalid:4444",
	})
	if err!=nil {t.Fatal(err)}
	if _,err:=production.AddHydraSigningKey(context.Background(),valid,&n06ReviewedJWKS{});err==nil {
		t.Fatal("remote insecure provider accepted")
	}
}
