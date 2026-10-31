package migration_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/migration"
	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/jackc/pgx/v5/pgxpool"
)

func n05Database(t *testing.T) (*migration.PostgresStore, *pgxpool.Pool) {
	t.Helper()
	if os.Getenv("IAM_N05_DISPOSABLE_PG") != "1" {
		t.Skip("requires explicit disposable PostgreSQL 17 environment")
	}
	dsn := os.Getenv("IAM_N05_TEST_DATABASE_URL")
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil || cfg.ConnConfig.Database != "n05_ci" ||
		(cfg.ConnConfig.Host != "127.0.0.1" && cfg.ConnConfig.Host != "localhost") {
		t.Fatal("N05 tests refuse non-local or non-disposable database")
	}
	pool, err := pgxpool.NewWithConfig(context.Background(),cfg)
	if err != nil { t.Fatal(err) }
	t.Cleanup(pool.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, migration.N05Schema()); err != nil {
		t.Fatalf("reviewed N05 PostgreSQL schema: %v", err)
	}
	store, err := migration.NewPostgresStore(ctx,pool)
	if err != nil { t.Fatal(err) }
	return store, pool
}

func n05ID(t *testing.T) string {
	t.Helper()
	var bytes [12]byte
	if _, err := rand.Read(bytes[:]); err != nil { t.Fatal(err) }
	return "iam-n05-" + hex.EncodeToString(bytes[:])
}
func n05Human(t *testing.T, store *migration.PostgresStore, target bool) *migration.Record {
	t.Helper()
	id := n05ID(t)
	r := &migration.Record{
		MigrationID: id, MigrationBatchID: "development-identity",
		CanonicalIdentityID: "principal-" + id,
		Source: migration.ProviderBinding{
			Provider: "keycloak",
			Issuer: "https://legacy-issuer.invalid/realms/enterprise",
			Subject: "legacy-" + id,
		},
		IdentityClass: migration.ClassHuman,
		CredentialStrategy: migration.StrategyControlledReEnrolment,
		MigrationState: migration.StateDiscovered,
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
	ctx := context.Background()
	if err := store.Put(ctx,r); err != nil { t.Fatal(err) }
	if target {
		svc := &migration.Service{Store:store}
		for _, state := range []migration.MigrationState{
			migration.StateValidated,migration.StateReady,migration.StateProvisioning,
		} {
			if _, err := svc.ApplyTransition(ctx,id,state); err != nil { t.Fatal(err) }
		}
		updated,err := svc.SetTargetBinding(ctx,id,migration.ProviderBinding{
			Provider: "ory", Issuer: "https://native-issuer.invalid",
			Subject: "11111111-1111-4111-8111-" + strings.TrimPrefix(id, "iam-n05-")[12:24],
		})
		if err != nil { t.Fatal(err) }
		if updated.Target.Issuer == "" { t.Fatal("missing actual target") }
		if _,err:=svc.ApplyTransition(ctx,id,migration.StateProvisioned);err!=nil{t.Fatal(err)}
	}
	row,err := store.Get(ctx,id)
	if err != nil {t.Fatal(err)}
	return row
}

func TestN05PostgresLedgerSourceCanonicalAndHistory(t *testing.T) {
	store,pool:=n05Database(t)
	ctx:=context.Background()
	first:=n05Human(t,store,false)
	if first.Revision!=1 {t.Fatalf("first revision %d",first.Revision)}
	history,err:=store.History(ctx,first.MigrationID)
	if err!=nil || len(history)!=1 || history[0].EventType!="DISCOVERED" {
		t.Fatalf("original history = %+v, %v",history,err)
	}
	stale:=*first
	svc:=&migration.Service{Store:store}
	updated,err:=svc.ApplyTransition(ctx,first.MigrationID,migration.StateValidated)
	if err!=nil||updated.Revision!=2 {t.Fatalf("state/revision %+v %v",updated,err)}
	if err:=store.Put(ctx,&stale);!errors.Is(err,migration.ErrMigrationConflict) {
		t.Fatalf("stale writer accepted: %v",err)
	}
	rebound:=*updated
	rebound.CanonicalIdentityID="principal-other"
	if err:=store.Put(ctx,&rebound);!errors.Is(err,migration.ErrMigrationConflict) {
		t.Fatalf("canonical person reassignment accepted: %v",err)
	}
	duplicate:=*first
	duplicate.MigrationID=n05ID(t)
	duplicate.Revision=0
	if err:=store.Put(ctx,&duplicate);!errors.Is(err,migration.ErrMigrationConflict){
		t.Fatalf("same external identity duplicated across cohort: %v",err)
	}
	if err:=store.Delete(ctx,first.MigrationID);!errors.Is(err,migration.ErrImmutableLedger) {
		t.Fatalf("durable history was deletable: %v",err)
	}
	if _,err:=pool.Exec(ctx,"DELETE FROM iam_migration.history WHERE migration_id=$1",first.MigrationID);err==nil {
		t.Fatal("append-only SQL history deleted")
	}
	if _,err:=pool.Exec(ctx,"UPDATE iam_migration.record SET source_subject='other',revision=revision+1 WHERE migration_id=$1",first.MigrationID);err==nil {
		t.Fatal("SQL bypass changed exact immutable legacy issuer+subject")
	}
	history,err=store.History(ctx,first.MigrationID)
	if err!=nil||len(history)!=2 || history[1].ToState!=migration.StateValidated {
		t.Fatalf("transaction event history drift: %+v %v",history,err)
	}
}

func TestN05PostgresTargetAndRollbackNoRevocationResurrection(t *testing.T) {
	store,_:=n05Database(t)
	ctx:=context.Background()
	r:=n05Human(t,store,true)
	if r.Target.Issuer==""||r.Revision<5 {
		t.Fatalf("missing immutable provisioned target: %+v",r)
	}
	other:=*r
	other.Target.Subject="target-different"
	if err:=store.Put(ctx,&other);!errors.Is(err,migration.ErrMigrationConflict){
		t.Fatalf("target reassignment accepted: %v",err)
	}
	witness:=n05Rollback{valid:true}
	rolled,err:=store.RollbackPreCutover(ctx,r.MigrationID,witness)
	if err!=nil || rolled.MigrationState!=migration.StateRolledBack {
		t.Fatalf("explicit pre-cutover rollback blocked: %+v %v",rolled,err)
	}
	again,err:=store.Get(ctx,r.MigrationID)
	if err!=nil||again.CanonicalIdentityID!=r.CanonicalIdentityID ||
		again.Target!=r.Target {
		t.Fatal("rollback modified identity mapping or target")
	}
	if _,err:=store.RollbackPreCutover(ctx,r.MigrationID,witness);err==nil {
		t.Fatal("repeated irreversible transition was silently accepted")
	}
}

type n05Rollback struct{valid bool}
func (w n05Rollback) VerifyPreCutoverRollback(context.Context,*migration.Record)(migration.RollbackWitness,error){
	return migration.RollbackWitness{
		SourceStillTrusted:w.valid,TargetTrustWithdrawn:w.valid,
		CanonicalUnchanged:w.valid,LegacyRevocationsPreserved:w.valid,
		OriginalReference:"private-development-issuer-trust-readback",
	},nil
}

type n05Provider struct {
	mu sync.Mutex
	disabled bool
	active int
	disableCalls int
	revokeCalls int
}
func (p *n05Provider) DisableIdentity(_ context.Context, subject provider.ExternalSubject)error{
	p.mu.Lock();defer p.mu.Unlock()
	p.disabled=true;p.disableCalls++;return nil
}
func (*n05Provider) EnableIdentity(context.Context,provider.ExternalSubject)error{
	return errors.New("N05 must not reenable credentials")
}
func (p *n05Provider) RevokeSessions(_ context.Context, subject provider.ExternalSubject)error{
	p.mu.Lock();defer p.mu.Unlock()
	p.revokeCalls++;p.active=0;return nil
}
func (p *n05Provider) GetIdentity(_ context.Context,s provider.ExternalSubject)(*provider.ProviderIdentity,error){
	p.mu.Lock();defer p.mu.Unlock()
	status:=provider.IdentityStatusActive
	if p.disabled { status=provider.IdentityStatusDisabled }
	return &provider.ProviderIdentity{Issuer:s.Issuer,Subject:s.Subject,Status:status},nil
}
func (p *n05Provider) ActiveSessionCount(context.Context,provider.ExternalSubject)(int,error){
	p.mu.Lock();defer p.mu.Unlock()
	return p.active,nil
}
type n05Veto struct{denied bool}
func (v n05Veto) VerifyCurrentDenial(_ context.Context,src,dst provider.ExternalSubject,canonical string)(migration.CurrentVetoEvidence,error){
	return migration.CurrentVetoEvidence{
		SourceIssuerDenied:v.denied,TargetIssuerDenied:v.denied,
		CanonicalUnchanged:v.denied,ObservedAt:time.Now().UTC(),
		OriginalReference:"test-only-unattested-cp-veto",
	},nil
}

func TestN05PostgresContainmentIsRevocationSafeAndResumable(t *testing.T){
	store,pool:=n05Database(t);ctx:=context.Background()
	row:=n05Human(t,store,true)
	p:=&n05Provider{active:3}
	controller:=migration.NativeContainment{Store:store,Provider:p,Current:n05Veto{denied:false}}
	op:="n05-contain-"+n05ID(t)
	out,err:=controller.Contain(ctx,row.MigrationID,op)
	if err==nil || out!=nil {t.Fatal("CP source token still active but N05 claimed success")}
	fenced,err:=store.DeniedByFence(ctx,row.MigrationID)
	if err!=nil||!fenced {t.Fatal("provider failure lost durable deny fence")}
	var phase string
	if err:=pool.QueryRow(ctx,"SELECT phase FROM iam_migration.containment WHERE operation_id=$1",op).Scan(&phase);err!=nil||phase!="UNKNOWN"{
		t.Fatalf("unknown provider outcome forgotten: %s %v",phase,err)
	}
	controller.Current=n05Veto{denied:true}
	res,err:=controller.Contain(ctx,row.MigrationID,op)
	if err!=nil||res.Phase!="VERIFIED" {
		t.Fatalf("idempotent exact-operation retry did not prove current deny: %+v %v",res,err)
	}
	if res.Classification=="PROTECTED_ACCEPTED" {t.Fatal("mock current veto promoted to protected acceptance")}
	// A stale database snapshot may say VERIFIED even when Kratos sessions
	// have been restored. N05 refuses the stale receipt, never resurrects
	// authority, and must not pretend the previous 0-session readback holds.
	p.mu.Lock()
	p.active=1
	p.mu.Unlock()
	if _,err:=controller.Contain(ctx,row.MigrationID,op);err==nil{
		t.Fatal("stale VERIFIED ledger hid restored active Kratos session")
	}
	p.mu.Lock()
	p.active=0
	p.mu.Unlock()
	controller.Current=n05Veto{denied:false}
	if _,err:=controller.Contain(ctx,row.MigrationID,op);err==nil{
		t.Fatal("stale VERIFIED ledger hid restored CP current-token allowance")
	}
	controller.Current=n05Veto{denied:true}
	replayed,err:=controller.Contain(ctx,row.MigrationID,op)
	if err!=nil || replayed.Phase!="VERIFIED" || p.disableCalls<4 || p.revokeCalls<4 {
		t.Fatal("restored sessions were not re-contained with same fenced operation")
	}
	beforeDisable,beforeRevoke:=p.disableCalls,p.revokeCalls
	if _,err:=controller.Contain(ctx,row.MigrationID,op);err!=nil ||
		p.disableCalls!=beforeDisable || p.revokeCalls!=beforeRevoke {
		t.Fatal("clean verified readback caused new provider mutations")
	}
	if _,err:=controller.Contain(ctx,row.MigrationID,"n05-other-operation-123456789"); !errors.Is(err,migration.ErrMigrationConflict) {
		t.Fatalf("different run took over original disabled account: %v",err)
	}
	if _,err:=store.RollbackPreCutover(ctx,row.MigrationID,n05Rollback{valid:true});err==nil ||
		!strings.Contains(err.Error(),"revoked authority") {
		t.Fatalf("rollback resurrected disabled sessions: %v",err)
	}
	if _,err:=pool.Exec(ctx,"DELETE FROM iam_migration.deny_fence WHERE migration_id=$1",row.MigrationID);err==nil {
		t.Fatal("direct SQL deleted durable deny tombstone")
	}
	var events int
	if err:=pool.QueryRow(ctx,`SELECT count(*) FROM iam_migration.containment_history
WHERE operation_id=$1`,op).Scan(&events);err!=nil||events<5{
		t.Fatalf("containment recovery history missing: %d %v",events,err)
	}
}

func TestN05PostgresSameTargetCannotBelongToTwoCanonicalPeople(t *testing.T) {
	store,_:=n05Database(t)
	ctx:=context.Background()
	first:=n05Human(t,store,true)
	second:=n05Human(t,store,false)
	svc:=migration.Service{Store:store}
	for _,state:=range []migration.MigrationState{
		migration.StateValidated,migration.StateReady,migration.StateProvisioning,
	}{
		if _,err:=svc.ApplyTransition(ctx,second.MigrationID,state);err!=nil{t.Fatal(err)}
	}
	if _,err:=svc.SetTargetBinding(ctx,second.MigrationID,first.Target);
		!errors.Is(err,migration.ErrMigrationConflict) {
		t.Fatalf("same target bound to two different canonical Principals: %v",err)
	}
	fresh,err:=store.Get(ctx,second.MigrationID)
	if err!=nil||fresh.CanonicalIdentityID!=second.CanonicalIdentityID||
		fresh.Target.Subject!=""{
		t.Fatal("failed duplicate target reconciliation mutated second Principal")
	}
}

func TestN05PostgresImportReconciliationRefusesCanonicalDrift(t *testing.T) {
	store,_:=n05Database(t)
	svc:=migration.Service{Store:store}
	id:=n05ID(t)
	source:=migration.SourceBinding{
		Provider:"keycloak",Issuer:"https://example.invalid/realms/enterprise",
		Subject:id,SuggestedClass:migration.ClassHuman,SnapshotReference:"batch-redacted-v1",
	}
	disc:=migration.FixtureDiscovery{Bindings:[]migration.SourceBinding{source}}
	mapper:=migration.MapCanonicalResolver{Mapping:map[string]string{
		source.Issuer+"\x00"+source.Subject:"principal-"+id,
	}}
	req:=migration.BatchRegisterRequest{BatchID:"n05-reconcile-"+id,
		DefaultStrategy:migration.StrategyControlledReEnrolment}
	result,err:=svc.RegisterBatch(context.Background(),disc,mapper,req)
	if err!=nil||result.Registered!=1 {t.Fatalf("first import %+v %v",result,err)}
	repeat,err:=svc.RegisterBatch(context.Background(),disc,mapper,req)
	if err!=nil||repeat.SkippedExists!=1 {t.Fatalf("exact idempotent import %+v %v",repeat,err)}
	mapper.Mapping[source.Issuer+"\x00"+source.Subject]="principal-different"
	if _,err:=svc.RegisterBatch(context.Background(),disc,mapper,req);err==nil {
		t.Fatal("new CP canonical person silently adopted by repeated import")
	}
}
