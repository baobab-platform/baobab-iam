// Package securityops owns privacy-minimized, durable IAM security evidence
// and restrictive lifecycle proposals. It does NOT issue CP permissions or
// mutate global issuer/federation trust (ADR-IAM-0029, 0033).
package securityops

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/001_n06_security.sql
var schema string

func Schema() string { return schema }
type Store struct { pool *pgxpool.Pool; indexKey []byte; now func()time.Time }

func NewStore(ctx context.Context, pool *pgxpool.Pool, key []byte, now func()time.Time)(*Store,error){
	if ctx==nil||pool==nil||len(key)!=32||now==nil {
		return nil,errors.New("securityops: PostgreSQL, scoped 256-bit pseudonymization key and clock required")
	}
	allZero:=true
	for _,x:=range key{if x!=0{allZero=false}}
	if allZero{return nil,errors.New("securityops: uninitialized index key")}
	var table *string
	if err:=pool.QueryRow(ctx,"SELECT to_regclass('iam_security.event')::text").Scan(&table);err!=nil||table==nil{
		return nil,errors.New("securityops: reviewed schema not installed")
	}
	return &Store{pool:pool,indexKey:append([]byte(nil),key...),now:now},nil
}
func (s *Store) tag(purpose, value string)([]byte,error){
	if s==nil ||len(s.indexKey)!=32||purpose==""||value==""||len(value)>2048||
		strings.ContainsAny(value,"\x00\r\n") { return nil,errors.New("securityops: invalid opaque identity reference") }
	mac:=hmac.New(sha256.New,s.indexKey)
	mac.Write([]byte(purpose))
	mac.Write([]byte{0})
	mac.Write([]byte(value))
	return mac.Sum(nil),nil
}
func uuid() (string,error){
	var id [16]byte
	if _,err:=rand.Read(id[:]);err!=nil{return "",err}
	id[6]=(id[6]&0x0f)|0x40
	id[8]=(id[8]&0x3f)|0x80
	x:=hex.EncodeToString(id[:])
	return x[:8]+"-"+x[8:12]+"-"+x[12:16]+"-"+x[16:20]+"-"+x[20:],nil
}
var uuidPattern=regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var recoveryReasons=[]string{"RECOVERY_COMPLETE","AUTHENTICATOR_REPLACED","SUSPECTED_TAKEOVER"}

// RecoveryAction is a provider-verified event, not a browser declaration.
// A recovery or authenticator replacement must not lower future assurance.
type RecoveryAction struct {
	Principal string
	Issuer string
	SecurityDomain string
	Reason string
	ObservedAt time.Time
	HoldUntil time.Time
}
func (s *Store) RecordRecovery(ctx context.Context, a RecoveryAction) error {
	now:=s.now().UTC()
	if ctx==nil||ctx.Err()!=nil||!slices.Contains(recoveryReasons,a.Reason)||
		a.ObservedAt.IsZero()||a.ObservedAt.After(now)||now.Sub(a.ObservedAt)>time.Minute||
		!a.HoldUntil.After(now)||a.HoldUntil.Sub(now)>30*24*time.Hour {
		return errors.New("securityops: current, approved recovery proof required")
	}
	p,err:=s.tag("principal",a.Principal);if err!=nil{return err}
	i,err:=s.tag("issuer",a.Issuer);if err!=nil{return err}
	d,err:=s.tag("security-domain",a.SecurityDomain);if err!=nil{return err}
	command,err:=s.pool.Exec(ctx,`INSERT INTO iam_security.recovery_hold
 (principal_key,issuer_key,security_domain_key,observed_at,hold_until,reason)
 VALUES ($1,$2,$3,$4,$5,$6)
 ON CONFLICT (principal_key) DO UPDATE SET
 observed_at=GREATEST(iam_security.recovery_hold.observed_at,EXCLUDED.observed_at),
 hold_until=GREATEST(iam_security.recovery_hold.hold_until,EXCLUDED.hold_until),
 reason=CASE WHEN EXCLUDED.hold_until>=iam_security.recovery_hold.hold_until
 THEN EXCLUDED.reason ELSE iam_security.recovery_hold.reason END,
 revision=iam_security.recovery_hold.revision+1
 WHERE iam_security.recovery_hold.issuer_key=EXCLUDED.issuer_key
 AND iam_security.recovery_hold.security_domain_key=EXCLUDED.security_domain_key`,
	p,i,d,a.ObservedAt,a.HoldUntil,a.Reason)
	if err!=nil{return fmt.Errorf("securityops: recovery hold not persisted: %w",err)}
	if command.RowsAffected()!=1{return errors.New("securityops: recovery issuer/security-domain ownership drift")}
	return nil
}

// RecoveryHoldUntil is a DB-read current scope, not proof that recovery
// never occurred when no row exists. Callers MUST require an authoritative
// source event-cursor watermark before interpreting a missing row as clear.
func (s *Store) RecoveryHoldUntil(ctx context.Context, principal, issuer, domain string)(time.Time,bool,error){
	if ctx==nil{return time.Time{},false,errors.New("securityops: context required")}
	p,err:=s.tag("principal",principal);if err!=nil{return time.Time{},false,err}
	i,err:=s.tag("issuer",issuer);if err!=nil{return time.Time{},false,err}
	d,err:=s.tag("security-domain",domain);if err!=nil{return time.Time{},false,err}
	var t time.Time
	err=s.pool.QueryRow(ctx,`SELECT hold_until FROM iam_security.recovery_hold
 WHERE principal_key=$1 AND issuer_key=$2 AND security_domain_key=$3`,p,i,d).Scan(&t)
	if errors.Is(err,pgx.ErrNoRows){return time.Time{},false,nil}
	if err!=nil{return time.Time{},false,err}
	return t,true,nil
}

var eventTypes=[]string{
	"authentication.failed","authentication.succeeded","mfa.challenge.failed",
	"passkey.registered","passkey.revoked","recovery.started","recovery.completed",
	"identity.disabled","session.revoked","credential.rotated",
	"crypto.key.compromised","oauth_client.revoked","incident.contained",
	"incident.unknown","authorization.denied",
}
var outcomes=[]string{"ALLOWED","DENIED","UNKNOWN","RECORDED"}
var severities=[]string{"LOW","MEDIUM","HIGH","CRITICAL"}
var codes=[]string{"POLICY_DENY","CURRENT_PROVIDER_DENY","EXPIRED_EVIDENCE","STEP_UP_REQUIRED","USER_CANCELLED","REPLAY_DENY","CORRELATION_LOST","INTERNAL_FAILURE","PROVIDER_CONFIRMED","RESOURCE_DENIED","UNKNOWN_OUTCOME"}

// SafeEvent excludes request bodies, browser cookies, email, IP address,
// user agent, tokens, raw principal, arbitrary key/value metadata or secrets.
// Indexes are independently keyed HMACs, not stable public identifiers.
type SafeEvent struct {
	Type string
	Actor string
	Subject string
	CorrelationID string
	Outcome string
	Severity string
	ResultCode string
	OccurredAt time.Time
}
func (s *Store) AppendEvent(ctx context.Context, ev SafeEvent)(string,error){
	now:=s.now().UTC()
	if ctx==nil||ctx.Err()!=nil||!slices.Contains(eventTypes,ev.Type)||
		!slices.Contains(outcomes,ev.Outcome)||!slices.Contains(severities,ev.Severity)||
		!slices.Contains(codes,ev.ResultCode)||
		!uuidPattern.MatchString(ev.CorrelationID)||
		ev.OccurredAt.IsZero()||ev.OccurredAt.After(now)||
		now.Sub(ev.OccurredAt)>10*time.Minute {
		return "",errors.New("securityops: unreviewed security event")
	}
	sub,err:=s.tag("subject",ev.Subject);if err!=nil{return "",err}
	var actor []byte
	if ev.Actor!="" { actor,err=s.tag("actor",ev.Actor);if err!=nil{return "",err} }
	id,err:=uuid();if err!=nil{return "",errors.New("securityops: secure event id unavailable")}
	// Result codes are intentionally low-cardinality; no arbitrary metadata
	// or provider exception text goes to the immutable audit stream.
	_,err=s.pool.Exec(ctx,`INSERT INTO iam_security.event
(event_id,event_type,occurred_at,actor_key,subject_key,correlation_id,
outcome,severity,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,jsonb_build_object('result_code',$9))`,
	id,ev.Type,ev.OccurredAt,actor,sub,ev.CorrelationID,ev.Outcome,ev.Severity,ev.ResultCode)
	if err!=nil{return "",fmt.Errorf("securityops: security event not committed: %w",err)}
	return id,nil
}

func errConflict(err error) error{
	var pg *pgconn.PgError
	if errors.As(err,&pg)&&slices.Contains([]string{"23505","23514","40001","P0001"},pg.Code) {
		return errors.New("securityops: security record conflict")
	}
	return errors.New("securityops: durable security store unavailable")
}
