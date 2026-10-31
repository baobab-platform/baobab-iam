package nativebff

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore keeps browser PKCE verifiers and tokens encrypted with an
// operator-custodied 256-bit key. It has no process-local fallback: transaction
// consumption is a single database DELETE ... RETURNING across all replicas.
// Schema: internal/nativebff/migrations/001_native_browser_bff.sql.
// The database must be a separately permissioned IAM-owned PostgreSQL 17 DB.
type PostgresStore struct {
	pool *pgxpool.Pool
	aead cipher.AEAD
}
func NewPostgresStore(pool *pgxpool.Pool,key []byte)(*PostgresStore,error){
	if pool==nil||len(key)!=32{return nil,errors.New("PostgreSQL 17 pool and 256-bit session encryption key required")}
	block,err:=aes.NewCipher(append([]byte(nil),key...));if err!=nil{return nil,err}
	aead,err:=cipher.NewGCM(block);if err!=nil{return nil,err}
	return &PostgresStore{pool:pool,aead:aead},nil
}
func hashID(id string)([]byte,error){
	if len(id)!=43{return nil,errors.New("invalid opaque browser identifier")}
	s:=sha256.Sum256([]byte(id))
	return s[:],nil
}
func (s *PostgresStore) seal(kind,id string,value any)([]byte,error){
	raw,err:=json.Marshal(value);if err!=nil||len(raw)>65536{return nil,errors.New("invalid session envelope")}
	nonce:=make([]byte,s.aead.NonceSize())
	if _,err=io.ReadFull(rand.Reader,nonce);err!=nil{return nil,err}
	out:=s.aead.Seal(nil,nonce,raw,[]byte(kind+":"+id))
	return append(nonce,out...),nil
}
func (s *PostgresStore) open(kind,id string,raw []byte,out any)error{
	if len(raw)<=s.aead.NonceSize()||len(raw)>65536+s.aead.Overhead()+s.aead.NonceSize(){
		return errors.New("invalid sealed session envelope")
	}
	nonce:=raw[:s.aead.NonceSize()]
	plain,err:=s.aead.Open(nil,nonce,raw[s.aead.NonceSize():],[]byte(kind+":"+id))
	if err!=nil{return errors.New("session integrity check failed")}
	if json.Unmarshal(plain,out)!=nil{return errors.New("invalid session record")}
	return nil
}
func (s *PostgresStore) PutTransaction(ctx context.Context,id string,t Transaction)error{
	if s==nil||t.Intent.Validate()!=nil||t.Verifier==""||t.CSRF==""||time.Until(t.ExpiresAt)<=0 {return errors.New("invalid native browser transaction")}
	hash,err:=hashID(id);if err!=nil{return err}
	payload,err:=s.seal("txn",id,t);if err!=nil{return err}
	_,err=s.pool.Exec(ctx,"INSERT INTO native_bff_transactions (id_hash,sealed,expires_at) VALUES ($1,$2,$3)",hash,payload,t.ExpiresAt)
	return err
}
func (s *PostgresStore) getTx(ctx context.Context,id string,take bool)(Transaction,error){
	var t Transaction
	if s==nil{return t,errors.New("native store unavailable")}
	hash,err:=hashID(id);if err!=nil{return t,err}
	var sealed []byte
	if take {
		err=s.pool.QueryRow(ctx,"DELETE FROM native_bff_transactions WHERE id_hash=$1 AND expires_at>clock_timestamp() RETURNING sealed",hash).Scan(&sealed)
	} else {
		err=s.pool.QueryRow(ctx,"SELECT sealed FROM native_bff_transactions WHERE id_hash=$1 AND expires_at>clock_timestamp()",hash).Scan(&sealed)
	}
	if err!=nil {if errors.Is(err,pgx.ErrNoRows){return t,errors.New("transaction expired or consumed")};return t,err}
	if err=s.open("txn",id,sealed,&t);err!=nil||t.Intent.Validate()!=nil||t.Verifier==""||t.CSRF==""||!time.Now().Before(t.ExpiresAt){
		return Transaction{},errors.New("native transaction unavailable")
	}
	return t,nil
}
func (s *PostgresStore) ReadTransaction(ctx context.Context,id string)(Transaction,error){return s.getTx(ctx,id,false)}
func (s *PostgresStore) TakeTransaction(ctx context.Context,id string)(Transaction,error){return s.getTx(ctx,id,true)}
func (s *PostgresStore) PutSession(ctx context.Context,id string,t Session)error{
	if s==nil||t.Issuer==""||t.Subject==""||t.PrincipalID==""||t.CSRF==""||t.Tokens.Validate()!=nil||
		t.Tokens.IDToken==""||time.Until(t.ExpiresAt)<=0 {return errors.New("invalid native browser session")}
	hash,err:=hashID(id);if err!=nil{return err}
	sealed,err:=s.seal("sess",id,t);if err!=nil{return err}
	_,err=s.pool.Exec(ctx,"INSERT INTO native_bff_sessions (id_hash,sealed,expires_at) VALUES ($1,$2,$3)",hash,sealed,t.ExpiresAt)
	return err
}
func (s *PostgresStore) ReadSession(ctx context.Context,id string)(Session,error){
	var t Session
	if s==nil{return t,errors.New("native store unavailable")}
	hash,err:=hashID(id);if err!=nil{return t,err}
	var sealed []byte
	err=s.pool.QueryRow(ctx,"SELECT sealed FROM native_bff_sessions WHERE id_hash=$1 AND expires_at>clock_timestamp()",hash).Scan(&sealed)
	if err!=nil {if errors.Is(err,pgx.ErrNoRows){return t,errors.New("session missing or expired")};return t,err}
	if err=s.open("sess",id,sealed,&t);err!=nil||t.Tokens.Validate()!=nil||!time.Now().Before(t.ExpiresAt){
		return Session{},errors.New("native session unavailable")
	}
	return t,nil
}
func (s *PostgresStore) DeleteSession(ctx context.Context,id string)error{
	if s==nil{return errors.New("native store unavailable")}
	hash,err:=hashID(id);if err!=nil{return err}
	_,err=s.pool.Exec(ctx,"DELETE FROM native_bff_sessions WHERE id_hash=$1",hash)
	return err
}
var _ Store = (*PostgresStore)(nil)
