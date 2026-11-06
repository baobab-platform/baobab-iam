package nativebff

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/assurance"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

type a3Current struct {
	key assurance.CurrentSessionKey
	evidence assurance.Evidence
}
func (c a3Current) CurrentNativeAuthentication(_ context.Context, cred ory.NativeSessionCredential) (assurance.CurrentSessionKey, assurance.Evidence, error) {
	return c.key, c.evidence, nil
}
type a3Challenges struct {
	mu sync.Mutex
	item WebAuthnChallenge
	taken bool
}
func (s *a3Challenges) Consume(_ context.Context, id string) (WebAuthnChallenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.taken || id != s.item.ID { return WebAuthnChallenge{}, errA3Denied }
	s.taken = true
	return s.item, nil
}
type a3Credentials struct {
	mu sync.Mutex
	item KratosWebAuthnCredential
	counter uint32
}
func (s *a3Credentials) CurrentKratosCredential(_ context.Context, _ assurance.CurrentSessionKey, id string) (KratosWebAuthnCredential, error) {
	if id != s.item.ID { return KratosWebAuthnCredential{}, errA3Denied }
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.item
	v.SignCount = s.counter
	return v, nil
}
func (s *a3Credentials) AdvanceKratosSignCounter(_ context.Context, item KratosWebAuthnCredential, next uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if item.SignCount != s.counter || next <= s.counter { return errA3Denied }
	s.counter = next
	return nil
}
type a3Fixture struct {
	v *WebAuthnA3Verifier
	assertion WebAuthnAssertion
	challenges *a3Challenges
	credentials *a3Credentials
}
func makeA3Fixture(t *testing.T) a3Fixture {
	t.Helper()
	now := time.Date(2026, 11, 6, 8, 0, 0, 0, time.UTC)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { t.Fatal("generate real ephemeral ES256 key") }
	pub, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil { t.Fatal("marshal ephemeral provider public key") }
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil { t.Fatal("secure test challenge") }
	key := assurance.CurrentSessionKey{Issuer:"https://iam.example.test", Subject:"subject-existing", SessionID:"session-existing"}
	challenge := WebAuthnChallenge{
		ID:"challenge-original-unique", Session:key,
		RPID:"auth.example.test", Origin:"https://auth.example.test",
		Nonce:nonce, CreatedAt:now.Add(-20*time.Second), ExpiresAt:now.Add(30*time.Second),
	}
	raw, err := json.Marshal(map[string]any{
		"type":"webauthn.get", "origin":challenge.Origin,
		"challenge":base64.RawURLEncoding.EncodeToString(nonce), "crossOrigin":false,
	})
	if err != nil { t.Fatal(err) }
	auth := make([]byte, 37)
	rp := sha256.Sum256([]byte(challenge.RPID))
	copy(auth[:32], rp[:])
	auth[32] = 0x05 // UP and UV, NOT a hardware attestation
	binary.BigEndian.PutUint32(auth[33:], 2)
	cd := sha256.Sum256(raw)
	signed := append(append([]byte{}, auth...), cd[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil { t.Fatal("sign fixture assertion") }
	credentials := &a3Credentials{item:KratosWebAuthnCredential{
		ID:"credential-owned-by-kratos", Issuer:key.Issuer, Subject:key.Subject,
		PublicKeyDER:pub, SignCount:1,
	},counter:1}
	challenges := &a3Challenges{item:challenge}
	base := assurance.Evidence{Issuer:key.Issuer,Subject:key.Subject,SessionID:key.SessionID,
		AAL:"aal2", Methods:[]string{"webauthn"}, AuthenticatedAt:now.Add(-15*time.Second),
		ObservedAt:now}
	return a3Fixture{
		v:&WebAuthnA3Verifier{
			Kratos:a3Current{key:key,evidence:base}, Challenges:challenges,
			Credentials:credentials,Now:func() time.Time{return now},
		},
		assertion:WebAuthnAssertion{
			ChallengeID:challenge.ID,CredentialID:credentials.item.ID,
			ClientDataJSON:raw,AuthenticatorData:auth,SignatureDER:sig,
		},challenges:challenges,credentials:credentials,
	}
}

func TestN06WebAuthnA3VerifiesRealES256AndDeniesReplay(t *testing.T) {
	f := makeA3Fixture(t)
	cred := ory.NativeSessionCredential{Cookie:"ory_kratos_session=server-only"}
	evidence, err := f.v.Verify(context.Background(), cred, f.assertion)
	if err != nil || evidence.AAL != "aal2" || !evidence.PasskeyUsed ||
		!evidence.UserVerified || !evidence.OriginBound || evidence.HardwareBound ||
		evidence.Subject != f.challenges.item.Session.Subject {
		t.Fatal("valid real ES256 RP assertion did not produce strictly A3-only proof")
	}
	if f.credentials.counter != 2 { t.Fatal("Kratos credential counter not advanced") }
	if _, err := f.v.Verify(context.Background(), cred, f.assertion); err == nil {
		t.Fatal("one-time challenge was replayed")
	}
}

func TestN06WebAuthnA3FailClosedNegativeMatrix(t *testing.T) {
	testCases := map[string]func(*a3Fixture){
		"missing-uv":func(f *a3Fixture){f.assertion.AuthenticatorData[32] = 0x01},
		"missing-up":func(f *a3Fixture){f.assertion.AuthenticatorData[32] = 0x04},
		"wrong-rp":func(f *a3Fixture){f.assertion.AuthenticatorData[0] ^= 0xFF},
		"signature-tamper":func(f *a3Fixture){f.assertion.SignatureDER[12] ^= 0x3F},
		"wrong-browser-origin":func(f *a3Fixture){f.challenges.item.Origin = "https://foreign.example.test"},
		"unexpected-http-origin":func(f *a3Fixture){f.challenges.item.Origin = "http://auth.example.test"},
		"wrong-subject":func(f *a3Fixture){f.challenges.item.Session.Subject = "other"},
		"wrong-issuer":func(f *a3Fixture){f.challenges.item.Session.Issuer = "https://other.example.test"},
		"expired":func(f *a3Fixture){f.challenges.item.ExpiresAt = f.v.Now().Add(-time.Second)},
		"untrusted-client-nonce":func(f *a3Fixture){f.challenges.item.Nonce[0] ^= 0xFA},
		"wrong-credential":func(f *a3Fixture){f.assertion.CredentialID = "credential-from-other-provider"},
		"replayed-sign-count":func(f *a3Fixture){f.credentials.counter = 2},
		"no-native-current-aal2":func(f *a3Fixture){
			v := f.v.Kratos.(a3Current)
			v.evidence.AAL = "aal1"
			f.v.Kratos = v
		},
		"untrusted-method-only":func(f *a3Fixture){
			v := f.v.Kratos.(a3Current)
			v.evidence.Methods = []string{"password","totp"}
			f.v.Kratos = v
		},
		"browser-claims-hardware":func(f *a3Fixture){
			f.assertion.ClientDataJSON = []byte(`{"type":"webauthn.get","challenge":"invalid","origin":"https://auth.example.test","hardwareBound":true}`)
		},
		"duplicate-client-origin":func(f *a3Fixture){
			f.assertion.ClientDataJSON = []byte(`{"type":"webauthn.get","origin":"https://auth.example.test","origin":"https://evil.example.test","challenge":"fake"}`)
		},
		"wrong-client-type":func(f *a3Fixture){
			f.assertion.ClientDataJSON = []byte(`{"type":"webauthn.create","origin":"https://auth.example.test","challenge":"fake"}`)
		},
		"cross-origin":func(f *a3Fixture){
			f.assertion.ClientDataJSON = []byte(`{"type":"webauthn.get","origin":"https://auth.example.test","challenge":"fake","crossOrigin":true}`)
		},
		"unknown-challenge":func(f *a3Fixture){f.assertion.ChallengeID = "challenge-from-other-actor"},
	}
	for name, mutate := range testCases {
		t.Run(name,func(t *testing.T){
			f := makeA3Fixture(t)
			mutate(&f)
			if _, err := f.v.Verify(context.Background(),
				ory.NativeSessionCredential{Cookie:"ory_kratos_session=server-only"},
				f.assertion); err == nil {
				t.Fatal("invalid WebAuthn A3 proof was accepted")
			}
		})
	}
}

func TestN06WebAuthnClientDataRejectsDuplicateAndUnknownFields(t *testing.T) {
	f := makeA3Fixture(t)
	var candidate map[string]json.RawMessage
	if err := json.Unmarshal(f.assertion.ClientDataJSON, &candidate); err != nil {t.Fatal(err)}
	if _, err := decodeBoundWebAuthnClientData(f.assertion.ClientDataJSON);err!=nil {t.Fatal("valid client data refused",err)}
	for _, input := range [][]byte{
		[]byte(`{"type":"webauthn.get","type":"webauthn.create","challenge":"x","origin":"y"}`),
		[]byte(`{"type":"webauthn.get","challenge":"x","origin":"y","admin":true}`),
		[]byte(`[]`),
	} {
		if _, err := decodeBoundWebAuthnClientData(input);err==nil {
			t.Fatal("ambiguous browser client data admitted")
		}
	}
}
