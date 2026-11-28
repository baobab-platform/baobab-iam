module github.com/baobab-platform/baobab-iam

go 1.27.3

// Provider and migration interfaces remain stdlib-only. Federation's actual
// protocol verifier uses maintained OIDC/JOSE libraries and a durable ledger.
// Go 1.27.3 also includes the crypto/x509 distrust mitigation for CVE-2026-111943.

require (
	github.com/beevik/etree v1.8.1
	github.com/coreos/go-oidc/v3 v3.21.0
	github.com/fxamacker/cbor/v2 v2.10.0
	github.com/go-jose/go-jose/v4 v4.1.9
	github.com/jackc/pgx/v5 v5.13.0
	github.com/russellhaering/goxmldsig v1.6.1
	github.com/supatype/saml v0.7.0
	go.etcd.io/bbolt v1.5.0
	golang.org/x/net v0.63.0
	golang.org/x/sys v0.50.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/text v0.44.0 // indirect
)
