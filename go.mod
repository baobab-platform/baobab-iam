module github.com/baobab-platform/baobab-iam

go 1.27.2

// Provider and migration interfaces remain stdlib-only. Federation's actual
// protocol verifier uses maintained OIDC/JOSE libraries and a durable ledger.
// Go 1.27.2 includes the security-fixed net/http and crypto/tls stdlib used by IAM federation binaries.

require (
	github.com/beevik/etree v1.8.1
	github.com/coreos/go-oidc/v3 v3.21.0
	github.com/crewjam/saml v0.5.1
	github.com/go-jose/go-jose/v4 v4.1.5
	github.com/russellhaering/goxmldsig v1.6.1
	go.etcd.io/bbolt v1.4.3
	golang.org/x/net v0.60.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.11.0
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)
