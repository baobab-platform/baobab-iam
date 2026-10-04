module github.com/baobab-platform/baobab-iam

go 1.27.0

// Provider and migration interfaces remain stdlib-only. Federation's actual
// protocol verifier uses maintained OIDC/JOSE libraries and a durable ledger.
// Go 1.25 is the dependency minimum; use the tested CP-aligned Go 1.27 toolchain.

require (
	github.com/coreos/go-oidc/v3 v3.21.0
	github.com/go-jose/go-jose/v4 v4.1.5
	go.etcd.io/bbolt v1.4.3
)

require (
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
)
