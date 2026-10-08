#!/usr/bin/env bash
# Build an isolated acceptance candidate. Never publish or alter provider.lock.yaml.
set -euo pipefail
cd "$(dirname "$0")/../../.."
root=$PWD
candidate_dir=$(mktemp -d)
trap 'rm -rf "$candidate_dir"' EXIT
base=0b84568fffccf151dc5e6c7955fdfb738555bf4b
fix=92bd3eab9864453d72edc3d0bc51f004ff986c06
git init -q "$candidate_dir/source"
git -C "$candidate_dir/source" remote add origin https://github.com/ory/hydra.git
git -C "$candidate_dir/source" fetch --depth 2 origin "$base" "$fix"
git -C "$candidate_dir/source" checkout --detach "$base"
# Source and unit-test hunks of the upstream commit apply verbatim (backport.patch). Its OAuth HTTP test hunk also applies,
# except that it was written on top of a later upstream test (an unrelated "issuer-derived audience" subtest) that is not in
# v26.2.0: oauth2-jwt-bearer-test.patch is that hunk with only that unrelated subtest removed. It keeps upstream's own edit that
# selects the legacy copy behavior for the released HTTP suite and adds upstream's test for the new option.
git -C "$candidate_dir/source" show --format= "$fix" -- \
  .schema/config.schema.json driver/config/provider.go driver/config/provider_test.go \
  fosite/config.go fosite/config_default.go fosite/handler/rfc7523/handler.go \
  fosite/handler/rfc7523/handler_test.go spec/config.json > "$candidate_dir/backport.patch"
git -C "$candidate_dir/source" apply --check "$candidate_dir/backport.patch"
git -C "$candidate_dir/source" apply "$candidate_dir/backport.patch"
# Preserve the exact released Pop implementation, port only its configuration
# parser to the pgx/v5 driver already used for actual database connections.
pop_version=v6.3.2-0.20251203152233-a32233875f7e
pop_dir=$(cd "$candidate_dir/source" && go mod download -json "github.com/ory/pop/v6@$pop_version" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Dir"])')
mkdir -p "$candidate_dir/source/security"
cp -R "$pop_dir" "$candidate_dir/source/security/pop"
chmod -R u+w "$candidate_dir/source/security/pop"
python3 - "$candidate_dir/source/security/pop/dialect_postgresql.go" <<'PYPOP'
import sys
from pathlib import Path
p=Path(sys.argv[1]); s=p.read_text()
old='"github.com/jackc/pgconn"'
assert s.count(old)==1
p.write_text(s.replace(old,'"github.com/jackc/pgx/v5/pgconn"'))
p=p.with_name('dialect_postgresql_test.go'); s=p.read_text()
# Disabled TLS has no certificate fixture. Test the stronger missing-file
# rejection independently, rather than relying on nonexistent certificate paths.
old=' sslcert=/some/location sslkey=/some/other/location sslrootcert=/root/location'
assert s.count(old)==1
p.write_text(s.replace(old,''))
PYPOP
git -C "$candidate_dir/source" apply --check "$root/tests/ory-foundation/hydra-audience/security.patch"
git -C "$candidate_dir/source" apply "$root/tests/ory-foundation/hydra-audience/security.patch"
cp "$root/tests/ory-foundation/hydra-audience/parser_test.go.fixture" "$candidate_dir/source/security/pop/candidate_parser_test.go"
mkdir -p "$candidate_dir/source/internal/candidatesecurity"
cp "$root/tests/ory-foundation/hydra-audience/sqlstate_test.go.fixture" "$candidate_dir/source/internal/candidatesecurity/security_test.go"
test_patch="$root/tests/ory-foundation/hydra-audience/oauth2-jwt-bearer-test.patch"
git -C "$candidate_dir/source" apply --check "$test_patch"
git -C "$candidate_dir/source" apply "$test_patch"
(
  cd "$candidate_dir/source"
  # The explicit test tag retains the original Docker helpers in upstream tests.
  go test -race ./fosite/handler/rfc7523 ./driver/config ./internal/candidatesecurity
  # Local replacements are nested modules; run via their module path.
  go test -race github.com/ory/pop/v6 -run '^Test_PostgreSQL_|^TestCandidateParser' -count=1
  runtime_modules=$(go list -mod=readonly -deps -f '{{if .Module}}{{.Module.Path}}{{end}}' .)
  if printf '%s\n' "$runtime_modules" | grep -Eq '^github.com/(docker/docker|jackc/pgconn|jackc/pgproto3/v2)$'; then
    echo 'Forbidden legacy/test-only runtime dependency remains' >&2
    exit 1
  fi
  CGO_ENABLED=1 go test -tags sqlite,hydra_integration_tests ./oauth2 -run '^TestJWTBearer$' -count=1 -v | tee "$candidate_dir/jwtbearer.txt"
  grep -q -- '--- PASS: TestJWTBearer/case=omits_the_assertion_audience_when_omit_assertion_audience_is_enabled' "$candidate_dir/jwtbearer.txt"
  CGO_ENABLED=0 go build -mod=readonly -buildvcs=false -ldflags="-X github.com/ory/hydra/v2/driver/config.Version=v26.2.0-baobab-audience.1" -o "$candidate_dir/hydra" .
)
mkdir -p ory-foundation-evidence
python3 - "$candidate_dir" "$base" "$fix" "$test_patch" <<'PY'
import hashlib,json,sys
from pathlib import Path
p=Path(sys.argv[1])
receipt={'classification':'ISOLATED_BUILD_CANDIDATE','base_commit':sys.argv[2], 'upstream_fix_commit':sys.argv[3],
         'patch_sha256':hashlib.sha256((p/'backport.patch').read_bytes()).hexdigest(),
         'test_patch_sha256':hashlib.sha256(Path(sys.argv[4]).read_bytes()).hexdigest(),
         'security_patch_sha256':hashlib.sha256(Path('tests/ory-foundation/hydra-audience/security.patch').read_bytes()).hexdigest(),
         'go_mod_sha256':hashlib.sha256((p/'source/go.mod').read_bytes()).hexdigest(),
         'go_sum_sha256':hashlib.sha256((p/'source/go.sum').read_bytes()).hexdigest(),
         'binary_sha256':hashlib.sha256((p/'hydra').read_bytes()).hexdigest(), 'production_accepted':False}
Path('ory-foundation-evidence/hydra-backport-build.json').write_text(json.dumps(receipt,indent=2)+'\n')
PY
cp "$root/tests/ory-foundation/hydra-audience/Dockerfile" "$candidate_dir/Dockerfile"
mkdir "$candidate_dir/image"
cp "$candidate_dir/hydra" "$candidate_dir/Dockerfile" "$candidate_dir/image/"
docker build --tag baobab-hydra-audience-candidate:ci "$candidate_dir/image"
docker image inspect --format '{{.Id}}' baobab-hydra-audience-candidate:ci > ory-foundation-evidence/hydra-candidate-image.txt
