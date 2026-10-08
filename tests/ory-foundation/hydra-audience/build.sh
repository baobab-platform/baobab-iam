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
# The upstream OAuth HTTP test file changed structurally since the release.
# Retain release HTTP tests; carry the upstream RFC7523 and config unit tests.
git -C "$candidate_dir/source" show --format= "$fix" -- \
  .schema/config.schema.json driver/config/provider.go driver/config/provider_test.go \
  fosite/config.go fosite/config_default.go fosite/handler/rfc7523/handler.go \
  fosite/handler/rfc7523/handler_test.go spec/config.json > "$candidate_dir/backport.patch"
git -C "$candidate_dir/source" apply --check "$candidate_dir/backport.patch"
git -C "$candidate_dir/source" apply "$candidate_dir/backport.patch"
# Legacy HTTP tests explicitly request legacy behavior; no verification is removed.
python3 - "$candidate_dir/source/oauth2/oauth2_jwt_bearer_test.go" <<'PY'
import sys
from pathlib import Path
p=Path(sys.argv[1]); s=p.read_text()
old='reg := testhelpers.NewRegistryMemory(t, driver.WithConfigOptions(configx.WithValue(config.KeyAccessTokenStrategy, "opaque")))'
new='reg := testhelpers.NewRegistryMemory(t, driver.WithConfigOptions(configx.WithValue(config.KeyAccessTokenStrategy, "opaque"), configx.WithValue(config.KeyOAuth2GrantJWTOmitAssertionAudience, false)))'
assert s.count(old)==1
p.write_text(s.replace(old,new))
PY
(
  cd "$candidate_dir/source"
  go test -race ./fosite/handler/rfc7523 ./driver/config
  CGO_ENABLED=1 go test -tags sqlite ./oauth2 -run '^TestJWTBearer$' -count=1
  CGO_ENABLED=0 go build -mod=readonly -buildvcs=false -ldflags="-X github.com/ory/hydra/v2/driver/config.Version=v26.2.0-baobab-audience.1" -o "$candidate_dir/hydra" .
)
mkdir -p ory-foundation-evidence
python3 - "$candidate_dir" "$base" "$fix" <<'PY'
import hashlib,json,sys
from pathlib import Path
p=Path(sys.argv[1])
receipt={'classification':'ISOLATED_BUILD_CANDIDATE','base_commit':sys.argv[2], 'upstream_fix_commit':sys.argv[3],
         'patch_sha256':hashlib.sha256((p/'backport.patch').read_bytes()).hexdigest(),
         'binary_sha256':hashlib.sha256((p/'hydra').read_bytes()).hexdigest(), 'production_accepted':False}
Path('ory-foundation-evidence/hydra-backport-build.json').write_text(json.dumps(receipt,indent=2)+'\n')
PY
cp "$root/tests/ory-foundation/hydra-audience/Dockerfile" "$candidate_dir/Dockerfile"
mkdir "$candidate_dir/image"
cp "$candidate_dir/hydra" "$candidate_dir/Dockerfile" "$candidate_dir/image/"
docker build --tag baobab-hydra-audience-candidate:ci "$candidate_dir/image"
docker image inspect --format '{{.Id}}' baobab-hydra-audience-candidate:ci > ory-foundation-evidence/hydra-candidate-image.txt
