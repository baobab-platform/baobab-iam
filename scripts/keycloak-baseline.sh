#!/usr/bin/env bash
# Resolve and verify the pinned Keycloak image, and record which override-
# relevant libraries it vendors. Needs registry egress (CI), not a dev sandbox.
#   scripts/keycloak-baseline.sh            verify; fail if lock/Dockerfile disagree
# Evidence is written to $EVIDENCE_DIR (default keycloak-baseline-evidence/).
set -euo pipefail
cd "$(dirname "$0")/.."

ver=$(yq -o=json '.' upstream.lock.yaml | jq -r '.keycloak.version')
img=$(yq -o=json '.' upstream.lock.yaml | jq -r '.keycloak.image')
pin=$(yq -o=json '.' upstream.lock.yaml | jq -r '.keycloak.digest')
out=${EVIDENCE_DIR:-keycloak-baseline-evidence}
mkdir -p "$out"

live=$(docker buildx imagetools inspect "$img:$ver" --format '{{json .Manifest}}' | jq -r '.digest')
echo "resolved $img:$ver -> $live" | tee "$out/digest.txt"

# Vendored libraries, for deciding which overrides are still needed.
docker pull -q "$img:$ver@$live" >/dev/null
cid=$(docker create "$img:$ver@$live")
trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT
{
  echo "## lib/lib/main"; docker cp "$cid:/opt/keycloak/lib/lib/main" - | tar -t | grep -E 'bcprov|bcpkix|bcutil|freemarker|jackson' | sed 's|.*/||' | sort -u
  echo "## bin/client"; docker cp "$cid:/opt/keycloak/bin/client" - | tar -t | grep -E 'jar$' | sed 's|.*/||' | sort -u
} | tee "$out/vendored-libraries.txt"

# Admin CLI is a fat jar: record the Jackson databind it embeds.
docker cp "$cid:/opt/keycloak/bin/client/keycloak-admin-cli-$ver.jar" "$out/admin-cli.jar"
cli_db=$(unzip -p "$out/admin-cli.jar" META-INF/maven/com.fasterxml.jackson.core/jackson-databind/pom.properties | sed -n 's/^version=//p')
rm -f "$out/admin-cli.jar"
echo "admin-cli embedded jackson-databind: ${cli_db:-none}" | tee -a "$out/vendored-libraries.txt"
fail=0
# The base image must carry the fixes itself (no jar overrides in the Dockerfile).
ge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$2" ]; }  # $1 >= $2
ge "${cli_db:-0}" 2.21.6 || { echo "::error::admin-cli embeds jackson-databind ${cli_db:-none} < 2.21.6"; fail=1; }
grep -q 'freemarker-2\.3\.\(3[5-9]\|[4-9]\)' "$out/vendored-libraries.txt" || { echo "::error::FreeMarker < 2.3.35"; fail=1; }
grep -q 'bcprov-jdk18on-1\.\(8[5-9]\|9\)' "$out/vendored-libraries.txt" || { echo "::error::Bouncy Castle < 1.85"; fail=1; }
! grep -q 'COPY --from=\(bouncycastle\|freemarker\|jackson\)' Dockerfile || { echo "::error::obsolete jar override present"; fail=1; }
case "$pin" in
  sha256:*) [ "$pin" = "$live" ] || { echo "::error::upstream.lock.yaml digest $pin != registry $live"; fail=1; } ;;
  *) echo "::error::upstream.lock.yaml digest is not pinned (R-1). Set keycloak.digest to $live"; fail=1 ;;
esac
want="$img:$ver@$pin"
grep -q "^FROM $want" Dockerfile || { echo "::error::Dockerfile final/builder FROM must consume $want"; fail=1; }
exit $fail
