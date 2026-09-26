# Dockerfile – multi‑stage build for Keycloak with Baobab configuration
#
# The upstream quay.io/keycloak/keycloak final-stage image is built on
# ubi9-micro, which intentionally has no package manager (no dnf/microdnf).
# bootstrap.sh (executed inside the running container) needs jq (to read
# clientId / merge a dev-only secret from the client JSON files) — it does
# NOT need curl; the readiness wait loop uses kcadm.sh's own bundled Java
# HTTP client instead (see bootstrap.sh). Per Red Hat's documented pattern
# for adding packages to a micro image, jq is resolved in a throwaway ubi9
# stage and its installed files copied into the final image — this avoids
# pulling a package manager, or its transitive attack surface, into the
# shipped image itself.
#
# curl was deliberately NOT added here: an earlier version of this
# Dockerfile installed it alongside jq, and Trivy flagged the ubi9-provided
# curl/libcurl package for 3 HIGH-severity CVEs with no fixed version yet
# available upstream (CVE-2026-11352, CVE-2026-11586, CVE-2026-8925).
# Nothing in this image actually needs curl, so the fix was to drop it
# rather than accept the exposure.
FROM registry.access.redhat.com/ubi9:9.4 AS tools-build
RUN mkdir -p /mnt/rootfs && \
    dnf install \
      --installroot /mnt/rootfs \
      --releasever 9 \
      --setopt install_weak_deps=false \
      --nodocs \
      -y \
      jq \
    && dnf clean all --installroot /mnt/rootfs

# Bouncy Castle override. Keycloak 26.7.4 (and 26.7.3) vendors Bouncy
# Castle 1.84, whose bcprov has CRITICAL CVE-2026-8763 (name-constraints
# bypass) and HIGH CVE-2026-13506, both fixed in 1.85; Quarkus 3.33.3.2's
# BOM still pins 1.84, so no Keycloak release carries the fix yet. The
# patched jars are fetched here, verified against pinned SHA-256 digests
# (cross-checked with Maven Central's published SHA-1), and swapped into
# the builder stage below. Remove this stage once upstream.lock.yaml pins
# a Keycloak release that vendors Bouncy Castle >= 1.85.
FROM registry.access.redhat.com/ubi9:9.4 AS bouncycastle
RUN set -eu; mkdir /bc; cd /bc; \
    m=https://repo1.maven.org/maven2/org/bouncycastle; \
    curl -fsSL -o bcprov.jar "$m/bcprov-jdk18on/1.85.2/bcprov-jdk18on-1.85.2.jar"; \
    curl -fsSL -o bcpkix.jar "$m/bcpkix-jdk18on/1.85/bcpkix-jdk18on-1.85.jar"; \
    curl -fsSL -o bcutil.jar "$m/bcutil-jdk18on/1.85/bcutil-jdk18on-1.85.jar"; \
    printf '%s  %s\n' \
      986b0fb92ec10e0c66b43e036ce0077e6150cfaecd1db9fb92b56672e157afe5 bcprov.jar \
      c9f82b2d4e99c4bbdfccf684e52cc06ea06a0b567bfd0d08f9c5a3f417055996 bcpkix.jar \
      590f55ed5d68529239898a4a5c4f730b6e37f45d1cfa3fbe51f8485abe32c42d bcutil.jar \
      | sha256sum --check --strict

# CVE-2026-84939 (CRITICAL, path traversal via a malformed locale
# identifier): Keycloak 26.7.4 vendors Apache FreeMarker 2.3.32, which
# renders every login, account and email template; the fix is 2.3.35. As
# with Bouncy Castle above, the fixed jar is fetched from Maven Central,
# verified against its pinned SHA-256 (cross-checked with Maven Central's
# published SHA-1, dd1d9737c3e8b8a5bf0d44981eb308df4822e241), and swapped
# into the builder stage below. Remove this stage once upstream.lock.yaml
# pins a Keycloak release that vendors FreeMarker >= 2.3.35.
FROM registry.access.redhat.com/ubi9:9.4 AS freemarker
RUN set -eu; mkdir /fm; cd /fm; \
    curl -fsSL -o freemarker.jar \
      https://repo1.maven.org/maven2/org/freemarker/freemarker/2.3.35/freemarker-2.3.35.jar; \
    printf '%s  %s\n' \
      0fac87dddd78f1223139e8ef88e819c7f483c0a3835cdf5982ad5e4576d1d896 freemarker.jar \
      | sha256sum --check --strict

FROM quay.io/keycloak/keycloak:26.7.4 AS builder

# The upstream image already switches to its non-root runtime user (see
# the final stage's own USER 1000 below), which this build stage inherits.
# COPY always creates root-owned files regardless of the current USER, so
# the chmod below would fail as a non-root, non-owning user ("Operation
# not permitted"). This stage is discarded after the build (multi-stage),
# so building it as root has no effect on the shipped runtime image, which
# still ends with USER 1000.
USER root

# Replace Keycloak's vendored Bouncy Castle 1.84 jars in place (see the
# bouncycastle stage above). Filenames are kept because Quarkus' fast-jar
# classpath references them by name and the final stage's COPY of
# /opt/keycloak would otherwise leave the base image's 1.84 files behind.
# The guard fails the build if Keycloak stops shipping exactly these jars,
# so this override is revisited rather than silently applied to new files.
RUN for f in lib/lib/main/org.bouncycastle.bcprov-jdk18on-1.84.jar \
             lib/lib/main/org.bouncycastle.bcpkix-jdk18on-1.84.jar \
             lib/lib/main/org.bouncycastle.bcutil-jdk18on-1.84.jar \
             bin/client/lib/bcprov-jdk18on-1.84.jar; do \
      test -f "/opt/keycloak/$f" || { echo "expected Keycloak jar $f is missing" >&2; exit 1; }; \
    done
COPY --from=bouncycastle /bc/bcprov.jar /opt/keycloak/lib/lib/main/org.bouncycastle.bcprov-jdk18on-1.84.jar
COPY --from=bouncycastle /bc/bcpkix.jar /opt/keycloak/lib/lib/main/org.bouncycastle.bcpkix-jdk18on-1.84.jar
COPY --from=bouncycastle /bc/bcutil.jar /opt/keycloak/lib/lib/main/org.bouncycastle.bcutil-jdk18on-1.84.jar
COPY --from=bouncycastle /bc/bcprov.jar /opt/keycloak/bin/client/lib/bcprov-jdk18on-1.84.jar

# Replace Keycloak's vendored FreeMarker 2.3.32 in place (see the
# freemarker stage above), keeping the filename for the same fast-jar
# classpath reason. The guard fails the build if Keycloak stops shipping
# exactly this jar, so the override is revisited rather than misapplied.
RUN test -f /opt/keycloak/lib/lib/main/org.freemarker.freemarker-2.3.32.jar \
    || { echo "expected Keycloak jar org.freemarker.freemarker-2.3.32.jar is missing" >&2; exit 1; }
COPY --from=freemarker /fm/freemarker.jar /opt/keycloak/lib/lib/main/org.freemarker.freemarker-2.3.32.jar

# Copy custom theme and providers (if any)
COPY themes/ /opt/keycloak/themes/
COPY providers/ /opt/keycloak/providers/

# Copy realm configuration and bootstrap script
COPY config/ /opt/keycloak/config/
COPY scripts/bootstrap.sh /opt/keycloak/bootstrap.sh
RUN chmod +x /opt/keycloak/bootstrap.sh

# `db` is a build-time option in Keycloak: an `--optimized` runtime start
# (see the final stage's CMD) skips re-augmentation and so ignores any
# `KC_DB` set only at runtime (docker-compose.yml's own `KC_DB: postgres`
# is therefore not enough by itself) — it must already be baked into this
# build. Without this, the container never reaches a running state: it
# silently keeps whatever `db` this build step defaulted to and never
# becomes healthy, which is what happened before this was added (the
# integration-test job's Keycloak container ran for 5 minutes without
# ever reaching /health/ready). Connection details (db-url/username/
# password) remain correctly runtime-only, set in docker-compose.yml.
ENV KC_DB=postgres

# `health-enabled` is ALSO a build-time option, and defaults to disabled —
# with it unset, no health endpoint answers on any port, build-time or
# runtime, which is why moving the wait loop to the management port
# (port 9000) alone did not fix readiness. Both this and KC_DB above must
# be set before `kc.sh build`, not just at runtime, because of --optimized
# (see the KC_DB comment above for why).
ENV KC_HEALTH_ENABLED=true

# Build the Keycloak distribution (optimized)
RUN /opt/keycloak/bin/kc.sh build

# Final stage – minimal distroless image
FROM quay.io/keycloak/keycloak:26.7.4
ARG VERSION=0.0.0-dev
ARG REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/baobab-platform/baobab-iam" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

# jq for bootstrap.sh (see tools-build stage above)
COPY --from=tools-build /mnt/rootfs /

# Copy the built distribution from builder
COPY --from=builder /opt/keycloak/ /opt/keycloak/

# Non‑root user (already set by upstream)
USER 1000

# Health checks
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD /opt/keycloak/bin/kc.sh health || exit 1

EXPOSE 8080
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized", "--http-enabled=true", "--hostname=localhost"]
