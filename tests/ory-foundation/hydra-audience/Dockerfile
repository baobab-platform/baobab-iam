# Reuse the reviewed trust bundle and nonroot account, without unused OS libraries.
FROM oryd/hydra:v26.2.0@sha256:ff67c7fb5f95074fa53374d41151713554960504b340cd3f95b09e65deaea2a9 AS runtime-assets
FROM scratch
COPY --from=runtime-assets /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=runtime-assets /etc/passwd /etc/passwd
COPY --from=runtime-assets /etc/group /etc/group
COPY hydra /usr/bin/hydra
USER 65532:65532
EXPOSE 4444 4445
ENTRYPOINT ["/usr/bin/hydra"]
CMD ["serve", "all"]
LABEL org.baobab.acceptance="isolated-candidate" \
      org.baobab.hydra.base="0b84568fffccf151dc5e6c7955fdfb738555bf4b" \
      org.baobab.hydra.fix="92bd3eab9864453d72edc3d0bc51f004ff986c06"
