# Inherit the reviewed runtime; replace only the source-built Hydra executable.
FROM oryd/hydra:v26.2.0@sha256:ff67c7fb5f95074fa53374d41151713554960504b340cd3f95b09e65deaea2a9
COPY hydra /usr/bin/hydra
LABEL org.baobab.acceptance="isolated-candidate" \
      org.baobab.hydra.base="0b84568fffccf151dc5e6c7955fdfb738555bf4b" \
      org.baobab.hydra.fix="92bd3eab9864453d72edc3d0bc51f004ff986c06"
