# Providers

Custom Keycloak SPI extension JARs (per ADR-0002 Section 26-27's extension
preference hierarchy) live here.

This directory currently exists only so `Dockerfile`'s `COPY providers/
/opt/keycloak/providers/` has a source to copy — no custom provider has
been written yet, and per ADR-0002 the preference is to avoid one unless a
requirement cannot be met by native Keycloak configuration. Any provider
added here SHALL have automated tests, a documented supported Keycloak
version range, and an explicit owner (ADR-0002 Section 27).
