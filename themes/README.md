# Themes

The realm selects `baobab` for login and account. Its packaged theme types
inherit the maintained `keycloak.v2` login and `keycloak.v3` account console
bundled with the pinned Keycloak image. No templates, scripts, authentication
flow or MFA policy are overridden. Future branding remains presentation only
under ADR-0002 §28 and must preserve upstream security and accessibility.

This closes the missing-theme source defect recorded in Gate IAM-14 §5.
`scripts/check_theme_inventory.py` and its negative regressions run in CI to
prevent selecting a custom theme type that the image never packages. Actual
human code/PKCE and MFA interoperability remain Infrastructure INT-02 evidence;
a source inventory check does not establish that live acceptance.
