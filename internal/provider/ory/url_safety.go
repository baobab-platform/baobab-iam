package ory

import (
	"errors"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// validateProviderEndpoint rejects ambiguous endpoint configuration before an
// adapter can send privileged admin requests. Provider admin API URLs are
// origins; allowing paths, userinfo, or query parameters makes appended API
// routes ambiguous and may expose credentials.
//
// HTTP for admin endpoints remains supported for explicitly private Docker
// and service-network deployments. This parser does NOT establish private
// network placement, TLS termination, trust roots or runtime authorization;
// those remain separate deployment and CP evidence gates.
//
// OIDC issuers may legitimately contain a path and must remain byte-exact
// between provider tokens and ExternalIdentity mappings.
func validateProviderEndpoint(raw string, admin bool) error {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\\\r\n\t") {
		return errors.New("invalid provider endpoint")
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || !u.IsAbs() || u.Hostname() == "" ||
		(u.Scheme != "http" && u.Scheme != "https") ||
		u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || u.RawFragment != "" {
		return errors.New("invalid provider endpoint")
	}
	if admin && ((u.Path != "" && u.Path != "/") || u.RawPath != "") {
		return errors.New("admin endpoint must be a bare origin")
	}
	return nil
}

// validNativeIdentitySubject prevents an opaque external subject from being
// interpreted as a different Kratos Admin resource path. Kratos normally
// returns UUID subjects; do not require UUID here solely because migration
// fixtures and other compatible implementations use non-UUID opaque IDs.
// This is a routing boundary, not canonical-identity resolution.
func validNativeIdentitySubject(subject string) bool {
	if subject == "" || len(subject) > 255 || subject == "." || subject == ".." ||
		strings.TrimSpace(subject) != subject || !utf8.ValidString(subject) ||
		strings.ContainsAny(subject, "/\\?#%") {
		return false
	}
	for _, r := range subject {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
