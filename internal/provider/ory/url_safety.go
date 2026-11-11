package ory

import (
	"errors"
	"net/url"
	"strings"
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
// An empty fragment delimiter (#) and trailing empty port (:) are ambiguous\n// yet accepted by net/url.Parse. Reject them before constructing HTTP paths.\n//\n// OIDC issuers may legitimately contain a path and must remain byte-exact
// between provider tokens and ExternalIdentity mappings.
func validateProviderEndpoint(raw string, admin bool) error {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\\\r\n\t") || strings.Contains(raw, "#") {
		return errors.New("invalid provider endpoint")
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || !u.IsAbs() || u.Hostname() == "" || strings.HasSuffix(u.Host, ":") ||
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
