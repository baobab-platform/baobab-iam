package ory

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// newNativeProviderHTTPClient is a privileged Kratos/Hydra HTTP boundary.
// No ambient HTTP(S)_PROXY, custom socket dialer, arbitrary RoundTripper,
// TLS verification bypass or application-supplied redirect policy may
// intercept a native session credential or an admin OAuth request.
// A caller-supplied *http.Transport is allowed only for an explicitly
// trusted additional CA pool and other non-bypassing transport settings.
func newNativeProviderHTTPClient(configured *http.Client) (*http.Client, error) {
	base := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
	}
	if configured != nil && configured.Transport != nil {
		source, ok := configured.Transport.(*http.Transport)
		if !ok || source == nil ||
			source.Proxy != nil || source.Dial != nil || source.DialContext != nil ||
			source.DialTLS != nil || source.DialTLSContext != nil ||
			len(source.TLSNextProto) != 0 {
			return nil, fmt.Errorf("native provider transport cannot override trusted routing")
		}
		base = source.Clone()
		base.Proxy = nil
		if base.TLSClientConfig == nil {
			base.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		} else {
			config := base.TLSClientConfig.Clone()
			if config.InsecureSkipVerify || config.ServerName != "" ||
				config.VerifyPeerCertificate != nil || config.VerifyConnection != nil ||
				config.GetClientCertificate != nil || config.GetConfigForClient != nil ||
				config.KeyLogWriter != nil || len(config.Certificates) != 0 ||
				config.Renegotiation != tls.RenegotiateNever ||
				config.MinVersion != 0 && config.MinVersion < tls.VersionTLS12 ||
				config.MaxVersion != 0 && config.MaxVersion < tls.VersionTLS12 ||
				len(config.CipherSuites) != 0 {
				return nil, fmt.Errorf("native provider transport TLS trust policy denied")
			}
			config.MinVersion = tls.VersionTLS12
			if config.RootCAs != nil {
				config.RootCAs = config.RootCAs.Clone()
			}
			base.TLSClientConfig = config
		}
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: base,
	}, nil
}
