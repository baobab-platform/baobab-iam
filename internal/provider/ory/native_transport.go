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
// A caller-supplied *http.Transport can supply a trust pool and stricter
// TLS versions. The native client owns routing and HTTP behavior.
func newNativeProviderHTTPClient(configured *http.Client) (*http.Client, error) {
	base := &http.Transport{
		Proxy:             nil,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
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
		if config := source.TLSClientConfig; config != nil {
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
			base.TLSClientConfig.MinVersion = max(config.MinVersion, tls.VersionTLS12)
			base.TLSClientConfig.MaxVersion = config.MaxVersion
			if config.RootCAs != nil {
				base.TLSClientConfig.RootCAs = config.RootCAs.Clone()
			}
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
