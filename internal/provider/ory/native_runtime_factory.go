package ory

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/baobab-platform/baobab-iam/internal/federation"
)

// StartNativeHumanRuntime is the production host's composition factory. It
// supplies both current Kratos and Hydra authority to EVERY login/consent check,
// including the mechanics' final check before burning the challenge. The caller
// owns the service context and must cancel it and join the returned supervisor.
// This factory creates no HTTP endpoint, browser transaction, grant or audience.
func StartNativeHumanRuntime(ctx context.Context, c NativeHumanConfig, human, issuer federation.RuntimeComposition, tlsConfig *tls.Config) (*GovernedNativeHumanHandoff, *federation.SupervisedContexts, error) {
	if c.AllowLoopbackHTTP {
		return nil, nil, fmt.Errorf("production native runtime requires TLS")
	}
	// Own provider transport as well as CP transport. Production cannot inherit
	// proxy-environment routing, an insecure test transport or custom TLS hooks.
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	if c.Client != nil && c.Client.Transport != nil {
		configured, ok := c.Client.Transport.(*http.Transport)
		if !ok || configured.DialTLS != nil || configured.DialTLSContext != nil {
			return nil, nil, fmt.Errorf("verified native provider TLS required")
		}
		transport = configured.Clone()
		if transport.TLSClientConfig != nil {
			tc := transport.TLSClientConfig.Clone()
			if tc.ServerName != "" || tc.InsecureSkipVerify || tc.KeyLogWriter != nil || tc.VerifyConnection != nil || tc.VerifyPeerCertificate != nil {
				return nil, nil, fmt.Errorf("verified native provider TLS required")
			}
			if tc.MinVersion < tls.VersionTLS12 {
				tc.MinVersion = tls.VersionTLS12
			}
			if tc.MaxVersion != 0 && tc.MaxVersion < tc.MinVersion {
				return nil, nil, fmt.Errorf("verified native provider TLS required")
			}
			transport.TLSClientConfig = tc
		} else {
			transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
	}
	transport.Proxy = nil
	c.Client = &http.Client{Transport: transport}
	// Validate mechanics first: a bad issuer/URL/fence must not start renewal.
	if _, err := NewNativeHumanHandoff(c); err != nil {
		return nil, nil, err
	}
	authority, supervisor, err := federation.StartNativeRuntimeComposition(ctx, human, issuer, tlsConfig)
	if err != nil {
		return nil, nil, err
	}
	handoff, err := NewGovernedNativeHumanHandoff(c, authority)
	// The same immutable mechanics already validated above, so construction has no
	// remaining external failure path. Ownership remains with the service context.
	return handoff, supervisor, err
}
