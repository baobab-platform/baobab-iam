package workloadresource

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// CPBindingTarget is an exact, reviewed resource deployment input. It must be
// obtained from CP-governed registration; values from a token, HTTP request,
// tenant claim or provider self-description are never authoritative.
type CPBindingTarget struct {
	ProviderID              string
	EngineInstanceID        string
	OrganisationID          string
	EstateID                string
	ConfigurationReference  string
	SecurityDomainReference string
}

// CPRegistrationToken obtains a separately registered CP identity-runtime:read
// workload credential from the trusted service secret boundary on every call.
type CPRegistrationToken func(context.Context) (string, error)

type CPRegisteredBinding struct {
	endpoint string
	target   CPBindingTarget
	token    CPRegistrationToken
	client   *http.Client
}

var (
	providerIdentifier  = regexp.MustCompile(`^provider_[a-z0-9]+package workloadresource

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// CPBindingTarget is an exact, reviewed resource deployment input. It must be
// obtained from CP-governed registration; values from a token, HTTP request,
// tenant claim or provider self-description are never authoritative.
type CPBindingTarget struct {
	ProviderID              string
	EngineInstanceID        string
	OrganisationID          string
	EstateID                string
	ConfigurationReference  string
	SecurityDomainReference string
}

// CPRegistrationToken obtains a separately registered CP identity-runtime:read
// workload credential from the trusted service secret boundary on every call.
type CPRegistrationToken func(context.Context) (string, error)

type CPRegisteredBinding struct {
	endpoint string
	target   CPBindingTarget
	token    CPRegistrationToken
	client   *http.Client
}

)
	instanceIdentifier  = regexp.MustCompile(`^ei_[a-z0-9]+package workloadresource

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// CPBindingTarget is an exact, reviewed resource deployment input. It must be
// obtained from CP-governed registration; values from a token, HTTP request,
// tenant claim or provider self-description are never authoritative.
type CPBindingTarget struct {
	ProviderID              string
	EngineInstanceID        string
	OrganisationID          string
	EstateID                string
	ConfigurationReference  string
	SecurityDomainReference string
}

// CPRegistrationToken obtains a separately registered CP identity-runtime:read
// workload credential from the trusted service secret boundary on every call.
type CPRegistrationToken func(context.Context) (string, error)

type CPRegisteredBinding struct {
	endpoint string
	target   CPBindingTarget
	token    CPRegistrationToken
	client   *http.Client
}

)
	orgIdentifier       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}package workloadresource

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// CPBindingTarget is an exact, reviewed resource deployment input. It must be
// obtained from CP-governed registration; values from a token, HTTP request,
// tenant claim or provider self-description are never authoritative.
type CPBindingTarget struct {
	ProviderID              string
	EngineInstanceID        string
	OrganisationID          string
	EstateID                string
	ConfigurationReference  string
	SecurityDomainReference string
}

// CPRegistrationToken obtains a separately registered CP identity-runtime:read
// workload credential from the trusted service secret boundary on every call.
type CPRegistrationToken func(context.Context) (string, error)

type CPRegisteredBinding struct {
	endpoint string
	target   CPBindingTarget
	token    CPRegistrationToken
	client   *http.Client
}

)
	estateIdentifier    = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*package workloadresource

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// CPBindingTarget is an exact, reviewed resource deployment input. It must be
// obtained from CP-governed registration; values from a token, HTTP request,
// tenant claim or provider self-description are never authoritative.
type CPBindingTarget struct {
	ProviderID              string
	EngineInstanceID        string
	OrganisationID          string
	EstateID                string
	ConfigurationReference  string
	SecurityDomainReference string
}

// CPRegistrationToken obtains a separately registered CP identity-runtime:read
// workload credential from the trusted service secret boundary on every call.
type CPRegistrationToken func(context.Context) (string, error)

type CPRegisteredBinding struct {
	endpoint string
	target   CPBindingTarget
	token    CPRegistrationToken
	client   *http.Client
}

)
	referenceIdentifier = regexp.MustCompile(`^ref_[a-z0-9]+package workloadresource

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// CPBindingTarget is an exact, reviewed resource deployment input. It must be
// obtained from CP-governed registration; values from a token, HTTP request,
// tenant claim or provider self-description are never authoritative.
type CPBindingTarget struct {
	ProviderID              string
	EngineInstanceID        string
	OrganisationID          string
	EstateID                string
	ConfigurationReference  string
	SecurityDomainReference string
}

// CPRegistrationToken obtains a separately registered CP identity-runtime:read
// workload credential from the trusted service secret boundary on every call.
type CPRegistrationToken func(context.Context) (string, error)

type CPRegisteredBinding struct {
	endpoint string
	target   CPBindingTarget
	token    CPRegistrationToken
	client   *http.Client
}

)
)
var artifactDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func validCPBindingTarget(t CPBindingTarget) bool {
	return len(t.ProviderID) >= 10 && len(t.ProviderID) <= 63 && providerIdentifier.MatchString(t.ProviderID) &&
		len(t.EngineInstanceID) >= 6 && len(t.EngineInstanceID) <= 63 && instanceIdentifier.MatchString(t.EngineInstanceID) &&
		orgIdentifier.MatchString(t.OrganisationID) &&
		len(t.EstateID) >= 3 && len(t.EstateID) <= 63 && estateIdentifier.MatchString(t.EstateID) &&
		len(t.ConfigurationReference) >= 8 && len(t.ConfigurationReference) <= 63 && referenceIdentifier.MatchString(t.ConfigurationReference) &&
		len(t.SecurityDomainReference) >= 8 && len(t.SecurityDomainReference) <= 63 && referenceIdentifier.MatchString(t.SecurityDomainReference)
}

// NewCPRegisteredBinding is an ADAPTER to CP's already implemented
// POST /internal/identity-runtime/v1/binding read. It cannot create a provider,
// modify lifecycle, certify evidence or activate a capability. CP itself checks
// current registered reader scope, approved grant and source provenance.
func NewCPRegisteredBinding(origin string, roots *x509.CertPool, target CPBindingTarget,
	token CPRegistrationToken) (*CPRegisteredBinding, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" ||
		u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" ||
		token == nil || !validCPBindingTarget(target) {
		return nil, ErrDenied
	}
	return &CPRegisteredBinding{
		endpoint: origin + "/internal/identity-runtime/v1/binding",
		target:   target,
		token:    token,
		client: &http.Client{
			Timeout: 8 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				Proxy: nil,
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12, RootCAs: roots,
				},
			},
		},
	}, nil
}

type cpBindingSnapshot struct {
	ProviderID             string    `json:"provider_id"`
	EngineInstanceID       string    `json:"engine_instance_id"`
	Scope                  struct {
		OrganisationID string `json:"organisation_id"`
		EstateID       string `json:"estate_id"`
	} `json:"scope"`
	ProviderStatus         string    `json:"provider_status"`
	InstanceStatus         string    `json:"instance_status"`
	BindingStatus          string    `json:"binding_status"`
	RuntimeCapability      string    `json:"runtime_capability"`
	SupportStatus          string    `json:"support_status"`
	ArtifactDigest         string    `json:"artifact_digest"`
	DeployedArtifactDigest string    `json:"deployed_artifact_digest"`
	ProfileRevision        uint64    `json:"profile_revision"`
	EvidenceExpiresAt      time.Time `json:"evidence_expires_at"`
	ConfigurationReference string    `json:"configuration_reference"`
	SecurityDomainReference string   `json:"security_domain_reference"`
}

// CheckCapability re-reads the exact CP-owned registration every time.
// Missing permission, current support, binding, matching artifact, revision,
// valid evidence, or a network timeout causes DENY (not a cached fallback).
func (b *CPRegisteredBinding) CheckCapability(ctx context.Context, capability string) error {
	if b == nil || b.client == nil || ctx == nil || ctx.Err() != nil ||
		capability != WorkloadIssueCapability {
		return ErrDenied
	}
	secret, err := b.token(ctx)
	if err != nil || len(secret) < 20 || len(secret) > 16384 ||
		secret != strings.TrimSpace(secret) || strings.ContainsAny(secret, " \r\n\t,") {
		return ErrDenied
	}
	t := b.target
	raw, err := json.Marshal(struct {
		ProviderID              string `json:"provider_id"`
		EngineInstanceID        string `json:"engine_instance_id"`
		OrganisationID          string `json:"organisation_id"`
		EstateID                string `json:"estate_id"`
		RuntimeCapability       string `json:"runtime_capability"`
		ConfigurationReference  string `json:"configuration_reference"`
		SecurityDomainReference string `json:"security_domain_reference"`
	}{t.ProviderID, t.EngineInstanceID, t.OrganisationID, t.EstateID,
		"WORKLOAD_TOKEN_ISSUANCE", t.ConfigurationReference, t.SecurityDomainReference})
	if err != nil {
		return ErrDenied
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint, bytes.NewReader(raw))
	if err != nil {
		return ErrDenied
	}
	request.Header.Set("Authorization", "Bearer "+secret)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	result, err := b.client.Do(request)
	if err != nil {
		return ErrDenied
	}
	defer result.Body.Close()
	if result.StatusCode != http.StatusOK || result.Header.Get("Cache-Control") != "no-store" {
		return ErrDenied
	}
	body, err := io.ReadAll(io.LimitReader(result.Body, 8193))
	if err != nil || len(body) > 8192 {
		return ErrDenied
	}
	if _, err := decodeUnique(body); err != nil {
		return ErrDenied
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var observed cpBindingSnapshot
	if decoder.Decode(&observed) != nil {
		return ErrDenied
	}
	if _, err = decoder.Token(); err != io.EOF {
		return ErrDenied
	}
	now := time.Now().UTC()
	if ctx.Err() != nil || observed.ProviderID != t.ProviderID ||
		observed.EngineInstanceID != t.EngineInstanceID ||
		observed.Scope.OrganisationID != t.OrganisationID ||
		observed.Scope.EstateID != t.EstateID ||
		observed.RuntimeCapability != "WORKLOAD_TOKEN_ISSUANCE" ||
		observed.ConfigurationReference != t.ConfigurationReference ||
		observed.SecurityDomainReference != t.SecurityDomainReference ||
		observed.ProviderStatus != "ACTIVE" ||
		observed.InstanceStatus != "ACTIVE" ||
		observed.BindingStatus != "ACTIVE" ||
		observed.SupportStatus != "VERIFIED" ||
		observed.ProfileRevision == 0 ||
		!artifactDigest.MatchString(observed.ArtifactDigest) ||
		observed.ArtifactDigest != observed.DeployedArtifactDigest ||
		!now.Before(observed.EvidenceExpiresAt) {
		return ErrDenied
	}
	return nil
}

var _ RegisteredProviderAuthority = (*CPRegisteredBinding)(nil)
