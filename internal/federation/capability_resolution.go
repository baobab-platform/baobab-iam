package federation

import (
	"context"
	"regexp"
	"strings"
	"time"
)

// CapabilityResolution mirrors the pinned Shared capability/v1 resolution.
// Only CP produces it. It is not a provider registry or a login-discovery result.
type CapabilityResolution struct {
	ResolutionID    string                `json:"resolution_id"`
	ContextID       string                `json:"context_id"`
	CapabilityKey   string                `json:"capability_key"`
	ContractVersion int                   `json:"contract_version,omitempty"`
	Decision        string                `json:"decision"`
	ReasonCode      string                `json:"reason_code,omitempty"`
	GrantID         string                `json:"grant_id,omitempty"`
	BindingID       string                `json:"binding_id,omitempty"`
	Invocation      *CapabilityInvocation `json:"invocation,omitempty"`
	ResolvedAt      time.Time             `json:"resolved_at"`
	ExpiresAt       *time.Time            `json:"expires_at,omitempty"`
	CorrelationID   string                `json:"correlation_id"`
}

type CapabilityInvocation struct {
	ServiceReference string `json:"service_reference"`
	Protocol         string `json:"protocol"`
	ContractVersion  int    `json:"contract_version"`
	ProviderID       string `json:"provider_id"`
	EngineInstanceID string `json:"engine_instance_id"`
}

type CapabilityRequest struct {
	CapabilityKey           string `json:"capability_key"`
	RequiredContractVersion int    `json:"required_contract_version"`
	ContextID               string `json:"context_id"`
	CorrelationID           string `json:"correlation_id"`
}

type CapabilityResolver interface {
	ResolveCapability(context.Context, CapabilityRequest) (CapabilityResolution, error)
}

// ResolveCapability redeems a context belonging to THIS transport's workload
// principal. CP independently verifies canonical ownership, bounded context,
// grant, support, binding, health and existing policy. BFF contexts are not transferable.
func (a *HTTPAuthority) ResolveCapability(ctx context.Context, request CapabilityRequest) (CapabilityResolution, error) {
	if runtimeFacet(request.CapabilityKey) == "" || request.RequiredContractVersion != 1 ||
		!validResolutionContextID(request.ContextID) || !uuidPattern.MatchString(request.CorrelationID) {
		return CapabilityResolution{}, ErrInvalid
	}
	var out CapabilityResolution
	if err := a.call(ctx, "/v1/capabilities/resolve", request, &out); err != nil {
		return CapabilityResolution{}, err
	}
	return out, nil
}

var capabilityIDPattern = regexp.MustCompile(`^(res|grant|bind)_[a-z0-9]+$`)

func validCapabilityID(value, prefix string) bool {
	return len(value) >= 6 && len(value) <= 63 && strings.HasPrefix(value, prefix+"_") && capabilityIDPattern.MatchString(value)
}

func validResolutionContextID(value string) bool {
	return value != "" && len(value) <= 512 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t ")
}

var _ CapabilityResolver = (*HTTPAuthority)(nil)
