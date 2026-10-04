// Package federation consumes the pinned Shared MP2 contracts. It owns no
// canonical identity, platform binding, entitlement or provider selection.
package federation

import "time"

// These wire records mirror Shared identity/v1. Existing OIDC assurance is
// preserved; SAML evidence is never converted into invented OIDC claims.
type Binding struct {
	ProviderID             string `json:"provider_id"`
	EngineInstanceID       string `json:"engine_instance_id"`
	ConfigurationReference string `json:"configuration_reference"`
	TrustMaterialReference string `json:"trust_material_reference"`
}
type Trust struct {
	ID                          string     `json:"id"`
	Protocol                    string     `json:"protocol"`
	UpstreamIssuer              string     `json:"upstream_issuer"`
	OrganisationIDs             []string   `json:"organisation_ids"`
	EstateIDs                   []string   `json:"estate_ids"`
	ProviderBinding             Binding    `json:"provider_binding"`
	Status                      string     `json:"status"`
	AssurancePolicyReference    string     `json:"assurance_policy_reference"`
	AttributeMappingReference   string     `json:"attribute_mapping_reference"`
	ProvisioningPolicyReference string     `json:"provisioning_policy_reference"`
	Revision                    uint64     `json:"revision"`
	CreatedAt                   time.Time  `json:"created_at"`
	UpdatedAt                   time.Time  `json:"updated_at"`
	ActivationEvidenceReference string     `json:"activation_evidence_reference,omitempty"`
	ActivatedAt                 *time.Time `json:"activated_at,omitempty"`
	RevokedAt                   *time.Time `json:"revoked_at,omitempty"`
}
type Resolution struct {
	Status             string     `json:"status"`
	PrincipalID        string     `json:"principal_id,omitempty"`
	ExternalIdentityID string     `json:"external_identity_id,omitempty"`
	MappingReference   string     `json:"mapping_reference,omitempty"`
	MappingBasis       string     `json:"mapping_basis,omitempty"`
	ResolvedAt         *time.Time `json:"resolved_at,omitempty"`
}
type ExternalPrincipal struct {
	AuthenticationEventID string     `json:"authentication_event_id"`
	TrustID               string     `json:"trust_id"`
	ProviderID            string     `json:"provider_id"`
	EngineInstanceID      string     `json:"engine_instance_id"`
	Protocol              string     `json:"protocol"`
	Issuer                string     `json:"issuer"`
	Subject               string     `json:"subject"`
	ActorType             string     `json:"actor_type"`
	ObservedAt            time.Time  `json:"observed_at"`
	ExpiresAt             time.Time  `json:"expires_at"`
	Resolution            Resolution `json:"resolution"`
}
type OIDCAssurance struct {
	ActorType       string     `json:"actor_type"`
	ACR             string     `json:"acr"`
	AMR             []string   `json:"amr,omitempty"`
	AuthenticatedAt time.Time  `json:"authenticated_at"`
	StepUpAt        *time.Time `json:"step_up_at,omitempty"`
	Issuer          string     `json:"issuer"`
	ClientID        string     `json:"client_id"`
}
type SAMLAssurance struct {
	AuthnContextClassRef string    `json:"authn_context_class_ref"`
	AuthenticatedAt      time.Time `json:"authenticated_at"`
	SessionExpiresAt     time.Time `json:"session_expires_at"`
}
type UpstreamEvidence struct {
	OIDC *OIDCAssurance `json:"oidc,omitempty"`
	SAML *SAMLAssurance `json:"saml,omitempty"`
}
type Assurance struct {
	AuthenticationEventID    string           `json:"authentication_event_id"`
	TrustID                  string           `json:"trust_id"`
	ProviderID               string           `json:"provider_id"`
	EngineInstanceID         string           `json:"engine_instance_id"`
	Protocol                 string           `json:"protocol"`
	Issuer                   string           `json:"issuer"`
	Subject                  string           `json:"subject"`
	UpstreamEvidence         UpstreamEvidence `json:"upstream_evidence"`
	MappingStatus            string           `json:"mapping_status"`
	Level                    string           `json:"level,omitempty"`
	AssurancePolicyReference string           `json:"assurance_policy_reference"`
	MappingEvidenceReference string           `json:"mapping_evidence_reference,omitempty"`
	EvaluatedAt              time.Time        `json:"evaluated_at"`
	ExpiresAt                time.Time        `json:"expires_at"`
}
type Bundle struct {
	Trust             Trust             `json:"trust"`
	ExternalPrincipal ExternalPrincipal `json:"external_principal"`
	Assurance         Assurance         `json:"assurance"`
}
