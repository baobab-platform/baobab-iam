package federation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"io"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/crewjam/saml"
	jose "github.com/go-jose/go-jose/v4"
)

type brokerIDToken struct {
	Subject, EvidenceDigest    string
	AuthenticatedAt, ExpiresAt time.Time
	ACR                        string
	AMR                        []string
}

func verifyBrokerIDToken(ctx context.Context, issuer string, c OIDCConfiguration, raw, nonceDigest string, created, now time.Time, lifetime time.Duration) (brokerIDToken, error) {
	if len(raw) == 0 || len(raw) > 32768 || !exact(c.ClientID) || !now.Before(c.ValidUntil) {
		return brokerIDToken{}, ErrDenied
	}
	keys, err := publicOIDCKeys(c)
	if err != nil {
		return brokerIDToken{}, err
	}
	signed, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(c.SigningAlgorithm)})
	if err != nil || len(signed.Signatures) != 1 {
		return brokerIDToken{}, ErrDenied
	}
	if typ, ok := signed.Signatures[0].Header.ExtraHeaders[jose.HeaderType]; ok && typ != "JWT" {
		return brokerIDToken{}, ErrDenied
	}
	verifier := oidc.NewVerifier(issuer, &oidc.StaticKeySet{PublicKeys: keys}, &oidc.Config{ClientID: c.ClientID, SupportedSigningAlgs: []string{c.SigningAlgorithm}, Now: func() time.Time { return now }})
	token, err := verifier.Verify(ctx, raw)
	if err != nil {
		return brokerIDToken{}, ErrDenied
	}
	var payload json.RawMessage
	if token.Claims(&payload) != nil {
		return brokerIDToken{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if uniqueJSON(decoder) != nil {
		return brokerIDToken{}, ErrInvalid
	}
	if _, err = decoder.Token(); err != io.EOF {
		return brokerIDToken{}, ErrInvalid
	}
	var claims struct {
		AZP            string   `json:"azp"`
		AuthTime       int64    `json:"auth_time"`
		NBF            int64    `json:"nbf"`
		ACR            string   `json:"acr"`
		AMR            []string `json:"amr"`
		Type           string   `json:"typ"`
		EvidenceDigest string   `json:"baobab_upstream_evidence_digest"`
	}
	if token.Claims(&claims) != nil {
		return brokerIDToken{}, ErrInvalid
	}
	authenticated := time.Unix(claims.AuthTime, 0).UTC()
	if token.Issuer != issuer || !exact(token.Subject) || len(token.Audience) != 1 || token.Audience[0] != c.ClientID || claims.AZP != "" && claims.AZP != c.ClientID || claims.Type != "" && claims.Type != "ID" || !equalSecret(token.Nonce, nonceDigest) || !now.Before(token.Expiry) || token.IssuedAt.IsZero() || token.IssuedAt.After(now) || token.IssuedAt.Before(created.Add(-time.Second)) || token.Expiry.Sub(token.IssuedAt) > lifetime || claims.AuthTime <= 0 || authenticated.After(token.IssuedAt) || now.Sub(authenticated) > lifetime || claims.NBF > now.Unix() {
		return brokerIDToken{}, ErrDenied
	}
	return brokerIDToken{token.Subject, claims.EvidenceDigest, authenticated, token.Expiry, claims.ACR, claims.AMR}, nil
}

// QualifiedSAMLSubject preserves persistent NameID semantics across SPs. CP
// maps this opaque deterministic key; no email or broker-local ID is substituted.
func QualifiedSAMLSubject(issuer, entityID, value string) string {
	encoded, _ := json.Marshal([]string{"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", issuer, entityID, value})
	sum := sha256.Sum256(encoded)
	return "saml2:persistent:" + hex.EncodeToString(sum[:])
}

// SAML structural checks restrict the supported profile before the maintained
// verifier performs signature and protocol validation. No network metadata,
// artifacts, encrypted assertions, external references or weak algorithms.
func boundedSAMLXML(raw string) error {
	if len(raw) == 0 || len(raw) > 65536 {
		return ErrInvalid
	}
	decoder := xml.NewDecoder(bytes.NewBufferString(raw))
	depth, count, assertions, signatures, roots := 0, 0, 0, 0, 0
	ids := map[string]bool{}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ErrInvalid
		}
		count++
		if count > 12000 {
			return ErrInvalid
		}
		switch t := token.(type) {
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(t)) != "" {
				return ErrInvalid
			}
		case xml.Directive:
			return ErrDenied
		case xml.StartElement:
			depth++
			if depth == 1 {
				roots++
			}
			if depth > 32 {
				return ErrInvalid
			}
			if depth == 1 && (t.Name.Space != "urn:oasis:names:tc:SAML:2.0:protocol" || t.Name.Local != "Response") {
				return ErrDenied
			}
			if t.Name.Space == "urn:oasis:names:tc:SAML:2.0:assertion" && t.Name.Local == "Assertion" {
				assertions++
				if depth != 2 {
					return ErrDenied
				}
			}
			if t.Name.Local == "EncryptedAssertion" {
				return ErrUnsupported
			}
			for _, a := range t.Attr {
				if a.Name.Local == "ID" {
					if a.Value == "" || ids[a.Value] {
						return ErrDenied
					}
					ids[a.Value] = true
				}
			}
			if t.Name.Space == "http://www.w3.org/2000/09/xmldsig#" {
				if t.Name.Local == "Signature" {
					signatures++
					if depth != 2 && depth != 3 {
						return ErrDenied
					}
				}
				for _, a := range t.Attr {
					if t.Name.Local == "SignatureMethod" && a.Name.Local == "Algorithm" && a.Value != "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" && a.Value != "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" {
						return ErrUnsupported
					}
					if t.Name.Local == "DigestMethod" && a.Name.Local == "Algorithm" && a.Value != "http://www.w3.org/2001/04/xmlenc#sha256" {
						return ErrUnsupported
					}
					if t.Name.Local == "Reference" && a.Name.Local == "URI" && (len(a.Value) < 2 || a.Value[0] != '#') {
						return ErrDenied
					}
				}
			}
		case xml.EndElement:
			depth--
		}
	}
	if depth != 0 || roots != 1 || assertions != 1 || signatures < 1 || signatures > 2 {
		return ErrDenied
	}
	return nil
}

func verifyBrokerSAML(s TrustSnapshot, c BrokerConfiguration, raw, requestID string, created, now time.Time, lifetime time.Duration) (ExternalPrincipal, Assurance, string, error) {
	if !exact(requestID) || len(c.SigningCertificates) < 1 || len(c.SigningCertificates) > 8 || !exact(c.SAML.EntityID) {
		return ExternalPrincipal{}, Assurance{}, "", ErrInvalid
	}
	if err := boundedSAMLXML(raw); err != nil {
		return ExternalPrincipal{}, Assurance{}, "", err
	}
	var envelope struct {
		Assertion *saml.Assertion `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	}
	if xml.Unmarshal([]byte(raw), &envelope) != nil || envelope.Assertion == nil || envelope.Assertion.Subject == nil || envelope.Assertion.Conditions == nil || envelope.Assertion.Subject.NameID == nil || len(envelope.Assertion.Subject.SubjectConfirmations) != 1 || envelope.Assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData == nil {
		return ExternalPrincipal{}, Assurance{}, "", ErrDenied
	}
	acs, err := brokerURL(c.SAML.ACSURL, false)
	if err != nil {
		return ExternalPrincipal{}, Assurance{}, "", err
	}
	certificates, err := samlSigningCertificates(c.SigningCertificates, now)
	if err != nil {
		return ExternalPrincipal{}, Assurance{}, "", err
	}
	var assertion *saml.Assertion
	for _, cert := range certificates {
		der := base64.StdEncoding.EncodeToString(cert.Raw)
		sp := saml.ServiceProvider{EntityID: c.SAML.EntityID, AcsURL: *acs, IDPMetadata: &saml.EntityDescriptor{EntityID: s.Trust.UpstreamIssuer}, IDPCertificate: &der}
		candidate, e := sp.ParseXMLResponse([]byte(raw), []string{requestID}, *acs)
		if e == nil {
			assertion = candidate
			break
		}
	}
	// Library errors contain original XML; never return/log them.
	if assertion == nil || assertion.Subject == nil || assertion.Subject.NameID == nil || assertion.Conditions == nil || assertion.Issuer.Value != s.Trust.UpstreamIssuer || len(assertion.AuthnStatements) != 1 || len(assertion.Subject.SubjectConfirmations) != 1 || len(assertion.Conditions.AudienceRestrictions) != 1 {
		return ExternalPrincipal{}, Assurance{}, "", ErrDenied
	}
	name := assertion.Subject.NameID
	conditions := assertion.Conditions
	statement := assertion.AuthnStatements[0]
	confirmation := assertion.Subject.SubjectConfirmations[0]
	if name.Format != "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" || !exact(name.Value) || name.SPProvidedID != "" || name.NameQualifier != "" && name.NameQualifier != s.Trust.UpstreamIssuer || name.SPNameQualifier != "" && name.SPNameQualifier != c.SAML.EntityID || conditions.AudienceRestrictions[0].Audience.Value != c.SAML.EntityID || confirmation.Method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" || confirmation.SubjectConfirmationData.InResponseTo != requestID || confirmation.SubjectConfirmationData.Recipient != c.SAML.ACSURL || !now.Before(confirmation.SubjectConfirmationData.NotOnOrAfter) || conditions.NotBefore.After(now) || !now.Before(conditions.NotOnOrAfter) || conditions.NotOnOrAfter.Sub(conditions.NotBefore) > lifetime || assertion.IssueInstant.After(now) || assertion.IssueInstant.Before(created.Add(-time.Second)) || statement.AuthnInstant.IsZero() || statement.AuthnInstant.After(now) || now.Sub(statement.AuthnInstant) > lifetime || statement.SessionNotOnOrAfter == nil || !now.Before(*statement.SessionNotOnOrAfter) || statement.AuthnContext.AuthnContextClassRef == nil || !exact(statement.AuthnContext.AuthnContextClassRef.Value) {
		return ExternalPrincipal{}, Assurance{}, "", ErrDenied
	}
	until := minimum(c.ValidUntil, s.ValidUntil, conditions.NotOnOrAfter, confirmation.SubjectConfirmationData.NotOnOrAfter, *statement.SessionNotOnOrAfter, now.Add(lifetime))
	p := ExternalPrincipal{TrustID: s.Trust.ID, ProviderID: c.Binding.ProviderID, EngineInstanceID: c.Binding.EngineInstanceID, Protocol: "SAML2", Issuer: s.Trust.UpstreamIssuer, Subject: QualifiedSAMLSubject(s.Trust.UpstreamIssuer, c.SAML.EntityID, name.Value), ActorType: "human", ObservedAt: now, ExpiresAt: until, Resolution: Resolution{Status: "UNRESOLVED"}}
	a := Assurance{TrustID: p.TrustID, ProviderID: p.ProviderID, EngineInstanceID: p.EngineInstanceID, Protocol: p.Protocol, Issuer: p.Issuer, Subject: p.Subject, UpstreamEvidence: UpstreamEvidence{SAML: &SAMLAssurance{AuthnContextClassRef: statement.AuthnContext.AuthnContextClassRef.Value, AuthenticatedAt: statement.AuthnInstant, SessionExpiresAt: *statement.SessionNotOnOrAfter}}, MappingStatus: "UNKNOWN", AssurancePolicyReference: s.Trust.AssurancePolicyReference, EvaluatedAt: now, ExpiresAt: until}
	return p, a, s.Trust.UpstreamIssuer + "\x00" + assertion.ID, nil
}

// Readiness and capture use the same bounded, current signing-certificate profile.
func samlSigningCertificates(encodedCertificates []string, now time.Time) ([]*x509.Certificate, error) {
	if len(encodedCertificates) < 1 || len(encodedCertificates) > 8 {
		return nil, ErrInvalid
	}
	var certificates []*x509.Certificate

	for _, encoded := range encodedCertificates {
		block, rest := pem.Decode([]byte(encoded))
		if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, ErrInvalid
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrInvalid
		}
		if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			continue
		}
		if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return nil, ErrInvalid
		}
		switch key := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			if key.N.BitLen() < 2048 || key.E < 65537 {
				return nil, ErrInvalid
			}
		case *ecdsa.PublicKey:
			if key.Curve != elliptic.P256() {
				return nil, ErrInvalid
			}
		default:
			return nil, ErrUnsupported
		}
		certificates = append(certificates, cert)
	}
	if len(certificates) == 0 {
		return nil, ErrUnverified
	}
	return certificates, nil
}
