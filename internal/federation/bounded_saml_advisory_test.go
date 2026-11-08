package federation

import (
	"errors"
	"strings"
	"testing"
)

// This is a DENIAL-ONLY preflight. The positive control does not assert SAML
// authenticity; the maintained library still must verify the signed response.
func TestBoundedSAMLXMLRejectsForeignIssuerAndSubjectSubstitution(t *testing.T) {
	const header = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:foreign="urn:baobab:foreign">`
	const good = `<saml:Assertion><saml:Issuer>trusted-idp</saml:Issuer><saml:Subject><saml:NameID>subject</saml:NameID></saml:Subject><ds:Signature/></saml:Assertion>`
	if err := boundedSAMLXML(header + good + `</samlp:Response>`); err != nil {
		t.Fatalf("well-shaped (not verified) SAML fixture rejected: %v", err)
	}
	cases := []struct {
		name string
		body string
	}{
		{"no-issuer", `<saml:Assertion><saml:Subject><saml:NameID>subject</saml:NameID></saml:Subject><ds:Signature/></saml:Assertion>`,},
		{"sibling-issuer", `<Other><saml:Issuer>unrelated</saml:Issuer></Other><saml:Assertion><saml:Subject><saml:NameID>subject</saml:NameID></saml:Subject><ds:Signature/></saml:Assertion>`,},
		{"sibling-subject", `<Other><saml:Subject><saml:NameID>foreign</saml:NameID></saml:Subject></Other><saml:Assertion><saml:Issuer>trusted-idp</saml:Issuer><ds:Signature/></saml:Assertion>`,},
		{"foreign-nameid", `<saml:Assertion><saml:Issuer>trusted-idp</saml:Issuer><saml:Subject><foreign:NameID>spoofed</foreign:NameID></saml:Subject><ds:Signature/></saml:Assertion>`,},
		{"extra-nameid", `<saml:Assertion><saml:Issuer>trusted-idp</saml:Issuer><saml:Subject><saml:NameID>subject</saml:NameID><foreign:NameID>spoofed</foreign:NameID></saml:Subject><ds:Signature/></saml:Assertion>`,},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := boundedSAMLXML(header + tc.body + `</samlp:Response>`); err == nil {
				t.Fatal("invalid assertion structure unexpectedly passed denial-only SAML gate")
			}
		})
	}
}

// SAML verification must refuse malformed broker XML before touching the
// potentially nil upstream assertion.Issuer value.
func TestBoundedSAMLXMLRejectsMalformedRootAndEntity(t *testing.T) {
	for _, raw := range []string{
		"", strings.Repeat("x", 65537),
		`<Response><Assertion><Issuer>x</Issuer></Assertion></Response>`,
		`<!DOCTYPE Response [<!ENTITY x SYSTEM "file:///etc/passwd">]><Response>&x;</Response>`,
	} {
		if err := boundedSAMLXML(raw); err == nil {
			t.Fatalf("malformed or unsafe XML admitted (length=%d)", len(raw))
		} else if !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrDenied) && !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unexpected error for malformed XML: %v", err)
		}
	}
}
