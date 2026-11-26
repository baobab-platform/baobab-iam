package federation

import (
	"errors"
	"strings"
	"testing"

	"github.com/supatype/saml"
)

// The structural guard does not try to establish a signature. Its job is to
// refuse ambiguous XML and namespace-blind subject substitution *before*
// calling the external signature/protocol verifier.
func TestBrokerSAMLStructuralGuardRejectsNamespaceBlindNameIDAndDuplicateSubjects(t *testing.T) {
	const canonical = `<p:Response xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol"
 xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion"
 xmlns:d="http://www.w3.org/2000/09/xmldsig#"
 xmlns:x="urn:attacker:namespace">
 <a:Assertion ID="assertion-1">
  <a:Subject><a:NameID>approved-human</a:NameID></a:Subject>
  <a:Conditions/>
  <d:Signature/>
 </a:Assertion>
</p:Response>`
	if err := boundedSAMLXML(canonical); err != nil {
		t.Fatalf("valid structural profile rejected: %v", err)
	}
	for name, raw := range map[string]string{
		"foreign NameID namespace":     strings.ReplaceAll(canonical, "a:NameID", "x:NameID"),
		"foreign Subject namespace":    strings.ReplaceAll(canonical, "a:Subject", "x:Subject"),
		"foreign Conditions namespace": strings.ReplaceAll(canonical, "a:Conditions", "x:Conditions"),
		"unsigned foreign assertion":   strings.ReplaceAll(canonical, "a:Assertion", "x:Assertion"),
		"two NameID":                   strings.Replace(canonical, "</a:NameID>", "</a:NameID><a:NameID>attacker-human</a:NameID>", 1),
		"two Subjects":                 strings.Replace(canonical, "</a:Subject>", "</a:Subject><a:Subject><a:NameID>attacker-human</a:NameID></a:Subject>", 1),
		"NameID outside Subject":       strings.Replace(canonical, "</a:Subject>", "</a:Subject><a:NameID>attacker-human</a:NameID>", 1),
		"nested Subject":               strings.Replace(canonical, "<a:NameID>", "<a:Subject><a:NameID>", 1),
		"unbound identity prefix":      strings.ReplaceAll(canonical, "a:NameID", "missing:NameID"),
		"missing subject":              strings.Replace(canonical, "<a:Subject><a:NameID>approved-human</a:NameID></a:Subject>", "", 1),
		"missing NameID":               strings.Replace(canonical, "<a:NameID>approved-human</a:NameID>", "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := boundedSAMLXML(raw); err == nil {
				t.Fatal("ambiguous or namespace-blind SAML subject admitted")
			}
		})
	}
}

func TestBrokerSAMLParserPanicsBecomeDenialsWithoutIdentityRelease(t *testing.T) {
	_, err := parseBrokerSAMLWithPanicFence(func() (*saml.Assertion, error) {
		panic("untrusted SAML assertion plaintext must not reach the caller")
	})
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("upstream SAML panic was not contained as generic denial: %v", err)
	}
	if _, err = parseBrokerSAMLWithPanicFence(nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing verifier was accepted: %v", err)
	}
	a := &saml.Assertion{ID: "fixture-only"}
	got, err := parseBrokerSAMLWithPanicFence(func() (*saml.Assertion, error) { return a, nil })
	if err != nil || got != a {
		t.Fatalf("valid verifier behavior was altered: %+v %v", got, err)
	}
}
