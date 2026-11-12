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
	jose "github.com/go-jose/go-jose/v4"
	"github.com/supatype/saml"
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
	var elementStack []xml.Name
	subjects, nameIDs, assertionIssuers := 0, 0, 0
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
			elementStack = append(elementStack, t.Name)
			if depth == 1 {
				roots++
			}
			if depth > 32 {
				return ErrInvalid
			}
			if depth == 1 && (t.Name.Space != "urn:oasis:names:tc:SAML:2.0:protocol" || t.Name.Local != "Response") {
				return ErrDenied
			}
			// Check the supported assertion shape before invoking the signed
			// protocol verifier. Identity elements must have the expected namespace.
			const assertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion"
			switch t.Name.Local {
			case "Assertion":
				if t.Name.Space != assertionNamespace {
					return ErrDenied
				}
			case "Subject":
				if t.Name.Space != assertionNamespace || depth != 3 || elementStack[depth-2].Space != assertionNamespace || elementStack[depth-2].Local != "Assertion" {
					return ErrDenied
				}
				subjects++
				if subjects != 1 {
					return ErrDenied
				}
			case "NameID":
				if t.Name.Space != assertionNamespace || depth != 4 || elementStack[depth-2].Space != assertionNamespace || elementStack[depth-2].Local != "Subject" {
					return ErrDenied
				}
				nameIDs++
				if nameIDs != 1 {
					return ErrDenied
				}
			case "Issuer":
				if t.Name.Space != assertionNamespace || (depth != 2 && depth != 3) {
					return ErrDenied
				}
				if depth == 3 {
					if elementStack[depth-2].Space != assertionNamespace || elementStack[depth-2].Local != "Assertion" {
						return ErrDenied
					}
					assertionIssuers++
				}
			case "Conditions", "SubjectConfirmation", "SubjectConfirmationData", "AudienceRestriction", "Audience", "AuthnStatement", "AuthnContext", "AuthnContextClassRef":
				if t.Name.Space != assertionNamespace {
					return ErrDenied
				}
			}
			if t.Name.Space == assertionNamespace && t.Name.Local == "Assertion" {
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
			if depth == 0 || len(elementStack) != depth || elementStack[depth-1] != t.Name {
				return ErrInvalid
			}
			elementStack = elementStack[:depth-1]
			depth--
		}
	}
	if depth != 0 || roots != 1 || assertions != 1 || subjects != 1 || nameIDs != 1 || assertionIssuers != 1 || signatures < 1 || signatures > 2 {
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
		candidate, e := parseBrokerSAMLWithPanicFence(func() (*saml.Assertion, error) {
			return sp.ParseXMLResponse([]byte(raw), []string{requestID}, *acs)
		})
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
	if name.Format != "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" || !exact(name.Value) || name.SPProvidedID != "" || name.NameQualifier != "" && name.NameQualifier != s.Trust.UpstreamIssuer || name.SPNameQualifier != "" && name.SPNameQualifier != c.SAML.EntityID || condition…26583 tokens truncated…f another writer races the initial check.
        # Never rename over an existing (including empty) output directory.
        output.mkdir()
        (root / 'contracts').rename(output / 'contracts')
        (root / 'receipt.json').rename(output / 'receipt.json')


def load_capability_catalogue(checkout, repository=ROOT):
    lock = yaml.safe_load((repository / '.baobab/capability-catalogue.lock.yaml').read_text())
    if lock.get('schema') != 'baobab-capability-catalogue-consumer-lock' or lock.get('purpose') != 'read-only-provider-declaration-contracts':
        raise ValueError('read-only capability catalogue pin required')
    return _load_shared(checkout, lock['source'], 'capability catalogue')


def load_runtime_shared(checkout, repository=ROOT):
    lock = yaml.safe_load((repository / 'contracts.lock.yaml').read_text())
    if lock.get('schema') != 'baobab-contract-consumer-lock':
        raise ValueError('runtime Shared consumer pin required')
    return _load_shared(checkout, lock['source'], 'runtime contract')


def _load_shared(checkout, source, purpose):
    if source['repository'] != 'baobab-platform/shared':
        raise ValueError('unapproved contract authority')
    commit = subprocess.check_output(
        ['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip()
    if commit != source['commit']:
        raise ValueError(f'Shared checkout does not match the immutable {purpose} pin')
    if subprocess.check_output(
            ['git', '-C', str(checkout), 'status', '--porcelain', '--untracked-files=all'], text=True).strip():
        raise ValueError('Shared checkout must be clean, including untracked files')
    spec = importlib.util.spec_from_file_location(
        'iam_pinned_capability_catalogue', checkout / 'scripts/capability_catalogue.py')
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module, commit


def validate_native_provider_roles(declaration):
    """Enforce ADR-IAM-0033 before any Shared registration candidate exists.

    Keycloak's legacy native authentication contract is deliberately PARTIAL:
    permanent federation is *not* a general Kratos replacement. A future
    independently accepted Shared enterprise-federation capability can be
    registered separately without weakening this prohibition.
    """
    roles = {
        'baobab-iam.kratos': ('kratos', 'identity.authentication.perform'),
        'baobab-iam.hydra': ('hydra', 'identity.workload-token.issue'),
        'baobab-iam.keycloak': ('keycloak', 'identity.authentication.perform'),
    }
    providers = declaration.get('providers')
    if not isinstance(providers, list):
        raise ValueError('native provider roles require an explicit provider list')
    for entry in providers:
        key = entry.get('provider_key')
        if key not in roles:
            # An alias with the same underlying adapter must not bypass the
            # federation-only rule while masquerading as a new provider.
            if entry.get('implementation_key') in {'kratos', 'hydra', 'keycloak'}:
                raise ValueError('unreviewed alias of an ADR-IAM-0033 native provider')
            continue  # A new implementation still requires separate Shared review.
        implementation, capability = roles[key]
        if entry.get('implementation_key') != implementation:
            raise ValueError('ADR-IAM-0033 provider implementation role mismatch')
        for support in entry.get('support', ()):
            name, status = support.get('capability_key'), support.get('implementation_status')
            if key == 'baobab-iam.keycloak' and name == capability and status == 'IMPLEMENTED':
                raise ValueError('Keycloak federation cannot publish native authentication support')
            if key == 'baobab-iam.kratos' and name == 'identity.workload-token.issue':
                raise ValueError('Kratos cannot issue workload OAuth tokens')
            if key == 'baobab-iam.hydra' and name == 'identity.authentication.perform':
                raise ValueError('Hydra cannot substitute for Kratos native human identity')


def prepare(module, checkout, declaration, repository=ROOT):
    validate_native_provider_roles(declaration)
    contracts = module.Contracts(checkout / 'contracts')
    errors = module.validate_catalogue(contracts)
    errors += module.validate_declaration(contracts, declaration, repository, 'baobab-iam')
    if errors:
        raise ValueError('; '.join(errors))
    registrations, excluded = [], []
    for provider in sorted(declaration['providers'], key=lambda p: p['provider_key']):
        for support in provider['support']:
            if support['implementation_status'] != 'IMPLEMENTED':
                excluded.append({
                    'provider_key': provider['provider_key'],
                    'capability_key': support['capability_key'],
                    'implementation_status': support['implementation_status'],
                })
        if any(s['implementation_status'] == 'IMPLEMENTED' for s in provider['support']):
            # Shared validates and generates the wire format; no IAM shadow schema.
            registrations.append(module.generate_registration(
                contracts, declaration, provider['provider_key'], 'DRAFT'))
    return contracts, registrations, excluded


def compare_exports(module, contracts, registrations, exports):
    """Compare reviewed EngineRegistration exports, not CP lifecycle/health.

    Input is a JSON array of canonical EngineRegistration documents. Missing,
    extra, duplicate and substituted declarations all count as drift. This
    offline comparison has no freshness or runtime-authority claim.
    """
    if not isinstance(exports, list):
        raise ValueError('registration export must be a JSON array')
    actual = {}
    for entry in exports:
        errors = contracts.errors(module.REGISTRATION_REF, entry)
        if errors:
            raise ValueError('invalid registration export: ' + '; '.join(errors))
        key = entry['provider']['provider_key']
        if entry['repository'] != 'baobab-iam' or key in actual:
            raise ValueError('foreign or duplicate registration export')
        actual[key] = entry
    expected = {entry['provider']['provider_key']: entry for entry in registrations}
    drift = []
    for key in sorted(set(actual) | set(expected)):
        if key not in expected:
            drift.append({'provider_key': key, 'reason': 'UNDECLARED_SUPPORT'})
        elif key not in actual:
            drift.append({'provider_key': key, 'reason': 'MISSING_REGISTRATION'})
        else:
            if actual[key] != expected[key]:
                drift.append({'provider_key': key, 'reason': 'DECLARATION_MISMATCH'})
    return drift


def compare_executable_support(declaration, census):
    """Bind publication eligibility to adapter declarations; never runtime truth."""
    validate_native_provider_roles(declaration)
    if not isinstance(census, dict) or set(census) != {'classification', 'providers'} or census['classification'] != 'EXECUTABLE_CONSTRUCTION_CENSUS':
        raise ValueError('invalid executable support census')
    rows = census['providers']
    if not isinstance(rows, list):
        raise ValueError('invalid executable provider list')
    actual = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'provider_key', 'implementation_key', 'support'}:
            raise ValueError('invalid executable provider declaration')
        key = row['provider_key']
        if not isinstance(key, str) or key in actual:
            raise ValueError('duplicate or invalid executable provider')
        if not isinstance(row['implementation_key'], str) or not row['implementation_key']:
            raise ValueError('invalid executable implementation key')
        support = row['support']
        if not isinstance(support, list):
            raise ValueError('invalid executable support list')
        seen_capabilities = set()
        for entry in support:
            if not isinstance(entry, dict) or set(entry) != {'capability_key', 'contract_versions', 'implementation_status'}:
                raise ValueError('invalid executable support entry')
            capability = entry['capability_key']
            if not isinstance(capability, str) or not capability or capability in seen_capabilities:
                raise ValueError('duplicate or invalid executable capability')
            seen_capabilities.add(capability)
            versions = entry['contract_versions']
            if (not isinstance(versions, list) or not versions or
                    any(type(version) is not int or version < 1 for version in versions) or
                    len(set(versions)) != len(versions)):
                raise ValueError('invalid executable contract versions')
            if entry['implementation_status'] not in ('IMPLEMENTED', 'PARTIAL', 'UNSUPPORTED'):
                raise ValueError('invalid executable implementation status')
        actual[key] = row
    expected = {p['provider_key']: {k: p[k] for k in ('provider_key', 'implementation_key', 'support')}
                for p in declaration['providers']}
    # Evidence paths remain validated through Shared; executable code reports
    # conformance, not copies of the declaration's documentary evidence.
    for row in expected.values():
        row['support'] = [{k: s[k] for k in ('capability_key', 'contract_versions', 'implementation_status')}
                          for s in row['support']]
    if actual != expected:
        raise ValueError('canonical declaration and executable support drift')


def read_evidence_export(path):
    """Reject ambiguous wire evidence before any schema or drift comparison."""
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate registration evidence property')
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError('non-finite registration evidence number')

    return json.loads(path.read_text(), object_pairs_hook=unique_object,
                      parse_constant=reject_constant)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shared-checkout', type=Path, required=True)
    parser.add_argument('--registration-export', type=Path)
    parser.add_argument('--executable-support-export', type=Path)
    parser.add_argument('--require-registrable', action='store_true')
    parser.add_argument('--bundle-provider')
    parser.add_argument('--bundle-path')
    parser.add_argument('--bundle-output', type=Path)
    parser.add_argument('--expected-source-revision')
    parser.add_argument('--expected-index-sha256')
    args = parser.parse_args(argv)
    try:
        if any((args.bundle_provider, args.bundle_path, args.bundle_output,
                args.expected_source_revision, args.expected_index_sha256)) and args.shared_checkout.resolve().is_relative_to(ROOT):
            raise ValueError('candidate preparation requires a Shared checkout outside the IAM worktree; nested checkouts are read-only preflight inputs')
        module, commit = load_capability_catalogue(args.shared_checkout.resolve())
        path = ROOT / '.baobab/capability-provider.yaml'
        raw = path.read_bytes()
        declaration = yaml.safe_load(raw)
        contracts, registrations, excluded = prepare(
            module, args.shared_checkout.resolve(), declaration)
        if args.executable_support_export:
            compare_executable_support(declaration, read_evidence_export(args.executable_support_export))
        elif args.require_registrable:
            raise ValueError('strict publication requires an executable support census')
        drift = compare_exports(module, contracts, registrations,
                                read_evidence_export(args.registration_export)) if args.registration_export else None
        eligible = {r['provider']['provider_key'] for r in registrations}
        blocked = sorted(p['provider_key'] for p in declaration['providers'] if p['provider_key'] not in eligible)
        report = {
            'classification': 'CONSTRUCTION_PREFLIGHT',
            'shared_commit': commit,
            'declaration_sha256': hashlib.sha256(raw).hexdigest(),
            'source_revision': subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
            'source_dirty': bool(subprocess.check_output(['git', '-C', str(ROOT), 'status', '--porcelain'], text=True).strip()),
            'draft_registrations': registrations,
            'excluded_support': excluded,
            'executable_support_verified': bool(args.executable_support_export),
            'blocked_providers': blocked,
            'registration_drift': drift,
            'runtime_authority_verified': False,
        }
        bundle_options = (args.bundle_provider, args.bundle_path, args.bundle_output,
                          args.expected_source_revision, args.expected_index_sha256)
        if any(bundle_options):
            if not all(bundle_options):
                raise ValueError('bundle preparation requires provider, path, output, source revision and index digest')
            if report['source_dirty'] or report['source_revision'] != args.expected_source_revision:
                raise ValueError('bundle source must be clean and match the reviewed revision')
            if drift:
                raise ValueError('registration export drift blocks bundle preparation')
            if args.require_registrable and blocked:
                raise ValueError('strict registration requires every provider to be registrable')
            # Execute this revision, rather than trust an unbound census export.
            census = json.loads(subprocess.check_output(
                ['go', 'run', './cmd/provider-support-census'], cwd=ROOT, text=True))
            compare_executable_support(declaration, census)
            index_raw = (args.shared_checkout / 'contracts' / INDEX_PATH).read_bytes()
            digest = hashlib.sha256(index_raw).hexdigest()
            if digest != args.expected_index_sha256:
                raise ValueError('registration index changed; reconcile the reviewed base')
            proposed, registration = bundle_candidate(
                module, contracts, registrations, yaml.safe_load(index_raw), args.bundle_provider, args.bundle_path)
            if (args.shared_checkout / 'contracts' / args.bundle_path).exists():
                raise ValueError('candidate path already exists in Shared')
            receipt = {'classification': 'SHARED_REGISTRATION_REVIEW_CANDIDATE',
                       'source_revision': report['source_revision'], 'shared_commit': commit,
                       'base_index_sha256': digest, 'declaration_sha256': report['declaration_sha256'],
                       'provider_key': args.bundle_provider, 'bundle_path': args.bundle_path,
                       'bundle_sha256': hashlib.sha256((json.dumps(registration, indent=2, sort_keys=True) + '\n').encode()).hexdigest(),
                       'runtime_authority_verified': False, 'published': False}
            output = args.bundle_output.absolute()
            resolved_output = output.resolve()
            if resolved_output.is_relative_to(ROOT) or resolved_output.is_relative_to(args.shared_checkout.resolve()):
                raise ValueError('review output must be outside IAM and the pinned Shared checkout')
            if subprocess.check_output(['git', '-C', str(ROOT), 'status', '--porcelain', '--untracked-files=all'], text=True).strip():
                raise ValueError('bundle source changed during preparation')
            if subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip() != args.expected_source_revision:
                raise ValueError('bundle source revision changed during preparation')
            load_capability_catalogue(args.shared_checkout.resolve())
            write_bundle_candidate(output, args.bundle_path, proposed, registration, receipt)
            report['bundle_candidate'] = receipt
        print(json.dumps(report, indent=2, sort_keys=True))
        return 2 if drift or (args.require_registrable and blocked) else 0
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError, yaml.YAMLError) as error:
        print(f'publication preflight denied: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
