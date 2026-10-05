package org.baobab.iam;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.util.JsonSerialization;

/** Private MP8 evidence export. No token storage, logging or canonical account mapping. */
public final class EvidenceBridge extends AbstractIdentityProviderMapper {
    public static final String ID = "baobab-evidence-bridge";
    public static final String DIGEST_NOTE = "baobab_upstream_evidence_digest";
    @Override public String getId() { return ID; }
    @Override public String[] getCompatibleProviders() { return new String[] {"oidc", "saml"}; }
    @Override public String getDisplayCategory() { return "Baobab federation"; }
    @Override public String getDisplayType() { return "Private upstream evidence bridge"; }
    @Override public String getHelpText() { return "Export original upstream proof to the private IAM verifier; failure denies login."; }
    @Override public List<ProviderConfigProperty> getConfigProperties() {
        return List.of(new ProviderConfigProperty("trust-id", "Approved trust", "Exact IAM FederationTrust ID", ProviderConfigProperty.STRING_TYPE, null),
                       new ProviderConfigProperty("client-id", "Bound client", "Exact enterprise BFF client", ProviderConfigProperty.STRING_TYPE, null));
    }

    private static void restoreDigest(BrokeredIdentityContext context) {
        Object digest = context.getContextData().get(DIGEST_NOTE);
        if (!(digest instanceof String value) || !value.matches("sha256:[a-f0-9]{64}") || context.getAuthenticationSession() == null)
            throw new IdentityBrokerException("Private upstream federation evidence binding missing");
        context.getAuthenticationSession().setUserSessionNote(DIGEST_NOTE, (String) digest);
    }
    // First broker login resets user-session notes. Restore the verified digest
    // from server-side serialized broker context after that flow completes.
    @Override public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapper, BrokeredIdentityContext context) {
        restoreDigest(context);
    }
    @Override public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapper, BrokeredIdentityContext context) {
        restoreDigest(context);
    }

    private static byte[] protectedFile(String name, int limit) throws Exception {
        String configured = System.getenv(name);
        if (configured == null || configured.isBlank()) throw new IllegalArgumentException();
        Path path = Path.of(configured);
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) ||
            !Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS).equals(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)) ||
            !Files.getAttribute(path, "unix:uid", LinkOption.NOFOLLOW_LINKS).equals(Files.getAttribute(Path.of("/proc/self"), "unix:uid")) ||
            !Integer.valueOf(1).equals(Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS))) throw new IllegalArgumentException();
        byte[] result;
        try (var stream = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) { result = stream.readNBytes(limit + 1); }
        if (result.length == 0 || result.length > limit) throw new IllegalArgumentException();
        return result;
    }
    private static String secret(String name) throws Exception {
        String value = new String(protectedFile(name, 16384), java.nio.charset.StandardCharsets.UTF_8).strip();
        if (value.isEmpty() || value.chars().anyMatch(c -> c <= 32 || c >= 127)) throw new IllegalArgumentException();
        return value;
    }
    private static SSLContext tls() throws Exception {
        char[] password = secret("BAOBAB_EVIDENCE_KEYSTORE_PASSWORD_FILE").toCharArray();
        KeyStore keys = KeyStore.getInstance("PKCS12");
        keys.load(new java.io.ByteArrayInputStream(protectedFile("BAOBAB_EVIDENCE_KEYSTORE_FILE", 65536)), password);
        KeyManagerFactory managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()); managers.init(keys, password);
        char[] trustPassword = secret("BAOBAB_EVIDENCE_TRUSTSTORE_PASSWORD_FILE").toCharArray();
        KeyStore roots = KeyStore.getInstance("PKCS12");
        roots.load(new java.io.ByteArrayInputStream(protectedFile("BAOBAB_EVIDENCE_TRUSTSTORE_FILE", 65536)), trustPassword);
        TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); trust.init(roots);
        SSLContext context = SSLContext.getInstance("TLSv1.3"); context.init(managers.getKeyManagers(), trust.getTrustManagers(), null);
        java.util.Arrays.fill(password, '\0'); java.util.Arrays.fill(trustPassword, '\0');
        return context;
    }

    @Override public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm, IdentityProviderMapperModel mapper, BrokeredIdentityContext context) {
        String phase = "binding";
        try {
            var auth = context.getAuthenticationSession();
            String expectedClient = mapper.getConfig().get("client-id");
            String trust = mapper.getConfig().get("trust-id");
            if (auth == null || expectedClient == null || !expectedClient.equals(auth.getClient().getClientId()) ||
                trust == null || !trust.matches("[a-fA-F0-9-]{36}")) throw new IllegalArgumentException();
            phase = "upstream-correlation";
            String nonce = auth.getClientNote("nonce");
            String route = context.getIdpConfig().getAlias();
            String protocol = context.getIdpConfig().getProviderId();
            String correlation;
            String assertion;
            if ("oidc".equals(protocol)) {
                AccessTokenResponse response = (AccessTokenResponse) context.getContextData().get(OIDCIdentityProvider.FEDERATED_ACCESS_TOKEN_RESPONSE);
                if (response == null) throw new IllegalArgumentException();
                assertion = response.getIdToken();
                correlation = auth.getClientNote("BROKER_NONCE");
            } else if ("saml".equals(protocol)) {
                String encoded = session.getContext().getHttpRequest().getDecodedFormParameters().getFirst("SAMLResponse");
                if (encoded == null || encoded.length() > 90000) throw new IllegalArgumentException();
                byte[] original = Base64.getDecoder().decode(encoded);
                if (original.length > 65536) throw new IllegalArgumentException();
                assertion = new String(original, java.nio.charset.StandardCharsets.UTF_8);
                correlation = auth.getClientNote(SamlProtocol.SAML_REQUEST_ID_BROKER);
            } else throw new IllegalArgumentException();
            if (nonce == null || correlation == null || assertion == null || assertion.isBlank() || assertion.length() > 65536) throw new IllegalArgumentException();
            phase = "endpoint";
            URI endpoint = URI.create(System.getenv("BAOBAB_EVIDENCE_ENDPOINT"));
            if (!"https".equals(endpoint.getScheme()) || endpoint.getHost() == null || endpoint.getUserInfo() != null || endpoint.getQuery() != null || endpoint.getFragment() != null) throw new IllegalArgumentException();
            byte[] body = JsonSerialization.writeValueAsBytes(Map.of("TrustID", trust, "Nonce", nonce, "ProviderRoute", route, "UpstreamCorrelation", correlation, "Assertion", assertion));
            phase = "bearer-file";
            String bearer = secret("BAOBAB_EVIDENCE_BEARER_FILE");
            HttpRequest request = HttpRequest.newBuilder(endpoint).timeout(Duration.ofSeconds(5)).header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + bearer).POST(HttpRequest.BodyPublishers.ofByteArray(body)).build();
            phase = "tls-files";
            SSLContext contextTLS = tls();
            HttpClient client = HttpClient.newBuilder().sslContext(contextTLS).connectTimeout(Duration.ofSeconds(5)).followRedirects(HttpClient.Redirect.NEVER).build();
            phase = "delivery";
            HttpResponse<Void> result = client.send(request, HttpResponse.BodyHandlers.discarding());
            if (result.statusCode() != 200 && result.statusCode() != 204) {phase = "verifier-denied";throw new IllegalArgumentException();}
            String digest = "sha256:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(assertion.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            context.getContextData().put(DIGEST_NOTE, digest);
            auth.setUserSessionNote(DIGEST_NOTE, digest);
        } catch (Exception denied) {
            // Exceptions can contain response/token material; deliberately discard them.
            throw new IdentityBrokerException("Private upstream federation evidence denied (" + phase + ":" + denied.getClass().getSimpleName() + ")");
        }
    }
}
