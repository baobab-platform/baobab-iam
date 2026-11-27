package org.baobabplatform.n06probe

import android.app.Activity
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Bundle
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.text.InputType
import android.util.Base64
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.URI
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.Executors
import javax.net.ssl.HttpsURLConnection

class ProbeActivity : Activity() {
    private val worker = Executors.newSingleThreadExecutor()
    private val cancellation = CancellationSignal()
    private lateinit var endpoint: EditText
    private lateinit var ticket: EditText
    private lateinit var tee: CheckBox
    private lateinit var result: TextView
    private lateinit var start: Button
    private lateinit var remove: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 48, 32, 32)
        }
        result = TextView(this)
        endpoint = EditText(this).apply {
            hint = "Reviewed development HTTPS origin"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            isSaveEnabled = false
        }
        ticket = EditText(this).apply {
            hint = "Disposable qualification ticket"
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            isSaveEnabled = false
        }
        tee = CheckBox(this).apply { text = "Permit a TEE evidence attempt if StrongBox is absent" }
        start = Button(this).apply {
            text = "Request challenge and collect evidence"
            setOnClickListener { qualify() }
        }
        remove = Button(this).apply {
            text = "Delete qualification key"
            setOnClickListener {
                busy(true)
                worker.execute {
                    val removed = runCatching {
                        keyStore().apply { deleteEntry(ALIAS) }
                        check(!keyStore().containsAlias(ALIAS))
                    }.isSuccess
                    finishAttempt(if (removed) "Qualification key deleted." else "Key deletion could not be verified.")
                }
            }
        }
        layout.addView(Button(this).apply {
            text = "Probe local capabilities"
            setOnClickListener { result.text = capabilityResult() }
        })
        listOf(result, endpoint, ticket, tee, start, remove).forEach { layout.addView(it) }
        setContentView(ScrollView(this).apply { addView(layout) })
        result.text = capabilityResult()
    }

    private fun hasStrongBox() = packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    private fun strongBiometricsReady() =
        getSystemService(BiometricManager::class.java)
            ?.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    private fun capabilityResult(): String {
        val strongBox = if (hasStrongBox()) "advertised" else "not advertised"
        val biometrics = if (strongBiometricsReady()) "ready" else "unavailable or not enrolled"
        return "StrongBox: $strongBox\nStrong biometrics: $biometrics\nIndependent attestation: awaiting server verification."
    }

    private fun qualify() {
        val origin = runCatching { approvedOrigin(endpoint.text.toString().trim()) }.getOrNull()
        val bearer = ticket.text.toString()
        val strongBox = hasStrongBox()
        if (origin == null || !bearer.matches(Regex("[A-Za-z0-9._~-]{24,512}")) ||
            !strongBiometricsReady() || (!strongBox && !tee.isChecked)) {
            result.text = "Check the HTTPS origin, ticket, biometrics and hardware selection."
            return
        }
        ticket.text.clear()
        busy(true)
        result.text = "Requesting the disposable challenge."
        worker.execute {
            try {
                val store = keyStore()
                check(!store.containsAlias(ALIAS))
                val challenge = request(origin, bearer, "/auth/n06/android/challenge", JSONObject())
                val id = challenge.getString("challenge_id")
                check(id.matches(Regex("[A-Za-z0-9_-]{16,160}")))
                val nonce = Base64.decode(challenge.getString("attestation_challenge"), Base64.URL_SAFE)
                val transcript = Base64.decode(challenge.getString("transcript"), Base64.URL_SAFE)
                val operation = challenge.getString("operation")
                check(nonce.size == 32 && validOperationTranscript(transcript, operation))
                val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(nonce)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                    .setInvalidatedByBiometricEnrollment(true)
                    .setIsStrongBoxBacked(strongBox)
                    .build()
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                    .apply { initialize(spec) }.generateKeyPair()
                val privateKey = store.getKey(ALIAS, null) as PrivateKey
                val info = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
                    .getKeySpec(privateKey, KeyInfo::class.java)
                val acceptable = if (strongBox) info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
                    else info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
                check(acceptable && privateKey.encoded == null)
                val chain = store.getCertificateChain(ALIAS)
                check(chain.size in 2..8 && chain.all { it.encoded.size in 1..16384 })
                val encodedChain = JSONArray(chain.map {
                    Base64.encodeToString(it.encoded, Base64.NO_WRAP)
                })
                val signer = Signature.getInstance("SHA256withECDSA")
                signer.initSign(privateKey)
                runOnUiThread {
                    if (isFinishing || isDestroyed) return@runOnUiThread
                    authenticate(signer, operation) { authorized ->
                        worker.execute {
                            val submitted = runCatching {
                                authorized.update(transcript)
                                val signature = Base64.encodeToString(authorized.sign(), Base64.NO_WRAP)
                                val body = JSONObject().put("challenge_id", id)
                                    .put("certificate_chain", encodedChain).put("signature", signature)
                                request(origin, bearer, "/auth/n06/android/evidence", body)
                            }.isSuccess
                            finishAttempt(if (submitted) "Original evidence submitted. Await independent verification."
                                else "Evidence submission failed. Delete the key before trying again.")
                        }
                    }
                }
            } catch (_: Exception) {
                finishAttempt("Qualification could not proceed. Check the reviewed endpoint and hardware; delete the key before retrying.")
            }
        }
    }

    private fun authenticate(signer: Signature, operation: String, complete: (Signature) -> Unit) {
        BiometricPrompt.Builder(this)
            .setTitle("Authorize disposable qualification signature")
            .setSubtitle(operation)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButton("Cancel", mainExecutor) { _, _ -> finishAttempt("Signing cancelled.") }
            .build().authenticate(BiometricPrompt.CryptoObject(signer), cancellation, mainExecutor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(response: BiometricPrompt.AuthenticationResult) {
                        val authenticated = response.cryptoObject?.signature
                        if (authenticated == null) finishAttempt("No biometric-authorized signature operation.")
                        else complete(authenticated)
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        finishAttempt("Biometric authorization did not complete.")
                    }
                })
    }

    private fun approvedOrigin(value: String): URI {
        val uri = URI(value)
        require(uri.scheme == "https" && uri.host != null && uri.rawUserInfo == null &&
            uri.rawQuery == null && uri.rawFragment == null && uri.rawPath in listOf("", "/"))
        return uri
    }

    private fun request(origin: URI, bearer: String, path: String, body: JSONObject): JSONObject {
        val connection = origin.resolve(path).toURL().openConnection() as HttpsURLConnection
        try {
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 8000
            connection.readTimeout = 8000
            connection.requestMethod = "POST"
            connection.doOutput = true
            connection.setRequestProperty("Authorization", "Bearer $bearer")
            connection.setRequestProperty("Content-Type", "application/json")
            val output = body.toString().toByteArray(Charsets.UTF_8)
            check(output.size <= 180000)
            connection.setFixedLengthStreamingMode(output.size)
            connection.outputStream.use { it.write(output) }
            check(connection.responseCode in 200..299)
            val response = connection.inputStream.use { reader ->
                val data = ByteArrayOutputStream()
                val chunk = ByteArray(4096)
                while (true) {
                    val size = reader.read(chunk)
                    if (size < 0) break
                    check(data.size() + size <= 32768)
                    data.write(chunk, 0, size)
                }
                data.toByteArray()
            }
            return if (response.isEmpty()) JSONObject() else JSONObject(response.toString(Charsets.UTF_8))
        } finally {
            connection.disconnect()
        }
    }

    private fun validOperationTranscript(data: ByteArray, operation: String): Boolean {
        if (operation !in setOf("PRIVILEGED_GRANT", "BREAK_GLASS") || data.size !in 100..8192 ||
            !data.copyOfRange(0, TRANSCRIPT_PREFIX.size).contentEquals(TRANSCRIPT_PREFIX)) return false
        val input = ByteBuffer.wrap(data, TRANSCRIPT_PREFIX.size, data.size - TRANSCRIPT_PREFIX.size)
        for (field in 0 until 7) {
            if (input.remaining() < Int.SIZE_BYTES) return false
            val size = input.int
            if (size <= 0 || size > input.remaining()) return false
            if (field == 3) {
                val op = ByteArray(size)
                input.get(op)
                if (!op.contentEquals(operation.toByteArray(Charsets.UTF_8))) return false
            } else {
                if (field == 4 && size != 32) return false
                input.position(input.position() + size)
            }
        }
        return !input.hasRemaining()
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun busy(active: Boolean) {
        start.isEnabled = !active
        remove.isEnabled = !active
    }

    private fun finishAttempt(message: String) = runOnUiThread {
        if (!isFinishing && !isDestroyed) {
            result.text = message
            busy(false)
        }
    }

    override fun onDestroy() {
        cancellation.cancel()
        worker.shutdownNow()
        super.onDestroy()
    }

    companion object {
        private const val ALIAS = "baobab-n06-disposable"
        private val TRANSCRIPT_PREFIX = "baobab-iam-hardware-a4-v1".toByteArray(Charsets.UTF_8)
    }
}
