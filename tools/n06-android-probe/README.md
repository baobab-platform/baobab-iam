# IAM-N06 Android development qualification utility

## Build and install

Use the exact-head artifact from the **IAM N06 Android qualification APK**
workflow on baobab-iam PR #151. Check that `CANDIDATE-HEAD.txt` matches
the reviewed PR head and that the run succeeded. On a trusted workstation,
extract the artifact and run:

```sh
sha256sum -c SHA256SUMS
apksigner verify --verbose --print-certs baobab-n06-probe.apk
```

Compare the signer digest with `APK-SIGNER.txt` from that same trusted run.
The build pins the Gradle distribution checksum, Android Gradle and Kotlin
plugins, API 35 and Build Tools 35.0.0. Hosted debug signing produces a
disposable build signer. Different runs can have different debug signing
keys and APK hashes. The APK signer is distinct from the Android Keystore
key generated during a hardware qualification attempt.

Install on the supervised HONOR 90 Lite through Android's installer or,
if the operator already uses authorized ADB, run
`adb install baobab-n06-probe.apk`. Review the source and use the exact
artifact before enabling that installation source. Remove the installer
permission after use. Keep the bootloader and OS security settings intact.

## First device checkpoint

1. Open **Baobab N06 Qualification** and tap **Probe local capabilities**.
2. Record the displayed StrongBox feature and strong-biometric readiness.
   This action requires no endpoint, identity, ticket or key generation.
3. Report the two capability results and the reviewed build commit. Omit
   settings screenshots, account details and device identifiers.

Both results are local availability observations. Independent evidence
requires a server challenge, an attestation chain, a matching signing key and
current server-side trust checks. Stop after the local probe until a reviewed
HTTPS environment and a disposable ticket are issued.

## Connected run, once the reviewed endpoint exists

The utility uses Android system HTTPS trust, disables redirects and expects
one scoped, short-lived operator ticket. The server routes and independent
A4 authorities are a separate qualification gate. The client contract is:

| Request | Required fields |
| --- | --- |
| `POST /auth/n06/android/challenge` | Empty JSON body with bearer ticket. Response carries `challenge_id`, `operation`, URL-safe base64 `attestation_challenge` of 32 bytes and `transcript` containing the exact N06 A4 operation transcript. |
| `POST /auth/n06/android/evidence` | Bearer ticket, `challenge_id`, original X.509 `certificate_chain` in leaf-first order and a DER ECDSA `signature`, each binary value encoded as base64. |

The server owns the session, operation, reviewer binding and both challenge
lifetimes. It must independently verify the returned evidence. On the
phone, choose TEE evidence collection only if StrongBox is unadvertised and
the reviewed test policy permits the attempt. No software fallback is
accepted by the utility. Approve the biometric prompt for the displayed
operation. Successful submission means evidence was transferred.

After verification, tap **Delete qualification key** and confirm deletion.
The operator must also withdraw the test ticket, remove the synthetic
identity and server challenge, and delete the app when the run is complete.
Keep original certificates and signatures only in approved server custody
with the run reference. Avoid sharing evidence in chat or copying it into
public CI logs.
