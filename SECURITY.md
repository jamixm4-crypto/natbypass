# Security Policy & Threat Model

## Supported Versions

Only the latest release and active beta of NatBypass receive security updates. Older versions are not supported.

| Version | Supported |
| :--- | :--- |
| **Latest Beta (`v1.9.505-beta.1`+)** | ✅ Yes |
| **Latest Stable Release** | ✅ Yes |
| Older Betas / Legacy Builds | ❌ No |

---

## Threat Model & Security Architecture

A comprehensive formal analysis of NatBypass's threat model, security guarantees, adversary capabilities, and out-of-scope non-goals is published in:
📖 [**docs/THREAT_MODEL.md**](docs/THREAT_MODEL.md)

Key architectural guarantees:
1. **End-to-End Encryption (E2EE)**: All tunnel traffic is secured using Noise_IK / ChaCha20-Poly1305 or NaCl SecretBox.
2. **Zero-Knowledge Relays**: Relays only forward opaque ciphertext envelopes and cannot inspect user data.
3. **Cryptographically Signed Updates**: All binary releases are signed with Ed25519 and Cosign/Sigstore.
4. **Third-Party Compliance**: Review dependency terms in [**THIRD_PARTY_LICENSES.md**](THIRD_PARTY_LICENSES.md).

---

## Reporting a Vulnerability

If you believe you have found a security vulnerability in NatBypass, please **do not open a public GitHub issue**. Instead, report it responsibly:

- **GitHub Private Vulnerability Reporting (Preferred)**: Use GitHub's built-in [Private Vulnerability Reporting](https://github.com/jamixm4-crypto/natbypass/security/advisories/new) feature to report issues confidentially.
- **Maintainer Contact**: Contact the repository owner via [GitHub Profile](https://github.com/jamixm4-crypto).

### What to Include
- A clear description of the vulnerability.
- Steps to reproduce or proof-of-concept code.
- Potential impact and affected platforms/versions.
- Any suggested mitigations.

### Response Timeline
- **Acknowledgement**: within 48 hours.
- **Initial assessment**: within 5 business days.
- **Fix and advisory**: prioritized and deployed in the next minor/beta release.

---

## Disclosure Policy & Safe Harbor

We follow a coordinated disclosure model. We ask that researchers provide a reasonable amount of time to investigate and address any reported issues prior to public disclosure.

We will not pursue legal action against researchers who discover and report vulnerabilities in good faith following this policy.

---

## Security Best Practices for Deployments

- **`trusted_keys`**: In production and sensitive networks, populate `trusted_keys` in `config.yaml` with the public keys of allowed devices. This enforces cryptographic whitelisting.
- **WebUI Password**: Change default credentials immediately if enabling LAN access on routers.
- **Private Signaling**: For maximum privacy, self-host your own MQTT signaling broker (`mosquitto` with TLS).
