# Security Policy

## Supported Versions

Only the latest beta release of NatBypass receives security patches. Older versions
are not supported.

| Version       | Supported          |
| ------------- | ------------------ |
| latest beta   | ✅ Yes             |
| older betas   | ❌ No              |

## Reporting a Vulnerability

If you believe you have found a security vulnerability in NatBypass, please **do not
open a public GitHub issue**. Instead, report it responsibly:

**Email:** report to the repository owner via the GitHub profile contacts page at
https://github.com/jamixm4-crypto

**GitHub Private Vulnerability Reporting:** Use GitHub's built-in
[Private Vulnerability Reporting](https://github.com/jamixm4-crypto/natbypass/security/advisories/new)
feature to report issues confidentially.

### What to Include

- A clear description of the vulnerability
- Steps to reproduce or proof-of-concept code
- The potential impact and affected versions
- Any suggested mitigations

### Response Timeline

- **Acknowledgement**: within 72 hours
- **Initial assessment**: within 7 days
- **Fix and advisory**: as soon as practical, depending on severity

## Disclosure Policy

We follow a coordinated disclosure model. We ask that you give us a reasonable
amount of time to investigate and address the issue before any public disclosure.

## Safe Harbor

We will not take legal action against researchers who discover and report
vulnerabilities in good faith following this policy.

## Known Security Considerations

- **`trusted_keys`**: Leave empty (`[]`) to allow any peer with the correct `network_key`.
  For production deployments, list explicit `trusted_keys` to restrict which devices
  can join the mesh network.
- **WebUI**: Always set a strong password in `config.yaml`. The default `admin` password
  must be changed before exposing the WebUI to any network.
- **`network_key`**: Keep your network key secret. Anyone with the key and the MQTT
  topic can join your mesh network.
