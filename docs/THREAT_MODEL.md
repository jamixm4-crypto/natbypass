# NatBypass Security Threat Model

## 1. System Overview & Purpose

**NatBypass** is a decentralized, peer-to-peer (P2P) mesh virtual private network (VPN) engineered for:
- Direct socket-to-socket communication between personal devices (home routers, PCs, smartphones, servers) across carrier-grade NAT (CGNAT) and symmetric NAT.
- Resilience against Deep Packet Inspection (DPI) and state censorship filters (e.g. TSPU / RKN) using protocol obfuscation (AmneziaWG packet morphing, QUIC chameleon framing, TCP ShadowTLS).
- Zero reliance on centralized commercial VPN servers or third-party cloud infrastructure.

This document defines the **security boundaries**, **threat model**, **explicit non-goals**, and **guarantees** provided by NatBypass.

---

## 2. In-Scope Security Guarantees (What NatBypass Protects)

| Threat Vector | Mitigation in NatBypass | Implementation Details |
| :--- | :--- | :--- |
| **Eavesdropping on Tunnel Traffic (Confidentiality)** | Full End-to-End Encryption (E2EE) | All user payload data between peers is encrypted using **Noise_IK / ChaCha20-Poly1305** (WireGuard/AWG) or **NaCl SecretBox / XSalsa20-Poly1305**. |
| **Packet Tampering & Forgery (Integrity)** | Cryptographic MAC verification | Any altered packet is dropped immediately by the cryptographic AEAD authentication tag (`Poly1305`). |
| **Traffic Fingerprinting by DPI (Censorship)** | AmneziaWG 3.1 & Chameleon Framing | AmneziaWG junk packets (`Jc`, `Jmin`, `Jmax`), randomized magic headers (`H1`–`H4`), variable padding (`S1`, `S2`), and QUIC Initial masquerading defeat heuristic and pattern-based DPI. |
| **Replay Attacks** | Sliding Window Filter + Monotonic Nonce/Timestamps | Every packet carries a 64-bit sequence counter and epoch ID. Replayed or duplicate packets are filtered out (`ValidateAndAccept`). |
| **Untrusted Intermediate Relays** | Zero-Knowledge Relay Architecture | Relays only receive opaque `MultiHopPacket` envelopes. Relays **cannot** decrypt, inspect, or modify the inner payload. |
| **Supply Chain / Malicious Auto-Updates** | Cryptographic Release Verification | Updates are digitally signed with an **Ed25519** private key. The public key is hardcoded in the client. Unsigned or corrupted binaries are rejected. |
| **WebUI Attacks on LAN / Localhost** | Host validation, CSRF, and Authentication | WebUI binds to `127.0.0.1` by default (except Keenetic router LAN). DNS Rebinding, CSRF, and unauthorized LAN access are blocked by strict middleware. |

---

## 3. Explicit Non-Goals & Limitations (What NatBypass Does NOT Protect)

> [!WARNING]
> NatBypass is a **Private Mesh VPN**, NOT an anonymous overlay network like **Tor** or **I2P**. Users requiring absolute anonymity against state adversaries must understand the following limitations:

### 1. Signaling Metadata Visibility
- **Public MQTT / Telegram Brokers**: When exchanging signaling coordinates (endpoints, STUN mapped ports, public keys), the signaling broker sees:
  - The client's public IP address.
  - The topic name (room) or Telegram chat ID.
  - Frequency of beacon messages.
- **Protection**: Signaling payloads are E2E encrypted with NaCl Box (`crypto.EncryptSelf` / `crypto.EncryptBox`). The broker cannot read peer internal IPs, device names, or encryption keys. However, traffic analysis of signaling packet sizes and timings remains theoretically possible.
- **Mitigation**: Users with high threat models should self-host their own private MQTT broker (`mosquitto` with TLS and authentication) or use custom webhook channels.

### 2. IP Exposure to STUN Servers
- When discovering external NAT mappings via RFC 5389 / 5780, STUN servers observe the client's public IP address.
- **Mitigation**: NatBypass supports specifying custom STUN servers in `config.yaml` to avoid public Google/Cloudflare STUN endpoints.

### 3. Traffic Volume & Timing Correlation
- While AmneziaWG obfuscates packet headers and adds jitter/padding, sophisticated passive network observers at the ISP level can observe:
  - Bandwidth consumption over time.
  - Communication duration between endpoints.
- NatBypass does not introduce synthetic dummy traffic padding at full line-rate (which would deplete mobile battery and data quotas).

---

## 4. Adversary Capabilities & Defenses

```
   [Peer A]  <================= Direct P2P (Encrypted & Obfuscated) ================>  [Peer B]
      │                                                                                  │
      ├───────► [Signaling Broker (MQTT/TG)]  (Sees IP + Topic; Payload is E2EE) ◄──────┤
      │                                                                                  │
      └───────► [Transit Relay Peer C] (Zero-Knowledge: Sees only Outer MultiHop Header) ┘
```

### Threat 1: Passive ISP Wiretapping
- **Adversary Action**: Captures all packets between Peer A and Peer B.
- **Outcome**: The ISP sees only high-entropy UDP or TLS traffic with randomized headers. It cannot read plaintext IP packets, cannot determine peer identity, and cannot decrypt payload.

### Threat 2: Active DPI Drop / TSPU Censorship
- **Adversary Action**: Injects TCP RST, drops UDP packets matching WireGuard signatures, or blocks UDP on ports 51820 / 443.
- **Outcome**: NatBypass detects packet loss via `AdaptiveProbeEngine`, escalates transport through the 5-tier ladder:
  1. QUIC Initial Chameleon Probe masking.
  2. AmneziaWG Strict header obfuscation.
  3. Direct IPv6 bypass (if available).
  4. TCP ShadowTLS over port 443 (mimics HTTPS).
  5. Multi-Hop Mesh Relay failover.

### Threat 3: Compromised or Malicious Mesh Relay
- **Adversary Action**: Node C is elected as a relay between Node A and Node B. Node C attempts to spy on traffic.
- **Outcome**: Because NatBypass employs **Zero-Knowledge Multi-Hop encapsulation**, Node C only sees:
  - Sender Device ID and Receiver Device ID.
  - Opaque ciphertext payload.
- Node C cannot read, decrypt, or alter the payload without invalidating the ChaCha20-Poly1305 MAC tag.

### Threat 4: Rogue Participant in Public Signaling Room
- **Adversary Action**: An attacker discovers the network topic name or room key and attempts to inject packets into the mesh.
- **Outcome**:
  - Without the `network_key` (symmetric passphrase), the attacker cannot decrypt signaling beacons or generate valid epoch signatures.
  - If `trusted_keys` (PublicKey Pinning) is enabled, unknown public keys are rejected immediately by the `Registry` regardless of valid signaling messages.

---

## 5. Exit Node Security & Kill-Switch Policies

When an Exit Node is enabled:
1. **Physical Gateway Bypass**: NatBypass dynamically bypasses the physical gateway for peer signaling and STUN traffic to prevent routing loops.
2. **DNS Leak Protection**: All DNS traffic is resolved through the Exit Node or local DoH proxy (`127.0.0.1:53`), preventing local ISP DNS hijacking.
3. **Recommended Operator Setting**: Exit Node administrators should restrict access via `trusted_keys` in `config.yaml` to prevent unauthorized mesh peers from routing internet traffic through their connection.

---

## 6. Responsible Disclosure

To report security vulnerabilities, consult [SECURITY.md](../SECURITY.md) or use [GitHub Private Vulnerability Reporting](https://github.com/jamixm4-crypto/natbypass/security/advisories/new).
