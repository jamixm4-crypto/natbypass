---
name: amneziawg-dpi-tuner
description: >-
  Comprehensive guide and presets for tuning AmneziaWG 2.0 protocol obfuscation parameters (Jc, Jmin, Jmax, S1, S2, H1, H2, H3, H4)
  to bypass deep packet inspection (DPI / TSPU) censorship systems on Windows, Android, Linux, and Keenetic/OpenWrt routers.
---

# AmneziaWG 2.0 DPI Bypass & Tuning Skill

## 1. Parameters Reference

| Parameter | Meaning | Standard WireGuard | Recommended DPI Bypass | Stealth Randomizer |
| :--- | :--- | :--- | :--- | :--- |
| **Jc** | Junk packet count injected at handshake | `0` | `4` | `3 – 8` |
| **Jmin** | Min junk packet payload size (bytes) | `0` | `40` | `20 – 60` |
| **Jmax** | Max junk packet payload size (bytes) | `0` | `70` | `60 – 120` |
| **S1** | Init packet header padding size | `0` | `48` | `16 – 64` |
| **S2** | Response packet header padding size | `0` | `32` | `16 – 64` |
| **H1** | Custom Header ID for Message Type 1 (Init) | `1` | `1428571428` | `Rand uint32` |
| **H2** | Custom Header ID for Message Type 2 (Resp) | `2` | `2147483647` | `Rand uint32` |
| **H3** | Custom Header ID for Message Type 3 (Cookie)| `3` | `857142857` | `Rand uint32` |
| **H4** | Custom Header ID for Message Type 4 (Data) | `4` | `1122334455` | `Rand uint32` |

---

## 2. Configuration Templates

### `amneziawg.conf` Template
```ini
[Interface]
PrivateKey = <Client_Private_Key>
Address = 10.200.0.2/24
DNS = 1.1.1.1, 8.8.8.8
MTU = 1420

# AmneziaWG 2.0 Obfuscation
Jc = 4
Jmin = 40
Jmax = 70
S1 = 48
S2 = 32
H1 = 1428571428
H2 = 2147483647
H3 = 857142857
H4 = 1122334455

[Peer]
PublicKey = <Peer_Public_Key>
AllowedIPs = 10.200.0.0/24
Endpoint = <Public_STUN_IP>:<Port>
PersistentKeepalive = 25
```

---

## 3. Platform Integration Notes
- **Windows Client**: Import `.conf` file into official AmneziaWG Windows client.
- **Keenetic Routers**: Paste config into Web Interface -> Other Connections -> Wireguard.
- **OpenWrt**: Install `kmod-amneziawg` or standard `amneziawg-tools`.
- **Android**: Scan QR code or import `.conf` via AmneziaWG App.
