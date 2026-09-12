import json
import hashlib
from pathlib import Path

build_dir = Path(r"e:\qwen\fnat\build")
old_manifest_path = Path(r"e:\qwen\fnat\mirror\releases\v1.9.226-beta11.json")
new_manifest_path = Path(r"e:\qwen\fnat\mirror\releases\v1.9.226-beta12.json")
latest_manifest_path = Path(r"e:\qwen\fnat\mirror\releases\latest-beta.json")

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

with open(old_manifest_path, "r", encoding="utf-8") as f:
    manifest = json.load(f)

manifest["version"] = "v1.9.226-beta12"
manifest["published_at"] = "2026-09-12T08:30:00Z"
manifest["html_url"] = "https://github.com/jamixm4-crypto/natbypass/releases/tag/v1.9.226-beta12"
manifest["release_notes"] = """**Full Changelog**: https://github.com/jamixm4-crypto/natbypass/compare/v1.9.226-beta11...v1.9.226-beta12

- Pure P2P Anti-TSPU/DPI Bypass: Add carrier_mobile (MTS, MegaFon, Tele2, Yota) and carrier_fixed (Rostelecom) presets with MTU 1280
- Strict Anti-DPI Invariant: Enforce S1 + 56 != S2 and |S1 - S2| != 56 to break WireGuard Handshake 148B/92B length signatures
- Deterministic Obfuscation Rotation: DeriveAWGParamsFromKeyAndEpoch rotates H1..H4, S1..S4, and HeaderProtectionKey across mesh
- DCUtR Millisecond Precision: ScheduleSimultaneousOpenMilli coordinates symmetric NAT open bursts within 15-25ms window
- Anti-Metronome Keep-Alive: Randomized interval (9..23s) with dynamic QUIC Initial Chameleon and decoy padding
- Low-TTL Decoy Probe: Inject IP_TTL=2 middlebox decoys via SyscallConn on Linux/Keenetic
- IPv6-First Direct P2P: Auto-discover global IPv6 and prioritize direct IPv6 routes to bypass IPv4 TSPU DPI entirely
- WebUI Presets & Rotation: Added one-click Carrier Mobile/Fixed and network-wide rotation button"""

for key, asset in manifest.get("assets", {}).items():
    filename = asset.get("name")
    file_path = build_dir / filename if filename else None
    if file_path and file_path.exists():
        asset["sha256"] = sha256_file(file_path)
        asset["size"] = file_path.stat().st_size
        print(f"Asset {key} ({filename}): size={asset['size']}, sha256={asset['sha256']}")
    else:
        print(f"WARNING: File {filename} not found in build dir!")
    if "url" in asset:
        asset["url"] = asset["url"].replace("v1.9.226-beta11", "v1.9.226-beta12")
    if "sig_url" in asset:
        asset["sig_url"] = asset["sig_url"].replace("v1.9.226-beta11", "v1.9.226-beta12")
    if "mirrors" in asset:
        asset["mirrors"] = [m.replace("v1.9.226-beta11", "v1.9.226-beta12") for m in asset["mirrors"]]

manifest_str = json.dumps(manifest, indent=2, ensure_ascii=False)

with open(new_manifest_path, "w", encoding="utf-8") as f:
    f.write(manifest_str)
print(f"Written {new_manifest_path}")

with open(latest_manifest_path, "w", encoding="utf-8") as f:
    f.write(manifest_str)
print(f"Written {latest_manifest_path}")
