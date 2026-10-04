#!/usr/bin/env python3
"""
sign_releases.py — Создание Ed25519-подписей (.sig) для всех релизных бинарников NatBypass.

Использование:
    python scripts/sign_releases.py --build-dir build --key-hex <PRIV_KEY_HEX>
Или через переменную окружения RELEASE_SIGNING_KEY:
    python scripts/sign_releases.py --build-dir build
"""

import argparse
import os
import sys
from pathlib import Path

try:
    import nacl.signing
    import nacl.encoding
except ImportError:
    print("PyNaCl not installed. Run: pip install pynacl", file=sys.stderr)
    sys.exit(1)


def sign_files(build_dir: Path, key_hex: str):
    signing_key = nacl.signing.SigningKey(key_hex, encoder=nacl.encoding.HexEncoder)
    verify_key_hex = signing_key.verify_key.encode(nacl.encoding.HexEncoder).decode()
    print(f"[SIGN] Using Ed25519 Public Key: {verify_key_hex}")

    for file_path in build_dir.iterdir():
        if not file_path.is_file():
            continue
        if file_path.suffix in [".sig", ".pem", ".sha256", ".txt", ".json", ".md"]:
            continue
        
        # Read file binary content
        data = file_path.read_bytes()
        # Sign raw binary: raw 64-byte Ed25519 signature
        signed = signing_key.sign(data)
        sig_data = signed.signature # 64 bytes
        
        sig_file = file_path.with_name(f"{file_path.name}.sig")
        sig_file.write_bytes(sig_data)
        print(f"[SIGN] Signed {file_path.name} -> {sig_file.name} ({len(sig_data)} bytes)")


def main():
    parser = argparse.ArgumentParser(description="Sign NatBypass release binaries with Ed25519")
    parser.add_argument("--build-dir", default="build", help="Path to build output directory")
    parser.add_argument("--key-hex", default=os.environ.get("RELEASE_SIGNING_KEY", ""), help="64-char Hex Ed25519 private key")
    args = parser.parse_args()

    if not args.key_hex:
        print("ERROR: --key-hex or RELEASE_SIGNING_KEY environment variable required", file=sys.stderr)
        sys.exit(1)

    build_dir = Path(args.build_dir)
    if not build_dir.exists():
        print(f"ERROR: Build directory {build_dir} not found", file=sys.stderr)
        sys.exit(1)

    sign_files(build_dir, args.key_hex.strip())


if __name__ == "__main__":
    main()
