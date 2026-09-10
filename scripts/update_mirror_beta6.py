import json
import hashlib
from pathlib import Path

build_dir = Path(r"e:\qwen\fnat\build")
old_manifest_path = Path(r"e:\qwen\fnat\mirror\releases\v1.9.226-beta5.json")
new_manifest_path = Path(r"e:\qwen\fnat\mirror\releases\v1.9.226-beta6.json")
latest_manifest_path = Path(r"e:\qwen\fnat\mirror\releases\latest-beta.json")

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

with open(old_manifest_path, "r", encoding="utf-8") as f:
    manifest = json.load(f)

manifest["version"] = "v1.9.226-beta6"
manifest["published_at"] = "2026-09-10T13:30:00Z"
manifest["html_url"] = "https://github.com/jamixm4-crypto/natbypass/releases/tag/v1.9.226-beta6"
manifest["release_notes"] = "**Full Changelog**: https://github.com/jamixm4-crypto/natbypass/compare/v1.9.226-beta5...v1.9.226-beta6"

# Update asset download URLs and sha256
for key, asset in manifest.get("assets", {}).items():
    filename = asset.get("name")
    file_path = build_dir / filename if filename else None
    if file_path and file_path.exists():
        asset["sha256"] = sha256_file(file_path)
        asset["size"] = file_path.stat().st_size
    if "url" in asset:
        asset["url"] = asset["url"].replace("v1.9.226-beta5", "v1.9.226-beta6")
    if "sig_url" in asset:
        asset["sig_url"] = asset["sig_url"].replace("v1.9.226-beta5", "v1.9.226-beta6")
    if "mirrors" in asset:
        asset["mirrors"] = [m.replace("v1.9.226-beta5", "v1.9.226-beta6") for m in asset["mirrors"]]

manifest_str = json.dumps(manifest, indent=2, ensure_ascii=False)

with open(new_manifest_path, "w", encoding="utf-8") as f:
    f.write(manifest_str)
print(f"Written {new_manifest_path}")

with open(latest_manifest_path, "w", encoding="utf-8") as f:
    f.write(manifest_str)
print(f"Written {latest_manifest_path}")
