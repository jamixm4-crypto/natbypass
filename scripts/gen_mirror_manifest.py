#!/usr/bin/env python3
"""
gen_mirror_manifest.py — генерация mirror-manifest.json для зеркал NatBypass.

Использование в CI (GitHub Actions):
    python scripts/gen_mirror_manifest.py \
        --tag v1.9.222-beta.13 \
        --token $GITHUB_TOKEN \
        --out-dir dist/mirror

Создаёт:
    dist/mirror/releases/latest.json        (stable)
    dist/mirror/releases/latest-beta.json   (beta)
    dist/mirror/releases/<tag>.json         (конкретный релиз)

Формат совместим с internal/updater/mirrors.go MirrorManifest.
"""

import argparse
import hashlib
import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path


REPO = "jamixm4-crypto/natbypass"
GITHUB_API = f"https://api.github.com/repos/{REPO}"

# Маппинг имён ассетов → ключи MirrorManifest.Assets
ASSET_KEY_MAP = {
    "NatBypass.exe":               "windows/amd64/main",
    "NatBypass-GUI.exe":           "windows/amd64/gui",
    "natbypass-cli.exe":           "windows/amd64/cli",
    "NatBypass-Diag.exe":          "windows/amd64/diag",
    "natbypass-linux-amd64":       "linux/amd64",
    "natbypass-linux-arm64":       "linux/arm64",
    "natbypass-keenetic-mipsle":   "linux/mipsle",
    "natbypass-router-mipsle":     "linux/mipsle",
    "natbypass-router-mips":       "linux/mips",
}


def github_get(url: str, token: str | None = None) -> dict:
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "NatBypass-MirrorBuilder/1.0")
    req.add_header("Accept", "application/vnd.github.v3+json")
    if token:
        req.add_header("Authorization", f"token {token}")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def sha256_of_url(url: str, token: str | None = None) -> str:
    """Скачивает файл и возвращает его SHA-256."""
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "NatBypass-MirrorBuilder/1.0")
    if token:
        req.add_header("Authorization", f"token {token}")
    h = hashlib.sha256()
    with urllib.request.urlopen(req, timeout=120) as resp:
        while chunk := resp.read(65536):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(release: dict, token: str | None, mirror_base: str | None) -> dict:
    tag = release["tag_name"]
    assets_map: dict[str, dict] = {}

    for asset in release.get("assets", []):
        name = asset["name"]
        # Пропускаем .sig, .pem, .apk в основном маппинге
        if name.endswith(".sig") or name.endswith(".pem") or name.endswith(".apk"):
            continue

        key = ASSET_KEY_MAP.get(name)
        if not key:
            continue

        dl_url = asset["browser_download_url"]
        sig_url = dl_url + ".sig"

        print(f"  [{name}] вычисляю SHA-256...", flush=True)
        try:
            sha = sha256_of_url(dl_url, token)
        except Exception as e:
            print(f"  WARN: не удалось получить SHA-256 для {name}: {e}", file=sys.stderr)
            sha = ""

        mirrors = []
        if mirror_base:
            # Зеркало хранит файлы по пути: <mirror_base>/<tag>/<name>
            mirrors.append(f"{mirror_base.rstrip('/')}/{tag}/{name}")

        assets_map[key] = {
            "name": name,
            "url": dl_url,
            "sig_url": sig_url,
            "size": asset["size"],
            "sha256": sha,
            "mirrors": mirrors,
        }

    manifest = {
        "version": tag,
        "published_at": release.get("published_at", ""),
        "prerelease": release.get("prerelease", False),
        "release_notes": (release.get("body") or "").strip(),
        "html_url": release.get("html_url", ""),
        "assets": assets_map,
    }
    return manifest


def write_manifest(manifest: dict, out_dir: Path, filenames: list[str]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    data = json.dumps(manifest, ensure_ascii=False, indent=2)
    for fname in filenames:
        path = out_dir / fname
        path.write_text(data, encoding="utf-8")
        print(f"  Записан: {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate NatBypass mirror manifest")
    parser.add_argument("--tag", required=True, help="Git tag, e.g. v1.9.222-beta.13")
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN"), help="GitHub API token")
    parser.add_argument("--out-dir", default="dist/mirror/releases", help="Output directory")
    parser.add_argument("--mirror-base", default=os.environ.get("MIRROR_BASE_URL", ""),
                        help="Base URL of file mirror, e.g. https://nb-mirror.pages.dev/files")
    args = parser.parse_args()

    tag = args.tag
    out_dir = Path(args.out_dir)
    mirror_base = args.mirror_base or ""

    print(f"=== NatBypass Mirror Manifest Generator ===")
    print(f"Tag:        {tag}")
    print(f"Output:     {out_dir}")
    print(f"Mirror:     {mirror_base or '(none)'}")
    print()

    # Получаем данные релиза из GitHub API
    print(f"Загрузка метаданных релиза {tag}...")
    try:
        release = github_get(f"{GITHUB_API}/releases/tags/{tag}", args.token)
    except urllib.error.HTTPError as e:
        print(f"ОШИБКА: не удалось получить релиз {tag}: HTTP {e.code}", file=sys.stderr)
        sys.exit(1)

    print(f"Релиз: {release['name']}, prerelease={release['prerelease']}")
    print()

    # Строим манифест
    print("Обработка ассетов:")
    manifest = build_manifest(release, args.token, mirror_base)
    print(f"  Ассетов в манифесте: {len(manifest['assets'])}")
    print()

    # Записываем файлы
    is_prerelease = manifest["prerelease"]
    tag_filename = f"{tag}.json"
    filenames = [tag_filename]
    if is_prerelease:
        filenames.append("latest-beta.json")
    else:
        filenames.append("latest.json")
        filenames.append("latest-beta.json")  # стабильный релиз обновляет и beta-канал

    print("Запись манифестов:")
    write_manifest(manifest, out_dir, filenames)

    print()
    print("✓ Манифест сгенерирован успешно.")


if __name__ == "__main__":
    main()
