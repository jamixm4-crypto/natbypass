#!/usr/bin/env bash
# ============================================================
# NatBypass — build.sh: кросс-компиляция под все платформы
# ============================================================
set -euo pipefail

APP="natbypass"
CMD="./cmd/natbypass"
DIST="./dist"
MODULE="github.com/natbypass/natbypass"

VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "unknown")

LDFLAGS="-s -w \
  -X ${MODULE}/cmd/natbypass.Version=${VERSION} \
  -X ${MODULE}/cmd/natbypass.Commit=${COMMIT} \
  -X ${MODULE}/cmd/natbypass.BuildDate=${DATE}"

mkdir -p "${DIST}"

build() {
  local goos="$1"
  local goarch="$2"
  local ext="${3:-}"
  local extra="${4:-}"
  local outname="${APP}-${goos}-${goarch}${ext}"

  echo ">> Сборка ${goos}/${goarch}${extra:+ (${extra})}..."
  env CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" ${extra} \
    go build -trimpath -ldflags="${LDFLAGS}" \
    -o "${DIST}/${outname}" "${CMD}"
  
  local size
  size=$(du -h "${DIST}/${outname}" | cut -f1)
  echo "   OK: ${outname} (${size})"
}

echo "============================================================"
echo " NatBypass Build Script v${VERSION}"
echo " Commit: ${COMMIT}  Date: ${DATE}"
echo "============================================================"
echo ""

# ── Рабочие столы ─────────────────────────────────────────────
build linux   amd64   ""    ""
build windows amd64   ".exe" ""
build linux   arm64   ""    ""

# ── Роутеры MIPS ──────────────────────────────────────────────
build linux   mips    ""    "GOMIPS=softfloat"
build linux   mipsle  ""    "GOMIPS=softfloat"

# ── Мобильные (опционально) ───────────────────────────────────
if [[ "${BUILD_MOBILE:-0}" == "1" ]]; then
  build android arm64 ""
  # iOS: требует macOS + Xcode
  if [[ "$(uname)" == "Darwin" ]]; then
    build ios arm64 ""
  else
    echo ">> iOS: пропуск (требует macOS)"
  fi
fi

echo ""
echo "============================================================"
echo " Сборка завершена. Бинарники в ${DIST}/:"
ls -lh "${DIST}/"
echo "============================================================"

# Проверка размера для MIPS (цель: <10 МБ)
for f in "${DIST}/${APP}-linux-mips" "${DIST}/${APP}-linux-mipsle"; do
  if [[ -f "${f}" ]]; then
    size_bytes=$(stat -c%s "${f}" 2>/dev/null || stat -f%z "${f}")
    size_mb=$(( size_bytes / 1024 / 1024 ))
    if (( size_mb > 10 )); then
      echo "ПРЕДУПРЕЖДЕНИЕ: ${f} = ${size_mb}МБ (цель: <10 МБ)"
    else
      echo "OK: ${f} = ${size_mb}МБ (в норме)"
    fi
  fi
done
