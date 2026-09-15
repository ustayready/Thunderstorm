#!/usr/bin/env bash
# Cross-compile the single `thunderstorm` binary for every release platform, then
# emit a manifest.json (version + per-file size and sha256). Pure-Go deps, so CGO
# is disabled and cross-compile is clean. For a normal local build use `make`.
#
#   ./build-binaries.sh            # build into ../dist
#   OUT=/somewhere ./build-binaries.sh
set -euo pipefail

cd "$(dirname "$0")"
OUT="${OUT:-../dist}"
mkdir -p "$OUT"

VERSION="$(CGO_ENABLED=0 go run ./cmd/thunderstorm version 2>/dev/null | awk '{print $2}')"
ENGINE="$(CGO_ENABLED=0 go run ./cmd/thunderstorm version 2>/dev/null | awk '{print $5}')"
BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# label|goos|goarch|filename
TARGETS=(
  "macOS (Apple Silicon / arm64)|darwin|arm64|thunderstorm-darwin-arm64"
  "macOS (Intel / x86-64)|darwin|amd64|thunderstorm-darwin-amd64"
  "Linux (x86-64)|linux|amd64|thunderstorm-linux-amd64"
  "Windows (x64)|windows|amd64|thunderstorm-windows-amd64.exe"
)

sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }

entries=()
for t in "${TARGETS[@]}"; do
  IFS='|' read -r label goos goarch fname <<<"$t"
  echo "building $goos/$goarch -> $fname"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "-s -w" -o "$OUT/$fname" ./cmd/thunderstorm
  size=$(wc -c < "$OUT/$fname" | tr -d ' ')
  digest=$(sha "$OUT/$fname")
  entries+=("{\"label\":\"$label\",\"os\":\"$goos\",\"arch\":\"$goarch\",\"filename\":\"$fname\",\"size\":$size,\"sha256\":\"$digest\"}")
done

{
  printf '{\n'
  printf '  "version": "%s",\n' "$VERSION"
  printf '  "engine_version": "%s",\n' "$ENGINE"
  printf '  "built_at": "%s",\n' "$BUILT_AT"
  printf '  "files": [\n    %s\n  ]\n' "$(IFS=,; echo "${entries[*]}" | sed 's/,/,\n    /g')"
  printf '}\n'
} > "$OUT/manifest.json"

echo "wrote $OUT/manifest.json (version $VERSION, engine $ENGINE)"
