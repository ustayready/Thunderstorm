#!/usr/bin/env sh
# Refresh the vendored RAGE snapshot at collectors/rage/ from a RAGE checkout.
#
# The thunderstorm binary embeds this snapshot (see collectors/embed.go). RAGE is
# the source of truth; this copies the runtime registries in. Invoke it via any of:
#   make RAGE_ROOT=/path/to/RAGE build      # re-vendor, then build
#   make vendor-rage RAGE_ROOT=/path        # re-vendor only
#   RAGE_ROOT=/path go generate ./...       # from the collectors module
#
# Resolves its destination relative to this script, so cwd does not matter.
set -eu
: "${RAGE_ROOT:?set RAGE_ROOT to your RAGE checkout}"

# Expand a leading ~ — shells don't tilde-expand `make VAR=~/x` arguments.
case "$RAGE_ROOT" in
  "~")   RAGE_ROOT="$HOME" ;;
  "~/"*) RAGE_ROOT="$HOME/${RAGE_ROOT#\~/}" ;;
esac

DEST="$(cd "$(dirname "$0")/.." && pwd)/rage"   # collectors/rage
mkdir -p "$DEST/providers" "$DEST/exposure-db" "$DEST/vocab"

cp "$RAGE_ROOT"/providers/aws.json "$RAGE_ROOT"/providers/gcp.json "$RAGE_ROOT"/providers/azure.json "$DEST/providers/"
cp "$RAGE_ROOT"/exposure-db/aws.json "$RAGE_ROOT"/exposure-db/gcp.json "$RAGE_ROOT"/exposure-db/azure.json "$RAGE_ROOT"/exposure-db/vocabulary.json "$DEST/exposure-db/"
cp "$RAGE_ROOT"/vocab/node-types.json "$RAGE_ROOT"/vocab/edge-types.json "$RAGE_ROOT"/vocab/conditions.json "$DEST/vocab/"

echo ">> vendored RAGE snapshot from $RAGE_ROOT"
