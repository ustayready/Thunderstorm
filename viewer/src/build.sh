#!/usr/bin/env bash
# Assemble the self-contained, offline Blaze Lite viewer from its sources.
#
#   viewer/src/{head.html, vendor/*.js, app.js, tail.html}  ->  viewer/blaze-lite.html
#
# Vendor libraries are inlined verbatim, each in its own <script> so minified
# IIFEs can't run together. The result is one file that opens over file://.
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
OUT="$SRC/../blaze-lite.html"

{
  cat "$SRC/head.html"
  for lib in cytoscape.min.js layout-base.js cose-base.js cytoscape-fcose.js; do
    printf '\n<script>\n'
    cat "$SRC/vendor/$lib"
    printf '\n</script>\n'
  done
  printf '\n<script>\n'
  cat "$SRC/app.js"
  printf '\n</script>\n'
  cat "$SRC/tail.html"
} > "$OUT"

echo "built $OUT ($(wc -c < "$OUT" | tr -d ' ') bytes)"
