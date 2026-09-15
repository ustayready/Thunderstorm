# Thunderstorm — one-command build.
#
#   make                          build the `thunderstorm` binary into ./bin/
#   make RAGE_ROOT=/path/to/rage  re-vendor the RAGE snapshot from a checkout, then build
#   make vendor-rage RAGE_ROOT=…  re-vendor collectors/rage/ only (no build)
#   make test                     run collector + engine test suites
#   make clean                    remove ./bin/
#
# The binary lands at ./bin/thunderstorm regardless of which module it lives in,
# so there's nothing to hunt for after cloning.

BIN_DIR := bin
BINARY  := $(BIN_DIR)/thunderstorm

# Blaze Lite viewer: the single self-contained HTML at viewer/blaze-lite.html is
# the source of truth; it is mirrored into the collector so the `view` command can
# embed it in the binary. `make viewer` rebuilds it from viewer/src/ and syncs the copy.
VIEWER_SRC   := viewer/blaze-lite.html
VIEWER_EMBED := collectors/internal/view/blaze-lite.html

# Optional RAGE refresh: pass RAGE_ROOT=/path/to/rage to re-vendor collectors/rage/
# from a live checkout before building; omit it to build with the current embed.
RAGE_ROOT ?=

.PHONY: build vendor-rage test clean viewer

build: vendor-rage viewer
	cd collectors && go build -trimpath -o ../$(BINARY) ./cmd/thunderstorm
	@echo "built ./$(BINARY)"

# Re-vendor the embedded RAGE snapshot — only when RAGE_ROOT is set (optional).
vendor-rage:
ifneq ($(strip $(RAGE_ROOT)),)
	@RAGE_ROOT="$(RAGE_ROOT)" sh collectors/scripts/vendor-rage.sh
else
	@echo ">> RAGE_ROOT not set — building with the existing vendored snapshot"
endif

viewer:
	@sh viewer/src/build.sh >/dev/null
	@cp $(VIEWER_SRC) $(VIEWER_EMBED)
	@echo "synced $(VIEWER_EMBED)"

test:
	cd collectors && go test ./...
	cd engine && go test ./...

clean:
	rm -rf $(BIN_DIR)
