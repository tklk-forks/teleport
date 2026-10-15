#!/usr/bin/env bash
#
# Builds Teleport from this AGPL source tree.
#
# Customizations applied to a staged copy of the source (the checkout itself
# is never modified):
#   - patches/0001: GitHub organizations that use external SSO are allowed.
#   - patches/0002: usage reporting and anonymous telemetry are compiled out.
#   - Binaries are stamped with the "oss" build type, which is the build type
#     for binaries built from the AGPL source. The Web UI therefore shows the
#     AGPL footer and no Community Edition license acknowledgement screen.
#
# Outputs:
#   server   linux/amd64 container image ($IMAGE) running teleport, plus the
#            linux/amd64 binaries copied to $OUT_DIR/server/.
#   clients  tsh, tctl and tbot for $CLIENT_TARGETS, cross-compiled with xgo
#            (cgo is required on macOS and Windows), packaged per platform in
#            $OUT_DIR/clients/ with a SHA256SUMS file.
#
# Usage:
#   build.assets/agpl-build/build.sh [all|server|clients|stage]
#
# Environment:
#   OUT_DIR          output directory (default: build/agpl)
#   IMAGE            server image name (default: teleport-agpl:<version>)
#   CLIENT_TARGETS   xgo targets (default: linux/amd64,linux/arm64,darwin-12.0/amd64,
#                    darwin-12.0/arm64,windows/amd64). macOS 12.0 is the oldest
#                    version Teleport supports.
#   CLIENT_BINARIES  client binaries to build (default: tsh tctl tbot)
#   XGO_IMAGE        xgo image (default: ghcr.io/techknowlogick/xgo:go-<go version from versions.mk>)
#   XGO_VERSION      xgo CLI version installed when xgo is not on PATH (default: v1.9.0)
#   DOCKER           docker CLI (default: docker)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
HERE="$ROOT/build.assets/agpl-build"

OUT_DIR="$(realpath -m "${OUT_DIR:-$ROOT/build/agpl}")"
STAGE_DIR="$OUT_DIR/src"
DOCKER="${DOCKER:-docker}"
CLIENT_TARGETS="${CLIENT_TARGETS:-linux/amd64,linux/arm64,darwin-12.0/amd64,darwin-12.0/arm64,windows/amd64}"
CLIENT_BINARIES="${CLIENT_BINARIES:-tsh tctl tbot}"
XGO_VERSION="${XGO_VERSION:-v1.9.0}"

BUILD_TYPE="oss"
BUILD_TYPE_LDFLAG="-X github.com/gravitational/teleport/lib/modules.teleportBuildType=$BUILD_TYPE"
# Matches the tags the Makefile uses for these binaries, minus optional
# features that need extra native libraries (libfido2, Touch ID, PIV) and the
# Rust RDP decoder in tsh, so the clients build without Rust.
CLIENT_TAGS="grpcnotrace kustomize_disable_go_plugin_support"

log() { printf '\033[1;32m==>\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

version() { make --no-print-directory -s -C "$ROOT" print-version; }

go_version() {
  awk -F'?= *' '/^GOLANG_VERSION/ { sub(/^go/, "", $2); print $2 }' "$ROOT/build.assets/versions.mk"
}

node_version() {
  awk -F'?= *' '/^NODE_VERSION/ { print $2 }' "$ROOT/build.assets/versions.mk"
}

# stage copies the tracked and untracked (non-ignored) files of the checkout
# into $STAGE_DIR and applies the patches. Enterprise code (e/) is excluded so
# the result is always an AGPL build.
stage() {
  log "Staging source in $STAGE_DIR"
  rm -rf "$STAGE_DIR"
  mkdir -p "$STAGE_DIR"
  (
    cd "$ROOT"
    git ls-files -z --cached --others --exclude-standard \
      | grep -zv -e '^e/' -e '^e$' -e '^build/' \
      | while IFS= read -r -d '' f; do [[ -e "$f" ]] && printf '%s\0' "$f"; done \
      | tar --null -T - -cf -
  ) | tar -xf - -C "$STAGE_DIR"

  local patch
  for patch in "$HERE"/patches/*.patch; do
    log "Applying $(basename "$patch")"
    git -C "$STAGE_DIR" apply --check "$patch" \
      || die "$(basename "$patch") no longer applies, update it for this source tree"
    git -C "$STAGE_DIR" apply "$patch"
  done
}

need_docker() {
  command -v "$DOCKER" >/dev/null || die "$DOCKER is required"
  "$DOCKER" info >/dev/null 2>&1 || die "cannot reach the Docker daemon"
}

build_server() {
  need_docker
  local ver image
  ver="$(version)"
  image="${IMAGE:-teleport-agpl:$ver}"

  log "Building server image $image (linux/amd64)"
  DOCKER_BUILDKIT=1 "$DOCKER" build \
    --platform linux/amd64 \
    --file "$HERE/Dockerfile.server" \
    --build-arg "GO_VERSION=$(go_version)" \
    --build-arg "NODE_VERSION=$(node_version)" \
    --build-arg "BUILD_TYPE=$BUILD_TYPE" \
    --tag "$image" \
    "$STAGE_DIR"

  log "Copying linux/amd64 binaries to $OUT_DIR/server"
  rm -rf "$OUT_DIR/server"
  mkdir -p "$OUT_DIR/server"
  local cid
  cid="$("$DOCKER" create --platform linux/amd64 "$image")"
  trap '"$DOCKER" rm -f "$cid" >/dev/null 2>&1 || true' RETURN
  local bin
  for bin in teleport tctl tsh tbot; do
    "$DOCKER" cp "$cid:/usr/local/bin/$bin" "$OUT_DIR/server/$bin"
  done
  (cd "$OUT_DIR/server" && sha256sum teleport tctl tsh tbot > SHA256SUMS)
  log "Server image: $image"
}

ensure_xgo() {
  if command -v xgo >/dev/null; then
    XGO="$(command -v xgo)"
    return
  fi
  command -v go >/dev/null || die "xgo is not on PATH and go is not available to install it"
  log "Installing xgo $XGO_VERSION"
  GOBIN="$OUT_DIR/tools" go install "src.techknowlogick.com/xgo@$XGO_VERSION"
  XGO="$OUT_DIR/tools/xgo"
}

kubectl_version() {
  (cd "$STAGE_DIR" && go list -m -f '{{.Version}}' k8s.io/kubectl 2>/dev/null) \
    || awk '$1 == "k8s.io/kubectl" { print $2; exit }' "$STAGE_DIR/go.mod"
}

build_clients() {
  need_docker
  ensure_xgo
  local ver xgo_image ldflags raw
  ver="$(version)"
  xgo_image="${XGO_IMAGE:-ghcr.io/techknowlogick/xgo:go-$(go_version)}"
  ldflags="-w -s -X k8s.io/component-base/version.gitVersion=$(kubectl_version | sed 's/^v0/v1/') $BUILD_TYPE_LDFLAG"
  raw="$OUT_DIR/xgo"
  rm -rf "$raw" "$OUT_DIR/clients"
  mkdir -p "$raw" "$OUT_DIR/clients"

  local bin
  for bin in $CLIENT_BINARIES; do
    log "Building $bin for $CLIENT_TARGETS with $xgo_image"
    "$XGO" \
      -image "$xgo_image" \
      -targets "$CLIENT_TARGETS" \
      -pkg "tool/$bin" \
      -out "$bin" \
      -dest "$raw" \
      -tags "$CLIENT_TAGS" \
      -ldflags "$ldflags" \
      -trimpath \
      -buildvcs=false \
      "$STAGE_DIR"
  done

  package_clients "$ver" "$raw"
}

# package_clients sorts the xgo outputs (named <bin>-<os>[-<osversion>]-<arch>
# [.exe]) into one archive per platform.
package_clients() {
  local ver="$1" raw="$2" target os arch bin dir found ext
  IFS=',' read -r -a targets <<< "$CLIENT_TARGETS"
  for target in "${targets[@]}"; do
    os="${target%%/*}"; os="${os%%-*}"
    arch="${target##*/}"
    dir="$OUT_DIR/clients/teleport-clients-v$ver-$os-$arch"
    mkdir -p "$dir"
    for bin in $CLIENT_BINARIES; do
      found="$(find "$raw" -maxdepth 1 -type f -name "$bin-$os*-$arch*" | head -n 1)"
      [[ -n "$found" ]] || die "missing $bin output for $target"
      ext=""; [[ "$os" == windows ]] && ext=".exe"
      cp "$found" "$dir/$bin$ext"
      chmod +x "$dir/$bin$ext"
    done
    cp "$ROOT/LICENSE" "$dir/"
    if [[ "$os" == windows ]]; then
      (cd "$OUT_DIR/clients" && rm -f "$(basename "$dir").zip" && zip -qr "$(basename "$dir").zip" "$(basename "$dir")")
    else
      tar -C "$OUT_DIR/clients" -czf "$dir.tar.gz" "$(basename "$dir")"
    fi
    rm -rf "$dir"
  done
  (cd "$OUT_DIR/clients" && sha256sum teleport-clients-* > SHA256SUMS)
  log "Client archives in $OUT_DIR/clients"
}

main() {
  local cmd="${1:-all}"
  case "$cmd" in
    stage)   stage ;;
    server)  need_docker; stage; build_server ;;
    clients) need_docker; stage; build_clients ;;
    all)     need_docker; stage; build_server; build_clients ;;
    -h|--help|help) sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//' | sed '$d' ;;
    *) die "unknown command: $cmd (expected all, server, clients or stage)" ;;
  esac
}

main "$@"
