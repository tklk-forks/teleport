#!/usr/bin/env bash
#
# Runs inside Dockerfile.server. Builds the linux/amd64 server and tool
# binaries with the repository Makefile, stamped with the given build type.

set -euo pipefail

BUILD_TYPE="${1:?build type required}"
STAMP="-X github.com/gravitational/teleport/lib/modules.teleportBuildType=$BUILD_TYPE"
LOG="build/agpl-make.log"
mkdir -p build

# The '$(...)' references are expanded by make, not by the shell.
# FIDO2=dynamic links tsh and tctl against libfido2 for hardware security keys.
make OS=linux ARCH=amd64 FIDO2=dynamic \
  TELEPORT_LDFLAGS="-ldflags '\$(GO_LDFLAGS) $STAMP'" \
  TOOLS_LDFLAGS="-ldflags '\$(GO_LDFLAGS) \$(KUBECTL_SETVERSION) $STAMP'" \
  build/teleport build/tctl build/tsh build/tbot 2>&1 | tee "$LOG"

# Go does not record -ldflags in build info for -trimpath builds, so check the
# go build commands make ran instead. The last -ldflags flag wins, so the
# requested build type must appear after any other build type.
for bin in teleport tctl tsh tbot; do
  cmd="$(grep -E "go build .* -o build/$bin( |$)" "$LOG" | tail -n 1)"
  last="$(grep -oE 'teleportBuildType=[a-z]+' <<< "$cmd" | tail -n 1)"
  if [[ "$last" != "teleportBuildType=$BUILD_TYPE" ]]; then
    echo "build/$bin was not built with build type $BUILD_TYPE (got '${last:-none}')" >&2
    exit 1
  fi
done
echo "All binaries built with build type $BUILD_TYPE."

# Smoke test: every binary runs and reports the version being built.
VERSION="$(make --no-print-directory -s print-version)"
HOME="$(mktemp -d)"
export HOME
for bin in teleport tctl tsh tbot; do
  if ! "build/$bin" version | grep -qF "$VERSION"; then
    echo "build/$bin version does not report $VERSION" >&2
    exit 1
  fi
done
echo "All binaries run and report version $VERSION."
