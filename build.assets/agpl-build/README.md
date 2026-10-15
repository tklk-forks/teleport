# AGPL build

`build.sh` builds Teleport from this source tree as an AGPL (`oss`) build:

- **Server:** a `linux/amd64` container image running `teleport`, built with
  the repository Makefile inside Docker. It includes the Web UI, PAM, enhanced
  session recording (BPF) and Windows desktop (RDP) support.
- **Clients:** `tsh`, `tctl` and `tbot` for Linux, macOS and Windows,
  cross-compiled with [xgo](https://github.com/techknowlogick/xgo). macOS and
  Windows builds need cgo, which xgo provides. The clients need no Rust.

The checkout is never modified. The script copies it to `build/agpl/src`,
leaves out enterprise code, and applies the changes below to the copy.

| Change | How |
|---|---|
| GitHub organizations that use external SSO are allowed | `patches/0001` |
| Usage reporting and tbot anonymous telemetry are compiled out | `patches/0002` |
| No Community Edition license screen in the Web UI | Binaries are stamped with the `oss` build type |

The `oss` build type is the one Teleport uses for binaries built from the AGPL
source. The Makefile's default `community` stamp is meant for the official
Community Edition downloads, which ship under a separate license and show the
license acknowledgement screen.

## Requirements

- Docker with BuildKit.
- Go, only to install the xgo CLI when it is not already on `PATH`.
- `git`, `make`, `tar`, `zip` and `sha256sum` on the host.

## Usage

```code
$ build.assets/agpl-build/build.sh            # server image and clients
$ build.assets/agpl-build/build.sh server     # server image only
$ build.assets/agpl-build/build.sh clients    # clients only
$ build.assets/agpl-build/build.sh stage      # only stage and patch the source
```

Outputs, under `build/agpl/` by default:

| Path | Contents |
|---|---|
| image `teleport-agpl:<version>` | Server image. Mount your config at `/etc/teleport/teleport.yaml`. |
| `server/` | The `linux/amd64` binaries from the image, with `SHA256SUMS`. |
| `clients/` | One archive per platform with `tsh`, `tctl` and `tbot`, with `SHA256SUMS`. |

Settings are environment variables, documented at the top of `build.sh`. The
most useful are `CLIENT_TARGETS` (xgo target list), `IMAGE` and `OUT_DIR`.
macOS targets carry xgo's version suffix, `darwin-12.0/arm64`, because xgo
otherwise targets macOS 10.12 and Teleport supports macOS 12.0 and later.

## Not included in the clients

These need native libraries that xgo images do not ship, so the clients are
built without them. Browser-based MFA, SSO and Windows Hello still work.

- Hardware security keys through libfido2 on Linux and macOS.
- Touch ID on macOS.
- PIV hardware key support.
- The Rust RDP decoder in `tsh`, used to export desktop session recordings.

## Updating the patches

A patch that no longer applies stops the build with an error naming it.
Regenerate it by making the change in a clean checkout and running
`git diff > build.assets/agpl-build/patches/<name>.patch`.
