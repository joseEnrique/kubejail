#!/bin/sh
# kubejail installer for Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/joseEnrique/kubejail/main/install.sh | sh
#
# Environment:
#   KUBEJAIL_VERSION      release tag to install (default: latest), e.g. v0.1.0
#   KUBEJAIL_INSTALL_DIR  where to put the binary (default: /usr/local/bin if
#                         writable, otherwise ~/.local/bin)
set -eu

REPO="joseEnrique/kubejail"
VERSION="${KUBEJAIL_VERSION:-latest}"

say() { printf '%s\n' "$*"; }
die() { printf 'install.sh: error: %s\n' "$*" >&2; exit 1; }

case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=macos ;;
    *) die "unsupported operating system: $(uname -s) (Linux and macOS only)" ;;
esac
case "$(uname -m)" in
    x86_64 | amd64) arch=x86_64 ;;
    arm64 | aarch64) arch=arm64 ;;
    *) die "unsupported architecture: $(uname -m)" ;;
esac
asset="kubejail-${os}-${arch}"

if [ "$VERSION" = latest ]; then
    base="https://github.com/${REPO}/releases/latest/download"
else
    base="https://github.com/${REPO}/releases/download/${VERSION}"
fi

if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -q -O "$2" "$1"; }
else
    die "curl or wget is required"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading ${asset} (${VERSION})..."
fetch "${base}/${asset}" "${tmp}/${asset}" || die "cannot download ${base}/${asset}"
fetch "${base}/${asset}.sha256" "${tmp}/${asset}.sha256" || die "cannot download the checksum"

expected="$(awk '{print $1}' "${tmp}/${asset}.sha256")"
if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "${tmp}/${asset}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "${tmp}/${asset}" | awk '{print $1}')"
else
    die "sha256sum or shasum is required to verify the download"
fi
[ -n "$expected" ] && [ "$expected" = "$actual" ] ||
    die "checksum mismatch for ${asset} (expected ${expected}, got ${actual})"

if [ -n "${KUBEJAIL_INSTALL_DIR:-}" ]; then
    dir="$KUBEJAIL_INSTALL_DIR"
elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    dir=/usr/local/bin
else
    dir="${HOME}/.local/bin"
fi
mkdir -p "$dir" || die "cannot create ${dir}"
chmod 755 "${tmp}/${asset}"
mv -f "${tmp}/${asset}" "${dir}/kubejail" || die "cannot write to ${dir}"

say "Installed ${dir}/kubejail ($("${dir}/kubejail" --version 2>/dev/null || echo "version unknown"))"

case ":${PATH}:" in
    *":${dir}:"*) ;;
    *) say "Note: ${dir} is not in your PATH. Add it with:"
       say "  export PATH=\"${dir}:\$PATH\"" ;;
esac
if [ "$os" = linux ] && ! command -v bwrap >/dev/null 2>&1; then
    say "Note: Bubblewrap (bwrap) is required; install the 'bubblewrap' package."
fi
command -v kubectl >/dev/null 2>&1 || say "Note: kubectl was not found in your PATH."
say "Try: kubejail enter <context> -n <namespace>"
