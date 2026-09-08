#!/bin/sh
# Installer for the jwt CLI (https://github.com/lazhari/jwt).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/lazhari/jwt/main/install.sh | sh
#
# Environment:
#   JWT_VERSION      Release to install, for example 2.0.1. Default: latest.
#   JWT_INSTALL_DIR  Target directory. Default: /usr/local/bin when writable,
#                    otherwise $HOME/.local/bin.
#
# The script downloads the release archive for this OS and CPU, verifies its
# SHA-256 against the release's checksums.txt, and copies the binary into the
# install directory. It never calls sudo; run it with `sudo sh` for a
# system-wide install. Supported: Linux and macOS on x86_64, arm64, and armv7.

set -eu

REPO="lazhari/jwt"
BINARY="jwt"
RELEASES="https://github.com/${REPO}/releases"

log() { printf '%s\n' "$*" >&2; }
fail() { log "install.sh: $*"; exit 1; }

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

# download URL DEST: fetch with curl or wget, whichever exists.
download() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        fail "need curl or wget to download files"
    fi
}

# latest_version TMPDIR: GitHub redirects /releases/latest/download/<asset> to
# the newest release, and every archive name in checksums.txt carries the
# version, so no API call and no redirect inspection is needed. This works the
# same with curl and with busybox wget.
latest_version() {
    download "${RELEASES}/latest/download/checksums.txt" "$1/latest-checksums.txt" \
        || fail "could not determine the latest release; set JWT_VERSION explicitly"
    v=$(sed -n "s/^[0-9a-f]*  *${BINARY}_\([0-9][^_]*\)_.*/\1/p" "$1/latest-checksums.txt" | head -n 1)
    [ -n "$v" ] || fail "could not read a version from checksums.txt; set JWT_VERSION explicitly"
    printf '%s' "$v"
}

detect_os() {
    case "$(uname -s)" in
        Linux) printf 'Linux' ;;
        Darwin) printf 'Darwin' ;;
        *) fail "unsupported operating system: $(uname -s). Download a build from ${RELEASES}" ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64 | amd64) printf 'x86_64' ;;
        aarch64 | arm64) printf 'arm64' ;;
        armv7l | armv7) printf 'armv7' ;;
        *) fail "unsupported CPU architecture: $(uname -m). Download a build from ${RELEASES}" ;;
    esac
}

# sha256_of FILE: print the hex digest with whichever tool is available.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d ' ' -f 1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d ' ' -f 1
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | sed 's/^.* //'
    else
        fail "need sha256sum, shasum, or openssl to verify the download"
    fi
}

# verify_checksum FILE CHECKSUMS_FILE: fail unless FILE's digest is listed.
verify_checksum() {
    name=$(basename "$1")
    expected=$(grep " ${name}\$" "$2" | cut -d ' ' -f 1)
    [ -n "$expected" ] || fail "no checksum for ${name} in checksums.txt"
    actual=$(sha256_of "$1")
    [ "$expected" = "$actual" ] || fail "checksum mismatch for ${name}: expected ${expected}, got ${actual}"
}

# install_dir: honour JWT_INSTALL_DIR, else the first writable default.
install_dir() {
    if [ -n "${JWT_INSTALL_DIR:-}" ]; then
        printf '%s' "$JWT_INSTALL_DIR"
    elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
        printf '/usr/local/bin'
    else
        printf '%s' "${HOME}/.local/bin"
    fi
}

path_hint() {
    case ":${PATH}:" in
        *":$1:"*) ;;
        *) log "note: $1 is not on your PATH; add it with: export PATH=\"$1:\$PATH\"" ;;
    esac
}

main() {
    need_cmd uname
    need_cmd tar
    need_cmd mktemp

    os=$(detect_os)
    arch=$(detect_arch)
    tmp=$(mktemp -d 2>/dev/null || mktemp -d -t jwt-install)
    trap 'rm -rf "$tmp"' EXIT INT TERM

    version="${JWT_VERSION:-}"
    if [ -z "$version" ]; then
        version=$(latest_version "$tmp")
    fi
    version="${version#v}"

    archive="${BINARY}_${version}_${os}_${arch}.tar.gz"
    base="${RELEASES}/download/v${version}"
    dir=$(install_dir)

    log "Installing ${BINARY} ${version} (${os}/${arch}) into ${dir}"
    download "${base}/${archive}" "${tmp}/${archive}" \
        || fail "download failed: ${base}/${archive} (does version ${version} exist?)"
    download "${base}/checksums.txt" "${tmp}/checksums.txt" \
        || fail "download failed: ${base}/checksums.txt"
    verify_checksum "${tmp}/${archive}" "${tmp}/checksums.txt"

    tar -xzf "${tmp}/${archive}" -C "$tmp" "$BINARY" \
        || fail "could not extract ${BINARY} from ${archive}"

    mkdir -p "$dir" || fail "cannot create ${dir}; set JWT_INSTALL_DIR to a writable directory"
    cp "${tmp}/${BINARY}" "${dir}/${BINARY}.tmp" \
        || fail "cannot write to ${dir}; set JWT_INSTALL_DIR or rerun with sudo"
    chmod 0755 "${dir}/${BINARY}.tmp"
    mv -f "${dir}/${BINARY}.tmp" "${dir}/${BINARY}"

    log "Installed: $("${dir}/${BINARY}" version)"
    path_hint "$dir"
}

main "$@"
