#!/usr/bin/env sh
# MCP-Lattice Installer
# Usage: curl -sSfL https://raw.githubusercontent.com/mcp-lattice/mcp-lattice/main/scripts/install.sh | sh
#
# Environment variables:
#   MCPLATTICE_VERSION   - Specific version to install (default: latest)
#   MCPLATTICE_INSTALL   - Installation directory (default: /usr/local/bin)

set -e

REPO="mcp-lattice/mcp-lattice"
INSTALL_DIR="${MCPLATTICE_INSTALL:-/usr/local/bin}"
BINARY_NAME="mcp-lattice"
TMPDIR_ROOT="${TMPDIR:-/tmp}"

# --- Helper functions ---

log() {
    printf "\033[1;34m==>\033[0m %s\n" "$1"
}

success() {
    printf "\033[1;32m==>\033[0m %s\n" "$1"
}

error() {
    printf "\033[1;31mError:\033[0m %s\n" "$1" >&2
    exit 1
}

# --- Detect OS and Architecture ---

detect_os() {
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "${OS}" in
        linux*)   OS="linux" ;;
        darwin*)  OS="darwin" ;;
        mingw*|msys*|cygwin*) OS="windows" ;;
        *)        error "Unsupported operating system: ${OS}" ;;
    esac
    echo "${OS}"
}

detect_arch() {
    ARCH="$(uname -m)"
    case "${ARCH}" in
        x86_64|amd64)   ARCH="amd64" ;;
        aarch64|arm64)  ARCH="arm64" ;;
        *)              error "Unsupported architecture: ${ARCH}" ;;
    esac
    echo "${ARCH}"
}

# --- Determine latest version ---

get_latest_version() {
    if [ -n "${MCPLATTICE_VERSION}" ]; then
        echo "${MCPLATTICE_VERSION}"
        return
    fi

    LATEST_URL="https://api.github.com/repos/${REPO}/releases/latest"

    if command -v curl >/dev/null 2>&1; then
        VERSION=$(curl -sSfL "${LATEST_URL}" | grep '"tag_name"' | sed -E 's/.*"tag_name":\s*"([^"]+)".*/\1/')
    elif command -v wget >/dev/null 2>&1; then
        VERSION=$(wget -qO- "${LATEST_URL}" | grep '"tag_name"' | sed -E 's/.*"tag_name":\s*"([^"]+)".*/\1/')
    else
        error "Neither curl nor wget found. Please install one of them."
    fi

    if [ -z "${VERSION}" ]; then
        error "Could not determine latest version. Set MCPLATTICE_VERSION manually."
    fi

    echo "${VERSION}"
}

# --- Download and verify ---

download_and_install() {
    OS="$(detect_os)"
    ARCH="$(detect_arch)"
    VERSION="$(get_latest_version)"
    VERSION_STRIPPED="${VERSION#v}"

    log "Installing mcp-lattice ${VERSION} for ${OS}/${ARCH}..."

    # Determine archive format
    if [ "${OS}" = "windows" ]; then
        ARCHIVE="mcp-lattice_${VERSION_STRIPPED}_${OS}_${ARCH}.zip"
    else
        ARCHIVE="mcp-lattice_${VERSION_STRIPPED}_${OS}_${ARCH}.tar.gz"
    fi

    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"
    CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

    # Create temporary directory
    WORK_DIR=$(mktemp -d "${TMPDIR_ROOT}/mcp-lattice-install.XXXXXXXX")
    trap 'rm -rf "${WORK_DIR}"' EXIT

    log "Downloading ${ARCHIVE}..."
    if command -v curl >/dev/null 2>&1; then
        curl -sSfL -o "${WORK_DIR}/${ARCHIVE}" "${DOWNLOAD_URL}"
        curl -sSfL -o "${WORK_DIR}/checksums.txt" "${CHECKSUM_URL}"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "${WORK_DIR}/${ARCHIVE}" "${DOWNLOAD_URL}"
        wget -q -O "${WORK_DIR}/checksums.txt" "${CHECKSUM_URL}"
    fi

    # Verify checksum
    log "Verifying checksum..."
    EXPECTED_CHECKSUM=$(grep "${ARCHIVE}" "${WORK_DIR}/checksums.txt" | awk '{print $1}')

    if [ -z "${EXPECTED_CHECKSUM}" ]; then
        error "Could not find checksum for ${ARCHIVE}"
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL_CHECKSUM=$(sha256sum "${WORK_DIR}/${ARCHIVE}" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        ACTUAL_CHECKSUM=$(shasum -a 256 "${WORK_DIR}/${ARCHIVE}" | awk '{print $1}')
    else
        error "Neither sha256sum nor shasum found. Cannot verify checksum."
    fi

    if [ "${EXPECTED_CHECKSUM}" != "${ACTUAL_CHECKSUM}" ]; then
        error "Checksum verification failed!\n  Expected: ${EXPECTED_CHECKSUM}\n  Actual:   ${ACTUAL_CHECKSUM}"
    fi

    success "Checksum verified"

    # Extract archive
    log "Extracting..."
    cd "${WORK_DIR}"
    if [ "${OS}" = "windows" ]; then
        unzip -q "${ARCHIVE}"
    else
        tar xzf "${ARCHIVE}"
    fi

    # Install binary
    log "Installing to ${INSTALL_DIR}..."
    if [ -w "${INSTALL_DIR}" ]; then
        cp "${WORK_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
        chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    else
        sudo cp "${WORK_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
        sudo chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    fi

    # Verify installation
    if command -v "${INSTALL_DIR}/${BINARY_NAME}" >/dev/null 2>&1; then
        INSTALLED_VERSION=$("${INSTALL_DIR}/${BINARY_NAME}" version 2>/dev/null || echo "${VERSION}")
        success "mcp-lattice ${VERSION} installed successfully!"
    else
        success "mcp-lattice ${VERSION} installed to ${INSTALL_DIR}/${BINARY_NAME}"
    fi

    echo ""
    echo "┌─────────────────────────────────────────────────────────┐"
    echo "│                   MCP-Lattice Quickstart                    │"
    echo "├─────────────────────────────────────────────────────────┤"
    echo "│                                                         │"
    echo "│  Scan an MCP server config:                             │"
    echo "│    mcp-lattice scan ./mcp-config.json                       │"
    echo "│                                                         │"
    echo "│  Scan with SARIF output:                                │"
    echo "│    mcp-lattice scan ./mcp-config.json -f sarif -o report    │"
    echo "│                                                         │"
    echo "│  List available security checks:                        │"
    echo "│    mcp-lattice list-checks                                  │"
    echo "│                                                         │"
    echo "│  Documentation:                                         │"
    echo "│    https://github.com/panavinsingh/MCP-Lattice                   │"
    echo "│                                                         │"
    echo "└─────────────────────────────────────────────────────────┘"
}

# --- Main ---

download_and_install
