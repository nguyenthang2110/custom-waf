#!/bin/bash
# ============================================================================
# scripts/build.sh - WAF Build Script
# ============================================================================

set -e  # Exit on error
cd "$(dirname "$0")/.."  # Always run from repo root

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="waf"
VERSION=${VERSION:-"1.0.0"}
BUILD_DIR="bin"
GOMODCACHE_DIR="${PWD}/.gomodcache"
GOCACHE_DIR="${PWD}/.gocache"
LDFLAGS="-s -w -X main.version=${VERSION} -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
PLATFORMS=("linux/amd64" "darwin/amd64" "windows/amd64")

go_cmd() {
    GOMODCACHE="${GOMODCACHE_DIR}" GOCACHE="${GOCACHE_DIR}" go "$@"
}

# Functions
print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║                                                      ║"
    echo "║   WAF Build Script                                   ║"
    echo "║   Version: ${VERSION}                                      ║"
    echo "║                                                      ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "${BLUE}==>${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_step "Checking prerequisites..."
    
    if ! command -v go &> /dev/null; then
        print_error "Go is not installed. Please install Go 1.21 or later."
        exit 1
    fi
    
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    print_success "Go version: ${GO_VERSION}"
    
    if ! command -v git &> /dev/null; then
        print_warning "Git is not installed (optional)"
    else
        print_success "Git found"
    fi
}

# Clean previous builds
clean() {
    print_step "Cleaning previous builds..."
    rm -rf ${BUILD_DIR}
    print_success "Cleaned ${BUILD_DIR}/"
}

# Download dependencies
download_deps() {
    print_step "Downloading dependencies..."
    go_cmd mod download
    go_cmd mod tidy
    print_success "Dependencies downloaded"
}

# Run tests
run_tests() {
    print_step "Running tests..."
    if go_cmd test ./... -v; then
        print_success "All tests passed"
    else
        print_error "Tests failed"
        exit 1
    fi
}

# Build for single platform
build_platform() {
    local GOOS=$1
    local GOARCH=$2
    local OUTPUT="${BUILD_DIR}/${PROJECT_NAME}-${GOOS}-${GOARCH}"
    
    if [ "${GOOS}" = "windows" ]; then
        OUTPUT="${OUTPUT}.exe"
    fi
    
    print_step "Building for ${GOOS}/${GOARCH}..."
    
    GOOS=${GOOS} GOARCH=${GOARCH} go_cmd build \
        -ldflags="${LDFLAGS}" \
        -o ${OUTPUT} \
        ./cmd/waf
    
    if [ $? -eq 0 ]; then
        SIZE=$(du -h ${OUTPUT} | cut -f1)
        print_success "Built ${OUTPUT} (${SIZE})"
    else
        print_error "Failed to build ${OUTPUT}"
        exit 1
    fi
}

# Build for all platforms
build_all() {
    print_step "Building for all platforms..."
    mkdir -p ${BUILD_DIR}
    
    for platform in "${PLATFORMS[@]}"; do
        IFS='/' read -r GOOS GOARCH <<< "$platform"
        build_platform ${GOOS} ${GOARCH}
    done
    
    print_success "Built for all platforms"
}

# Build for current platform only
build_current() {
    print_step "Building for current platform..."
    mkdir -p ${BUILD_DIR}
    
    go_cmd build \
        -ldflags="${LDFLAGS}" \
        -o ${BUILD_DIR}/${PROJECT_NAME} \
        ./cmd/waf
    
    if [ $? -eq 0 ]; then
        SIZE=$(du -h ${BUILD_DIR}/${PROJECT_NAME} | cut -f1)
        print_success "Built ${BUILD_DIR}/${PROJECT_NAME} (${SIZE})"
    else
        print_error "Build failed"
        exit 1
    fi
}

# Generate checksums
generate_checksums() {
    print_step "Generating checksums..."
    cd ${BUILD_DIR}
    sha256sum * > checksums.txt
    cd - > /dev/null
    print_success "Checksums generated: ${BUILD_DIR}/checksums.txt"
}

# Create release archive
create_archive() {
    print_step "Creating release archive..."
    local ARCHIVE_NAME="${PROJECT_NAME}-${VERSION}.tar.gz"
    
    tar -czf ${BUILD_DIR}/${ARCHIVE_NAME} \
        -C ${BUILD_DIR} \
        $(ls ${BUILD_DIR} | grep -v ".tar.gz")
    
    print_success "Archive created: ${BUILD_DIR}/${ARCHIVE_NAME}"
}

# Display build info
display_info() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║               Build Completed Successfully           ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Build artifacts:"
    ls -lh ${BUILD_DIR}
    echo ""
    echo "To run the WAF:"
    echo "  ${BUILD_DIR}/${PROJECT_NAME} -config configs/config.yaml"
    echo ""
}

# Main build process
main() {
    print_banner
    
    case "${1:-current}" in
        all)
            check_prerequisites
            clean
            download_deps
            run_tests
            build_all
            generate_checksums
            create_archive
            display_info
            ;;
        current)
            check_prerequisites
            clean
            download_deps
            build_current
            display_info
            ;;
        clean)
            clean
            ;;
        test)
            run_tests
            ;;
        *)
            echo "Usage: $0 {all|current|clean|test}"
            echo ""
            echo "  all     - Build for all platforms"
            echo "  current - Build for current platform only (default)"
            echo "  clean   - Clean build artifacts"
            echo "  test    - Run tests only"
            exit 1
            ;;
    esac
}

main "$@"
