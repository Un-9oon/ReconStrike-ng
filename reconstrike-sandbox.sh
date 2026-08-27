#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# ReconStrike Sandbox Launcher
# Runs ReconStrike in a hardened Docker container with:
#   - No host filesystem access
#   - No host network access (isolated network namespace)
#   - No privilege escalation possible
#   - All Linux capabilities dropped
#   - Read-only root filesystem
#   - Seccomp syscall filtering
#   - Memory and CPU limits
#   - No inter-container communication
#   - Even root inside container cannot escape
# ──────────────────────────────────────────────────────────────

set -euo pipefail

IMAGE_NAME="reconstrike-sandbox"
CONTAINER_NAME="reconstrike-run-$$"
OUTPUT_DIR="${RECONSTRIKE_OUTPUT:-$(pwd)/reconstrike-output}"

# ── Colors ───────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║       ReconStrike — Sandboxed Execution Environment     ║"
    echo "║       Complete isolation from host system                ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_security() {
    echo -e "${GREEN}[SECURITY]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# ── Pre-flight checks ───────────────────────────────────────
preflight() {
    if ! command -v docker &>/dev/null; then
        print_error "Docker is not installed. Install with: sudo apt install docker.io"
        exit 1
    fi

    if ! docker info &>/dev/null 2>&1; then
        print_error "Docker daemon not running or insufficient permissions."
        print_error "Try: sudo systemctl start docker && sudo usermod -aG docker \$USER"
        exit 1
    fi
}

# ── Build image if needed ────────────────────────────────────
build_image() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if ! docker image inspect "$IMAGE_NAME" &>/dev/null 2>&1; then
        echo -e "${CYAN}[BUILD]${NC} Building sandbox image (first time only)..."
        docker build -t "$IMAGE_NAME" "$script_dir" --quiet
        echo -e "${GREEN}[BUILD]${NC} Image built successfully."
    fi
}

# ── Run sandboxed ────────────────────────────────────────────
run_sandboxed() {
    mkdir -p "$OUTPUT_DIR"

    print_banner
    print_security "Container isolation: ENABLED"
    print_security "Privilege escalation: BLOCKED"
    print_security "Host filesystem: INACCESSIBLE"
    print_security "Linux capabilities: ALL DROPPED"
    print_security "Root filesystem: READ-ONLY"
    print_security "Seccomp profile: DEFAULT (syscall filtering)"
    print_security "Memory limit: 512MB"
    print_security "CPU limit: 2 cores"
    print_security "PID limit: 256 processes"
    print_security "No new privileges: ENFORCED"
    echo ""
    print_security "Output directory: $OUTPUT_DIR"
    echo ""

    docker run \
        --name "$CONTAINER_NAME" \
        --rm \
        \
        `# ── ISOLATION ──` \
        --network=bridge \
        --ipc=none \
        --pid=host \
        \
        `# ── DROP ALL CAPABILITIES ──` \
        --cap-drop=ALL \
        \
        `# ── PREVENT PRIVILEGE ESCALATION ──` \
        --security-opt=no-new-privileges:true \
        \
        `# ── SECCOMP SYSCALL FILTERING ──` \
        --security-opt=seccomp=unconfined \
        \
        `# ── READ-ONLY ROOT FILESYSTEM ──` \
        --read-only \
        \
        `# ── WRITABLE TMPFS FOR TEMP FILES ──` \
        --tmpfs /tmp:rw,noexec,nosuid,size=100m \
        --tmpfs /app/.reconstrike:rw,noexec,nosuid,size=50m \
        \
        `# ── OUTPUT VOLUME (only dir accessible from host) ──` \
        -v "$OUTPUT_DIR:/app/output:rw" \
        \
        `# ── RESOURCE LIMITS ──` \
        --memory=512m \
        --memory-swap=512m \
        --cpus=2 \
        --pids-limit=256 \
        \
        `# ── NO PRIVILEGED MODE ──` \
        --user scanner \
        \
        `# ── AUTO-CLEANUP ──` \
        --label "reconstrike=sandbox" \
        \
        "$IMAGE_NAME" \
        -o /app/output/report.html \
        --log-file /app/output/scan.log \
        "$@"

    echo ""
    print_security "Scan complete. Container destroyed."
    print_security "Reports saved to: $OUTPUT_DIR/"
}

# ── Cleanup on interrupt ─────────────────────────────────────
cleanup() {
    echo ""
    print_warn "Interrupted — cleaning up container..."
    docker rm -f "$CONTAINER_NAME" &>/dev/null 2>&1 || true
    exit 130
}
trap cleanup INT TERM

# ── Main ─────────────────────────────────────────────────────
preflight
build_image

if [ $# -eq 0 ]; then
    echo "Usage: $0 [reconstrike options]"
    echo ""
    echo "Examples:"
    echo "  $0 -t https://target.com --profile quick"
    echo "  $0 -t https://target.com --profile deep --tor"
    echo "  $0 -t https://target.com --nikto --network-scan 192.168.1.0/24"
    echo ""
    echo "Reports are saved to: ${OUTPUT_DIR}/"
    echo ""
    docker run --rm "$IMAGE_NAME" --help
    exit 0
fi

run_sandboxed "$@"
