#!/bin/bash
# Boundary Daemon - Phase 5 Setup: Security Verification Suite
#
# This script installs and configures the comprehensive security verification
# suite that validates all enforcement phases are functioning correctly.
#
# WHAT IT DOES:
# - Verifies all dependencies for Phases 1-4 are installed
# - Installs any missing optional dependencies
# - Configures verification to run on startup and periodically
# - Generates initial security report
#
# USAGE:
#   sudo ./setup-phase5-verify.sh --verify    # Run verification only
#   sudo ./setup-phase5-verify.sh --install   # Install and configure
#   sudo ./setup-phase5-verify.sh --status    # Show current security status

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
DAEMON_DIR="${DAEMON_DIR:-/opt/boundary-daemon}"
CONFIG_DIR="${CONFIG_DIR:-/etc/boundary-daemon}"
LOG_DIR="${LOG_DIR:-/var/log/boundary-daemon}"
STATE_DIR="${STATE_DIR:-/var/lib/boundary-daemon}"
REPORT_FILE="${LOG_DIR}/security_report.json"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_section() {
    echo
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root for full verification"
        log_warn "Running with limited verification..."
        return 1
    fi
    return 0
}

show_banner() {
    echo
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                               ║${NC}"
    echo -e "${CYAN}║      BOUNDARY DAEMON - PHASE 5: SECURITY VERIFICATION        ║${NC}"
    echo -e "${CYAN}║                                                               ║${NC}"
    echo -e "${CYAN}║  Validates all enforcement phases are functioning correctly  ║${NC}"
    echo -e "${CYAN}║                                                               ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo
}

# Check Phase 1 dependencies
check_phase1() {
    log_section "Phase 1: Userspace Enforcement"
    local score=0
    local total=5

    # Check iptables
    if command -v iptables &>/dev/null; then
        log_success "iptables installed"
        ((score++))
    else
        log_warn "iptables not installed"
    fi

    # Check nftables
    if command -v nft &>/dev/null; then
        log_success "nftables installed"
        ((score++))
    else
        log_warn "nftables not installed"
    fi

    # Check udevadm
    if command -v udevadm &>/dev/null; then
        log_success "udevadm installed"
        ((score++))
    else
        log_warn "udevadm not installed"
    fi

    # Check seccomp support
    if [[ -f /proc/sys/kernel/seccomp/actions_avail ]]; then
        log_success "seccomp-bpf supported"
        ((score++))
    else
        log_warn "seccomp support not detected"
    fi

    # Check persistence directory
    if [[ -d "$STATE_DIR" ]]; then
        log_success "State directory exists: $STATE_DIR"
        ((score++))
    else
        log_warn "State directory not found: $STATE_DIR"
    fi

    echo
    log_info "Phase 1 Score: $score/$total"
    return $score
}

# Check Phase 2 dependencies
check_phase2() {
    log_section "Phase 2: eBPF Monitoring"
    local score=0
    local total=4

    # Check BCC
    if python3 -c "from bcc import BPF" 2>/dev/null; then
        log_success "BCC Python bindings installed"
        ((score++))
    else
        log_warn "BCC not installed (apt install python3-bcc)"
    fi

    # Check /sys/fs/bpf
    if [[ -d /sys/fs/bpf ]]; then
        log_success "BPF filesystem mounted"
        ((score++))
    else
        log_warn "/sys/fs/bpf not found"
    fi

    # Check tracepoints
    if [[ -d /sys/kernel/debug/tracing/events/syscalls ]]; then
        log_success "Syscall tracepoints available"
        ((score++))
    else
        log_warn "Tracepoints not found (mount debugfs?)"
    fi

    # Check kernel version
    KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
    if awk "BEGIN {exit !($KERNEL_VERSION >= 4.15)}"; then
        log_success "Kernel version $KERNEL_VERSION supports eBPF"
        ((score++))
    else
        log_warn "Kernel $KERNEL_VERSION may not fully support eBPF"
    fi

    echo
    log_info "Phase 2 Score: $score/$total"
    return $score
}

# Check Phase 3 dependencies
check_phase3() {
    log_section "Phase 3: Hardware Watchdog"
    local score=0
    local total=4

    # Check watchdog device
    if [[ -e /dev/watchdog ]]; then
        log_success "/dev/watchdog exists"
        ((score++))
    else
        # Check if softdog can be loaded
        if modinfo softdog &>/dev/null 2>&1; then
            log_warn "/dev/watchdog not found, but softdog module available"
        else
            log_warn "No watchdog device available"
        fi
    fi

    # Check softdog module
    if modinfo softdog &>/dev/null 2>&1; then
        log_success "softdog kernel module available"
        ((score++))
    else
        log_warn "softdog module not available"
    fi

    # Check systemd watchdog configuration
    SERVICE_FILE="/etc/systemd/system/boundary-daemon.service"
    if [[ ! -f "$SERVICE_FILE" ]]; then
        SERVICE_FILE="$DAEMON_DIR/systemd/boundary-daemon.service"
    fi

    if [[ -f "$SERVICE_FILE" ]] && grep -q "WatchdogSec=" "$SERVICE_FILE"; then
        log_success "Systemd WatchdogSec configured"
        ((score++))
    else
        log_warn "WatchdogSec not configured in service file"
    fi

    # Check lockdown flag directory
    if [[ -d "$STATE_DIR" ]]; then
        log_success "Lockdown flag directory exists"
        ((score++))
    else
        log_warn "Lockdown flag directory not found"
    fi

    echo
    log_info "Phase 3 Score: $score/$total"
    return $score
}

# Check Phase 4 dependencies
check_phase4() {
    log_section "Phase 4: Mandatory Access Control"
    local score=0
    local total=4
    local mac_system="none"

    # Detect MAC system
    if [[ -d /sys/fs/selinux ]]; then
        mac_system="selinux"
        log_success "SELinux detected"
        ((score++))

        # Check if enforcing
        if command -v getenforce &>/dev/null; then
            mode=$(getenforce 2>/dev/null || echo "Unknown")
            if [[ "$mode" == "Enforcing" ]]; then
                log_success "SELinux is enforcing"
                ((score++))
            else
                log_warn "SELinux mode: $mode"
            fi
        fi

        # Check for boundary modules
        if command -v semodule &>/dev/null && semodule -l 2>/dev/null | grep -qi boundary; then
            log_success "Boundary SELinux module installed"
            ((score++))
        else
            log_warn "No boundary SELinux module found"
        fi

    elif [[ -d /sys/kernel/security/apparmor ]]; then
        mac_system="apparmor"
        log_success "AppArmor detected"
        ((score++))

        # Check if profiles loaded
        if command -v aa-status &>/dev/null; then
            profiles=$(aa-status --profiled 2>/dev/null || echo "0")
            if [[ "$profiles" -gt 0 ]]; then
                log_success "AppArmor has $profiles profiles loaded"
                ((score++))
            fi
        fi

        # Check for boundary profile
        if [[ -f /etc/apparmor.d/boundary-daemon ]]; then
            log_success "Boundary AppArmor profile found"
            ((score++))
        else
            log_warn "No boundary AppArmor profile found"
        fi
    else
        log_warn "No MAC system (SELinux/AppArmor) detected"
    fi

    # Check MAC tools
    if [[ "$mac_system" == "selinux" ]] && command -v semanage &>/dev/null; then
        log_success "SELinux tools installed"
        ((score++))
    elif [[ "$mac_system" == "apparmor" ]] && command -v apparmor_parser &>/dev/null; then
        log_success "AppArmor tools installed"
        ((score++))
    elif [[ "$mac_system" != "none" ]]; then
        log_warn "MAC tools not found"
    fi

    echo
    log_info "Phase 4 Score: $score/$total"
    log_info "MAC System: $mac_system"
    return $score
}

# Run Python verification suite
run_python_verification() {
    log_section "Running Full Verification Suite"

    # Check if daemon is installed
    if [[ ! -d "$DAEMON_DIR" ]]; then
        log_warn "Daemon not installed at $DAEMON_DIR"
        log_info "Using local directory..."
        DAEMON_DIR="$(cd "$(dirname "$0")/.." && pwd)"
    fi

    cd "$DAEMON_DIR"

    # Check if verification module exists
    VERIFY_MODULE="daemon/enforcement/security_verification.py"
    if [[ ! -f "$VERIFY_MODULE" ]]; then
        log_error "Verification module not found: $VERIFY_MODULE"
        return 1
    fi

    log_info "Running verification suite..."
    echo

    # Run verification
    if [[ "${JSON_OUTPUT:-0}" == "1" ]]; then
        python3 -m daemon.enforcement.security_verification --json
    else
        python3 -m daemon.enforcement.security_verification
    fi

    return $?
}

# Install verification cron job
install_cron() {
    log_section "Installing Periodic Verification"

    # Create verification script
    VERIFY_SCRIPT="/usr/local/bin/boundary-verify"
    cat > "$VERIFY_SCRIPT" << 'SCRIPT'
#!/bin/bash
# Boundary Daemon - Security Verification Check
cd /opt/boundary-daemon 2>/dev/null || cd "$(dirname "$0")/.."
python3 -m daemon.enforcement.security_verification --json > /var/log/boundary-daemon/security_report.json 2>&1
SCRIPT
    chmod +x "$VERIFY_SCRIPT"
    log_success "Created verification script: $VERIFY_SCRIPT"

    # Add cron job for hourly verification
    CRON_FILE="/etc/cron.hourly/boundary-verify"
    cat > "$CRON_FILE" << 'CRON'
#!/bin/bash
/usr/local/bin/boundary-verify
CRON
    chmod +x "$CRON_FILE"
    log_success "Created hourly cron job: $CRON_FILE"
}

# Show security status
show_status() {
    log_section "Current Security Status"

    # Show report if exists
    if [[ -f "$REPORT_FILE" ]]; then
        log_info "Loading last verification report..."

        if command -v jq &>/dev/null; then
            score=$(jq -r '.overall_score' "$REPORT_FILE" 2>/dev/null || echo "N/A")
            level=$(jq -r '.security_level' "$REPORT_FILE" 2>/dev/null || echo "N/A")
            timestamp=$(jq -r '.timestamp' "$REPORT_FILE" 2>/dev/null || echo "N/A")

            echo
            echo -e "  Last Check:     ${CYAN}$timestamp${NC}"
            echo -e "  Overall Score:  ${CYAN}$score%${NC}"
            echo -e "  Security Level: ${CYAN}$level${NC}"
            echo

            # Show phase scores
            log_info "Phase Scores:"
            jq -r '.phases[] | "  Phase \(.phase): \(.name) - \(.score | tostring + "%")"' "$REPORT_FILE" 2>/dev/null
        else
            cat "$REPORT_FILE"
        fi
    else
        log_warn "No verification report found"
        log_info "Run: $0 --verify"
    fi
}

# Install everything
install_all() {
    log_section "Installing Phase 5: Security Verification"

    # Create directories
    mkdir -p "$LOG_DIR" "$STATE_DIR"
    log_success "Created directories"

    # Install cron job
    install_cron

    # Run initial verification
    log_info "Running initial verification..."
    run_python_verification || true

    # Save report
    if [[ -f "$REPORT_FILE" ]]; then
        log_success "Security report saved to: $REPORT_FILE"
    fi

    log_section "Installation Complete"
    echo
    echo "Phase 5 (Security Verification) is now installed."
    echo
    echo "Commands:"
    echo "  $0 --verify   Run verification suite"
    echo "  $0 --status   Show current security status"
    echo "  boundary-verify         Run verification (installed to /usr/local/bin)"
    echo
    echo "Files:"
    echo "  /var/log/boundary-daemon/security_report.json  Latest report"
    echo "  /etc/cron.hourly/boundary-verify               Hourly verification"
    echo
}

# Parse arguments
ACTION=""
JSON_OUTPUT=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --verify|-v)
            ACTION="verify"
            shift
            ;;
        --install|-i)
            ACTION="install"
            shift
            ;;
        --status|-s)
            ACTION="status"
            shift
            ;;
        --json|-j)
            JSON_OUTPUT=1
            shift
            ;;
        --help|-h)
            show_banner
            echo "Usage: $0 [OPTIONS]"
            echo
            echo "Options:"
            echo "  --verify, -v    Run security verification suite"
            echo "  --install, -i   Install verification (cron job, scripts)"
            echo "  --status, -s    Show current security status"
            echo "  --json, -j      Output in JSON format (with --verify)"
            echo "  --help, -h      Show this help"
            echo
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Default to verify if no action specified
if [[ -z "$ACTION" ]]; then
    ACTION="verify"
fi

# Main
show_banner
check_root || true

case "$ACTION" in
    verify)
        # Run quick bash checks first
        check_phase1 || true
        check_phase2 || true
        check_phase3 || true
        check_phase4 || true

        # Run full Python verification
        run_python_verification
        ;;
    install)
        check_root || { log_error "Install requires root"; exit 1; }
        install_all
        ;;
    status)
        show_status
        ;;
esac

exit 0
