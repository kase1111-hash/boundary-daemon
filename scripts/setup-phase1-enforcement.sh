#!/bin/bash
#
# Phase 1 Enforcement Setup Script
# Boundary Daemon - Agent Smith
#
# This script enables ACTUAL kernel-level enforcement for the Boundary Daemon.
# After running this script, the daemon will:
#   - Block network traffic via iptables/nftables (not just log it)
#   - Block USB devices via udev rules (not just detect them)
#   - Filter syscalls via seccomp-bpf (not just monitor them)
#   - Persist protections across daemon restarts
#
# REQUIREMENTS:
#   - Root privileges (sudo)
#   - Linux with systemd
#   - iptables or nftables
#   - udevadm (udev)
#   - Python 3.9+
#
# USAGE:
#   sudo ./scripts/setup-phase1-enforcement.sh [OPTIONS]
#
# OPTIONS:
#   --install       Full installation with enforcement enabled
#   --verify        Verify enforcement is working
#   --test-network  Test network enforcement (blocks traffic briefly)
#   --test-usb      Show USB enforcement status
#   --status        Show current enforcement status
#   --disable       Disable enforcement (return to advisory mode)
#   --help          Show this help
#
# SECURITY NOTE:
#   This script modifies firewall rules and udev configurations.
#   Ensure you have console access in case of lockout.

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SYSTEMD_DIR="/etc/systemd/system"
INSTALL_DIR="/opt/boundary-daemon"
CONFIG_DIR="/etc/boundary-daemon"
LOG_DIR="/var/log/boundary-daemon"
RUN_DIR="/var/run/boundary-daemon"
LIB_DIR="/var/lib/boundary-daemon"
SECCOMP_DIR="/etc/boundary-daemon/seccomp"
UDEV_RULES_DIR="/etc/udev/rules.d"

# Service names
DAEMON_SERVICE="boundary-daemon.service"
WATCHDOG_SERVICE="boundary-watchdog.service"

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║     BOUNDARY DAEMON - PHASE 1 ENFORCEMENT SETUP                  ║"
    echo "║     Kernel-Level Security Enforcement                            ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

print_section() {
    echo ""
    echo -e "${BOLD}━━━ $1 ━━━${NC}"
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (sudo)"
        echo ""
        echo "Usage: sudo $0 --install"
        exit 1
    fi
}

check_platform() {
    if [[ "$(uname)" != "Linux" ]]; then
        print_error "Phase 1 enforcement requires Linux"
        print_info "Windows support is limited - use advisory mode"
        exit 1
    fi
}

check_dependencies() {
    print_section "Checking Dependencies"

    local errors=0

    # Check systemd
    if command -v systemctl &> /dev/null; then
        print_status "systemd: $(systemctl --version | head -1)"
    else
        print_error "systemd not found - required for service management"
        ((errors++))
    fi

    # Check Python
    if command -v python3 &> /dev/null; then
        local py_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")')
        print_status "Python: $py_version"

        # Check version >= 3.9
        local py_minor=$(python3 -c 'import sys; print(sys.version_info.minor)')
        if [[ $py_minor -lt 9 ]]; then
            print_warning "Python 3.9+ recommended (found 3.$py_minor)"
        fi
    else
        print_error "Python 3 not found"
        ((errors++))
    fi

    # Check firewall (iptables or nftables)
    local firewall_found=false
    if command -v nft &> /dev/null; then
        print_status "nftables: $(nft --version 2>/dev/null || echo 'installed')"
        firewall_found=true
    fi
    if command -v iptables &> /dev/null; then
        print_status "iptables: $(iptables --version 2>/dev/null | head -1 || echo 'installed')"
        firewall_found=true
    fi
    if [[ "$firewall_found" == "false" ]]; then
        print_error "Neither iptables nor nftables found - network enforcement will fail"
        ((errors++))
    fi

    # Check udev
    if command -v udevadm &> /dev/null; then
        print_status "udevadm: $(udevadm --version 2>/dev/null || echo 'installed')"
    else
        print_error "udevadm not found - USB enforcement will fail"
        ((errors++))
    fi

    # Check seccomp support
    if [[ -f /proc/sys/kernel/seccomp/actions_avail ]]; then
        print_status "seccomp: $(cat /proc/sys/kernel/seccomp/actions_avail)"
    elif [[ -f /proc/self/status ]]; then
        if grep -q "Seccomp:" /proc/self/status 2>/dev/null; then
            print_status "seccomp: supported (basic)"
        else
            print_warning "seccomp support unclear - process enforcement may be limited"
        fi
    else
        print_warning "Cannot verify seccomp support"
    fi

    # Check container runtime (optional)
    if command -v podman &> /dev/null; then
        print_status "podman: $(podman --version 2>/dev/null | head -1)"
    elif command -v docker &> /dev/null; then
        print_status "docker: $(docker --version 2>/dev/null | head -1)"
    else
        print_info "No container runtime found (optional for process isolation)"
    fi

    echo ""
    if [[ $errors -gt 0 ]]; then
        print_error "Missing $errors required dependencies"
        exit 1
    fi
    print_status "All required dependencies found"
}

create_directories() {
    print_section "Creating Directories"

    local dirs=(
        "$CONFIG_DIR"
        "$LOG_DIR"
        "$RUN_DIR"
        "$LIB_DIR"
        "$SECCOMP_DIR"
        "$INSTALL_DIR"
    )

    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            chmod 700 "$dir"
            print_status "Created $dir"
        else
            print_info "Exists: $dir"
        fi
    done
}

install_configs() {
    print_section "Installing Configuration Files"

    # Install main config
    if [[ -f "$PROJECT_DIR/config/boundary.conf" ]]; then
        cp "$PROJECT_DIR/config/boundary.conf" "$CONFIG_DIR/"
        chmod 600 "$CONFIG_DIR/boundary.conf"
        print_status "Installed boundary.conf"
    fi

    # Install enforcement config
    if [[ -f "$PROJECT_DIR/config/enforcement.conf" ]]; then
        cp "$PROJECT_DIR/config/enforcement.conf" "$CONFIG_DIR/"
        chmod 600 "$CONFIG_DIR/enforcement.conf"
        print_status "Installed enforcement.conf"
    else
        print_error "enforcement.conf not found in $PROJECT_DIR/config/"
        exit 1
    fi
}

install_daemon() {
    print_section "Installing Daemon"

    # Copy daemon code
    if [[ -d "$PROJECT_DIR/daemon" ]]; then
        cp -r "$PROJECT_DIR/daemon" "$INSTALL_DIR/"
        print_status "Installed daemon modules"
    fi

    # Copy API
    if [[ -d "$PROJECT_DIR/api" ]]; then
        cp -r "$PROJECT_DIR/api" "$INSTALL_DIR/"
        print_status "Installed API modules"
    fi

    # Set permissions
    chmod -R 755 "$INSTALL_DIR"
    find "$INSTALL_DIR" -name "*.py" -exec chmod 644 {} \;
}

install_services() {
    print_section "Installing Systemd Services"

    # Install daemon service
    if [[ -f "$PROJECT_DIR/systemd/boundary-daemon.service" ]]; then
        cp "$PROJECT_DIR/systemd/boundary-daemon.service" "$SYSTEMD_DIR/"
        print_status "Installed $DAEMON_SERVICE"
    else
        print_error "boundary-daemon.service not found"
        exit 1
    fi

    # Install watchdog service
    if [[ -f "$PROJECT_DIR/systemd/boundary-watchdog.service" ]]; then
        cp "$PROJECT_DIR/systemd/boundary-watchdog.service" "$SYSTEMD_DIR/"
        print_status "Installed $WATCHDOG_SERVICE"
    fi

    # Reload systemd
    systemctl daemon-reload
    print_status "Reloaded systemd"
}

enable_services() {
    print_section "Enabling Services"

    systemctl enable "$DAEMON_SERVICE" 2>/dev/null || true
    print_status "Enabled $DAEMON_SERVICE"

    if [[ -f "$SYSTEMD_DIR/$WATCHDOG_SERVICE" ]]; then
        systemctl enable "$WATCHDOG_SERVICE" 2>/dev/null || true
        print_status "Enabled $WATCHDOG_SERVICE"
    fi
}

start_services() {
    print_section "Starting Services"

    # Stop existing services first
    systemctl stop "$DAEMON_SERVICE" 2>/dev/null || true
    systemctl stop "$WATCHDOG_SERVICE" 2>/dev/null || true
    sleep 1

    # Start daemon
    systemctl start "$DAEMON_SERVICE"
    sleep 2

    if systemctl is-active --quiet "$DAEMON_SERVICE"; then
        print_status "Started $DAEMON_SERVICE"
    else
        print_error "Failed to start $DAEMON_SERVICE"
        echo ""
        echo "Check logs with: journalctl -u $DAEMON_SERVICE -n 50"
        exit 1
    fi

    # Start watchdog
    if [[ -f "$SYSTEMD_DIR/$WATCHDOG_SERVICE" ]]; then
        systemctl start "$WATCHDOG_SERVICE" 2>/dev/null || true
        sleep 1
        if systemctl is-active --quiet "$WATCHDOG_SERVICE"; then
            print_status "Started $WATCHDOG_SERVICE"
        else
            print_warning "Watchdog not started (may need daemon socket)"
        fi
    fi
}

verify_enforcement() {
    print_section "Verifying Enforcement Status"

    local all_good=true

    # Check daemon is running
    if systemctl is-active --quiet "$DAEMON_SERVICE"; then
        print_status "Daemon service: active"
    else
        print_error "Daemon service: inactive"
        all_good=false
    fi

    # Check for iptables BOUNDARY_DAEMON chain
    if iptables -L BOUNDARY_DAEMON -n 2>/dev/null | grep -q "Chain BOUNDARY_DAEMON"; then
        local rule_count=$(iptables -L BOUNDARY_DAEMON -n 2>/dev/null | wc -l)
        print_status "Network enforcement: active ($(($rule_count - 2)) rules)"
    elif nft list table inet boundary_daemon 2>/dev/null | grep -q "table"; then
        print_status "Network enforcement: active (nftables)"
    else
        print_warning "Network enforcement: no rules detected yet"
        print_info "Rules are applied on mode transition (e.g., AIRGAP)"
    fi

    # Check for udev rules
    if [[ -f "$UDEV_RULES_DIR/99-boundary-usb.rules" ]]; then
        print_status "USB enforcement: rules installed"
    else
        print_warning "USB enforcement: no rules installed yet"
        print_info "Rules are applied on mode transition"
    fi

    # Check for seccomp profiles
    if [[ -d "$SECCOMP_DIR" ]] && ls "$SECCOMP_DIR"/*.json 2>/dev/null | grep -q .; then
        local profile_count=$(ls "$SECCOMP_DIR"/*.json 2>/dev/null | wc -l)
        print_status "Process enforcement: $profile_count seccomp profile(s)"
    else
        print_info "Process enforcement: profiles created on demand"
    fi

    # Check persistence state
    if [[ -f "$LIB_DIR/protection_state.json" ]]; then
        print_status "Protection persistence: state file exists"
    else
        print_info "Protection persistence: will create on first mode change"
    fi

    # Check environment variables in service
    if grep -q "BOUNDARY_NETWORK_ENFORCE=1" "$SYSTEMD_DIR/$DAEMON_SERVICE" 2>/dev/null; then
        print_status "Service config: enforcement enabled"
    else
        print_warning "Service config: enforcement may not be enabled"
    fi

    echo ""
    if [[ "$all_good" == "true" ]]; then
        print_status "Phase 1 enforcement is ready"
    else
        print_warning "Some components need attention"
    fi
}

test_network_enforcement() {
    print_section "Testing Network Enforcement"

    print_warning "This will briefly apply AIRGAP mode rules"
    print_info "Network traffic will be blocked for ~5 seconds"
    echo ""
    read -p "Continue? (y/N) " -n 1 -r
    echo ""

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Test cancelled"
        return
    fi

    # Create a test script that applies and removes rules
    python3 << 'PYTEST'
import sys
sys.path.insert(0, '/opt/boundary-daemon')

try:
    from daemon.enforcement.network_enforcer import NetworkEnforcer
    from daemon.policy_engine import BoundaryMode

    enforcer = NetworkEnforcer()

    if not enforcer.is_available:
        print("Network enforcement not available")
        print(f"  Backend: {enforcer.backend.value}")
        print(f"  Has root: {enforcer._has_root}")
        sys.exit(1)

    print(f"Backend: {enforcer.backend.value}")
    print("Applying AIRGAP mode...")

    success, msg = enforcer.enforce_mode(BoundaryMode.AIRGAP, reason="test", persist=False)
    print(f"Result: {msg}")

    if success:
        print("\nCurrent rules:")
        print(enforcer.get_current_rules()[:500])

        import time
        print("\nWaiting 5 seconds...")
        time.sleep(5)

        print("\nRemoving rules...")
        enforcer.cleanup(force=True)
        print("Rules removed")

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
PYTEST

    print_status "Network enforcement test complete"
}

show_status() {
    print_section "Current Enforcement Status"

    # Service status
    echo -e "${BOLD}Services:${NC}"
    for service in "$DAEMON_SERVICE" "$WATCHDOG_SERVICE"; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^$service"; then
            local status=$(systemctl is-active "$service" 2>/dev/null || echo "inactive")
            local enabled=$(systemctl is-enabled "$service" 2>/dev/null || echo "disabled")

            case $status in
                active)   echo -e "  ${GREEN}●${NC} $service: $status ($enabled)" ;;
                inactive) echo -e "  ${YELLOW}○${NC} $service: $status ($enabled)" ;;
                failed)   echo -e "  ${RED}●${NC} $service: $status ($enabled)" ;;
                *)        echo -e "  ${YELLOW}?${NC} $service: $status ($enabled)" ;;
            esac
        fi
    done

    echo ""
    echo -e "${BOLD}Network Enforcement:${NC}"
    if iptables -L BOUNDARY_DAEMON -n 2>/dev/null | grep -q "Chain"; then
        echo -e "  ${GREEN}●${NC} iptables chain: active"
        iptables -L BOUNDARY_DAEMON -n 2>/dev/null | head -5 | sed 's/^/    /'
    elif nft list table inet boundary_daemon 2>/dev/null | grep -q "table"; then
        echo -e "  ${GREEN}●${NC} nftables table: active"
    else
        echo -e "  ${YELLOW}○${NC} No firewall rules (applied on mode transition)"
    fi

    echo ""
    echo -e "${BOLD}USB Enforcement:${NC}"
    if [[ -f "$UDEV_RULES_DIR/99-boundary-usb.rules" ]]; then
        echo -e "  ${GREEN}●${NC} udev rules: installed"
        head -5 "$UDEV_RULES_DIR/99-boundary-usb.rules" 2>/dev/null | sed 's/^/    /'
    else
        echo -e "  ${YELLOW}○${NC} No udev rules (applied on mode transition)"
    fi

    echo ""
    echo -e "${BOLD}Process Enforcement:${NC}"
    if [[ -d "$SECCOMP_DIR" ]]; then
        local profiles=$(ls "$SECCOMP_DIR"/*.json 2>/dev/null | wc -l)
        if [[ $profiles -gt 0 ]]; then
            echo -e "  ${GREEN}●${NC} seccomp profiles: $profiles installed"
        else
            echo -e "  ${YELLOW}○${NC} seccomp profiles: created on demand"
        fi
    else
        echo -e "  ${YELLOW}○${NC} seccomp directory not created yet"
    fi

    echo ""
    echo -e "${BOLD}Lockdown Status:${NC}"
    if [[ -f "$RUN_DIR/LOCKDOWN" ]]; then
        echo -e "  ${RED}●${NC} SYSTEM IS IN LOCKDOWN"
        cat "$RUN_DIR/LOCKDOWN" | sed 's/^/    /'
    else
        echo -e "  ${GREEN}○${NC} Normal operation"
    fi
}

disable_enforcement() {
    print_section "Disabling Enforcement"

    print_warning "This will return the daemon to advisory-only mode"
    read -p "Continue? (y/N) " -n 1 -r
    echo ""

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Cancelled"
        return
    fi

    # Remove iptables rules
    if iptables -L BOUNDARY_DAEMON -n 2>/dev/null | grep -q "Chain"; then
        iptables -F BOUNDARY_DAEMON 2>/dev/null || true
        iptables -D OUTPUT -j BOUNDARY_DAEMON 2>/dev/null || true
        iptables -X BOUNDARY_DAEMON 2>/dev/null || true
        print_status "Removed iptables rules"
    fi

    # Remove nftables table
    if nft list table inet boundary_daemon 2>/dev/null | grep -q "table"; then
        nft delete table inet boundary_daemon 2>/dev/null || true
        print_status "Removed nftables rules"
    fi

    # Remove udev rules
    if [[ -f "$UDEV_RULES_DIR/99-boundary-usb.rules" ]]; then
        rm "$UDEV_RULES_DIR/99-boundary-usb.rules"
        udevadm control --reload-rules 2>/dev/null || true
        print_status "Removed udev rules"
    fi

    # Clear persistence state
    if [[ -f "$LIB_DIR/protection_state.json" ]]; then
        rm "$LIB_DIR/protection_state.json"
        print_status "Cleared persistence state"
    fi

    print_status "Enforcement disabled"
    print_info "Restart daemon to apply: systemctl restart $DAEMON_SERVICE"
}

show_help() {
    echo "Phase 1 Enforcement Setup - Boundary Daemon"
    echo ""
    echo "Usage: sudo $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --install       Full installation with enforcement enabled"
    echo "  --verify        Verify enforcement is working"
    echo "  --test-network  Test network enforcement (brief traffic block)"
    echo "  --status        Show current enforcement status"
    echo "  --disable       Disable enforcement (advisory mode)"
    echo "  --help          Show this help"
    echo ""
    echo "What Phase 1 Enforcement Does:"
    echo ""
    echo "  ┌────────────────────────────────────────────────────────────┐"
    echo "  │  NETWORK ENFORCEMENT (iptables/nftables)                   │"
    echo "  │  ├─ OPEN:       No restrictions                            │"
    echo "  │  ├─ RESTRICTED: Logging enabled                            │"
    echo "  │  ├─ TRUSTED:    VPN only, other traffic blocked            │"
    echo "  │  ├─ AIRGAP:     Loopback only, all external blocked        │"
    echo "  │  ├─ COLDROOM:   Loopback only                              │"
    echo "  │  └─ LOCKDOWN:   ALL traffic blocked (including loopback)   │"
    echo "  └────────────────────────────────────────────────────────────┘"
    echo ""
    echo "  ┌────────────────────────────────────────────────────────────┐"
    echo "  │  USB ENFORCEMENT (udev rules)                              │"
    echo "  │  ├─ OPEN:       All USB allowed                            │"
    echo "  │  ├─ RESTRICTED: USB storage logged                         │"
    echo "  │  ├─ TRUSTED:    USB storage blocked                        │"
    echo "  │  ├─ AIRGAP:     USB storage blocked                        │"
    echo "  │  ├─ COLDROOM:   All USB blocked except HID (keyboard)      │"
    echo "  │  └─ LOCKDOWN:   ALL new USB blocked                        │"
    echo "  └────────────────────────────────────────────────────────────┘"
    echo ""
    echo "  ┌────────────────────────────────────────────────────────────┐"
    echo "  │  PROCESS ENFORCEMENT (seccomp-bpf)                         │"
    echo "  │  ├─ RESTRICTED: Dangerous syscalls blocked                 │"
    echo "  │  ├─ AIRGAP:     Network syscalls blocked                   │"
    echo "  │  ├─ COLDROOM:   Maximum syscall restrictions               │"
    echo "  │  └─ LOCKDOWN:   Emergency isolation, process termination   │"
    echo "  └────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Requirements:"
    echo "  - Root privileges (sudo)"
    echo "  - Linux with systemd"
    echo "  - iptables or nftables"
    echo "  - udevadm"
    echo ""
    echo "Examples:"
    echo "  sudo $0 --install      # Install and enable enforcement"
    echo "  sudo $0 --status       # Check current status"
    echo "  sudo $0 --verify       # Verify enforcement is working"
    echo ""
}

# Main
print_banner

case "${1:-}" in
    --install)
        check_root
        check_platform
        check_dependencies
        create_directories
        install_configs
        install_daemon
        install_services
        enable_services
        start_services
        verify_enforcement

        echo ""
        echo -e "${GREEN}${BOLD}Phase 1 Enforcement Installation Complete!${NC}"
        echo ""
        echo "Next steps:"
        echo "  1. Check status:    sudo $0 --status"
        echo "  2. View logs:       journalctl -u $DAEMON_SERVICE -f"
        echo "  3. Test mode:       boundaryctl mode airgap"
        echo "  4. Verify rules:    sudo iptables -L BOUNDARY_DAEMON -n"
        echo ""
        echo -e "${YELLOW}NOTE: Firewall/USB rules are applied when you change modes.${NC}"
        echo "      Current mode is TRUSTED. Try: boundaryctl mode airgap"
        ;;

    --verify)
        check_root
        verify_enforcement
        ;;

    --test-network)
        check_root
        test_network_enforcement
        ;;

    --status)
        show_status
        ;;

    --disable)
        check_root
        disable_enforcement
        ;;

    --help|"")
        show_help
        ;;

    *)
        print_error "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac
