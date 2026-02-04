#!/bin/bash
#
# Phase 3 Hardware Watchdog Setup Script
# Boundary Daemon - Agent Smith
#
# This script configures hardware watchdog protection to ensure the system
# enters lockdown even if the boundary daemon is killed (SIGKILL).
#
# WHAT THIS DOES:
# - Enables systemd watchdog integration (WatchdogSec)
# - Configures hardware/software watchdog (/dev/watchdog)
# - Sets up automatic lockdown on watchdog reset
# - Configures fail-closed boot behavior
#
# HOW IT WORKS:
#   1. Daemon pings watchdog every N seconds
#   2. If daemon is killed → pings stop
#   3. Watchdog timer expires → system resets
#   4. System reboots → daemon detects watchdog reset
#   5. Daemon starts in LOCKDOWN mode
#
# REQUIREMENTS:
#   - Linux with watchdog support (hardware or softdog)
#   - Root privileges
#   - Phase 1 and 2 already installed
#
# USAGE:
#   sudo ./scripts/setup-phase3-watchdog.sh [OPTIONS]
#
# OPTIONS:
#   --install       Install and configure watchdog protection
#   --check         Check watchdog support
#   --test          Test watchdog (WARNING: may reset system!)
#   --status        Show watchdog status
#   --disable       Disable watchdog protection
#   --help          Show this help
#
# WARNING:
#   Hardware watchdog WILL RESET YOUR SYSTEM if the daemon stops pinging.
#   This is by design - it's the ultimate fail-closed protection.
#   Ensure you have console access before enabling.

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
LIB_DIR="/var/lib/boundary-daemon"

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║     BOUNDARY DAEMON - PHASE 3 HARDWARE WATCHDOG                  ║"
    echo "║     Ultimate Fail-Closed Protection                              ║"
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
        exit 1
    fi
}

check_watchdog_support() {
    print_section "Checking Watchdog Support"

    local score=0
    local max_score=5

    # Check for watchdog device
    if [[ -e /dev/watchdog ]]; then
        print_status "/dev/watchdog exists"
        ((score++))

        if [[ -w /dev/watchdog ]]; then
            print_status "/dev/watchdog is writable"
            ((score++))
        else
            print_warning "/dev/watchdog not writable (need root)"
        fi
    else
        print_warning "/dev/watchdog not found"
    fi

    # Check for softdog module
    if lsmod | grep -q softdog 2>/dev/null; then
        print_status "softdog module loaded"
        ((score++))
    elif [[ -f /lib/modules/$(uname -r)/kernel/drivers/watchdog/softdog.ko* ]]; then
        print_info "softdog module available but not loaded"
    else
        print_warning "softdog module not available"
    fi

    # Check kernel config
    if [[ -f /proc/config.gz ]]; then
        if zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_WATCHDOG=y"; then
            print_status "Kernel watchdog support enabled"
            ((score++))
        fi
    elif [[ -f /boot/config-$(uname -r) ]]; then
        if grep -q "CONFIG_WATCHDOG=y" /boot/config-$(uname -r) 2>/dev/null; then
            print_status "Kernel watchdog support enabled"
            ((score++))
        fi
    fi

    # Check systemd watchdog support
    if systemctl --version | grep -q systemd; then
        print_status "systemd available for WatchdogSec"
        ((score++))
    fi

    echo ""
    echo -e "${BOLD}Score: $score/$max_score${NC}"

    if [[ $score -lt 2 ]]; then
        print_error "Insufficient watchdog support"
        return 1
    elif [[ $score -lt 4 ]]; then
        print_warning "Partial watchdog support - may need softdog"
        return 0
    else
        print_status "Good watchdog support"
        return 0
    fi
}

load_softdog() {
    print_section "Loading Software Watchdog"

    if [[ -e /dev/watchdog ]]; then
        print_info "Watchdog device already exists"
        return 0
    fi

    print_info "Loading softdog kernel module..."

    # Load with specific timeout
    if modprobe softdog soft_margin=60 2>/dev/null; then
        print_status "softdog module loaded"
        sleep 1

        if [[ -e /dev/watchdog ]]; then
            print_status "/dev/watchdog created"
            return 0
        else
            print_error "/dev/watchdog not created"
            return 1
        fi
    else
        print_error "Failed to load softdog module"
        return 1
    fi
}

configure_softdog_autoload() {
    print_section "Configuring Softdog Auto-Load"

    # Create modules-load.d config
    local modules_file="/etc/modules-load.d/boundary-watchdog.conf"
    echo "# Boundary Daemon - Load softdog for watchdog support" > "$modules_file"
    echo "softdog" >> "$modules_file"
    print_status "Created $modules_file"

    # Create modprobe config for timeout
    local modprobe_file="/etc/modprobe.d/boundary-watchdog.conf"
    echo "# Boundary Daemon - Softdog configuration" > "$modprobe_file"
    echo "options softdog soft_margin=60" >> "$modprobe_file"
    print_status "Created $modprobe_file"
}

install_watchdog_module() {
    print_section "Installing Watchdog Module"

    # Copy updated daemon code with hardware_watchdog.py
    if [[ -f "$PROJECT_DIR/daemon/enforcement/hardware_watchdog.py" ]]; then
        cp "$PROJECT_DIR/daemon/enforcement/hardware_watchdog.py" \
           "$INSTALL_DIR/daemon/enforcement/"
        print_status "Installed hardware_watchdog.py"
    fi

    # Update __init__.py
    if [[ -f "$PROJECT_DIR/daemon/enforcement/__init__.py" ]]; then
        cp "$PROJECT_DIR/daemon/enforcement/__init__.py" \
           "$INSTALL_DIR/daemon/enforcement/"
        print_status "Updated enforcement __init__.py"
    fi
}

update_systemd_service() {
    print_section "Updating Systemd Service"

    # Copy updated service file
    if [[ -f "$PROJECT_DIR/systemd/boundary-daemon.service" ]]; then
        cp "$PROJECT_DIR/systemd/boundary-daemon.service" "$SYSTEMD_DIR/"
        print_status "Updated boundary-daemon.service"
    fi

    # Reload systemd
    systemctl daemon-reload
    print_status "Reloaded systemd configuration"

    # Verify WatchdogSec is set
    if grep -q "WatchdogSec=" "$SYSTEMD_DIR/boundary-daemon.service"; then
        local watchdog_sec=$(grep "WatchdogSec=" "$SYSTEMD_DIR/boundary-daemon.service" | cut -d= -f2)
        print_status "WatchdogSec configured: ${watchdog_sec}"
    else
        print_warning "WatchdogSec not found in service file"
    fi
}

update_enforcement_config() {
    print_section "Updating Enforcement Configuration"

    local config_file="$CONFIG_DIR/enforcement.conf"

    if [[ -f "$config_file" ]]; then
        # Check if watchdog section exists
        if grep -q "^\[watchdog\]" "$config_file"; then
            print_info "Watchdog configuration section exists"
        else
            print_info "Adding watchdog configuration section..."
            cat >> "$config_file" << 'EOF'

[hardware_watchdog]
# Phase 3: Hardware Watchdog Protection
# Ensures system enters lockdown even if daemon is killed (SIGKILL)

# Enable hardware watchdog
enabled = true

# Watchdog timeout in seconds (system resets if no ping within this time)
timeout = 60

# Pre-timeout warning in seconds (triggers alert before reset)
pretimeout = 10

# Automatic ping from daemon main loop
auto_ping = true

# Ping interval (should be < timeout/2)
ping_interval = 20

# Load softdog module if no hardware watchdog found
load_softdog_if_needed = true

# Boot behavior after watchdog reset
# Options: lockdown, trusted, last_mode
boot_after_reset = lockdown

# Notify systemd watchdog (sd_notify)
systemd_notify = true
EOF
            print_status "Added [hardware_watchdog] section"
        fi
    else
        print_warning "Config file not found: $config_file"
    fi
}

create_lockdown_marker_dir() {
    print_section "Creating Lockdown Marker Directory"

    mkdir -p "$LIB_DIR"
    chmod 700 "$LIB_DIR"
    print_status "Created $LIB_DIR"

    # Create README
    cat > "$LIB_DIR/README" << 'EOF'
Boundary Daemon State Directory

This directory contains:
- protection_state.json: Persisted protection rules
- watchdog_lockdown_pending: Flag set before hardware watchdog enabled
- last_watchdog_reset: Marker indicating watchdog-triggered reset

If watchdog_lockdown_pending exists and daemon starts, it means
the system was reset by the watchdog (daemon was killed).
EOF
    print_status "Created README"
}

test_watchdog() {
    print_section "Testing Watchdog"

    print_warning "This test will verify watchdog functionality."
    print_warning "The system will NOT be reset during this test."
    echo ""

    python3 << 'PYTEST'
import sys
sys.path.insert(0, '/opt/boundary-daemon')

try:
    from daemon.enforcement.hardware_watchdog import (
        HardwareWatchdogManager,
        check_watchdog_support,
    )

    # Check support
    print("Checking watchdog support...")
    support = check_watchdog_support()
    print(f"  Platform: {support['platform']}")
    print(f"  Is Root: {support['is_root']}")
    print(f"  Devices: {support['devices']}")
    print(f"  Recommendation: {support['recommendation']}")
    print()

    if not support['devices']:
        print("No watchdog device found. Try loading softdog:")
        print("  sudo modprobe softdog")
        sys.exit(1)

    # Create manager but don't enable (safe test)
    print("Creating watchdog manager (not enabling)...")
    hwdog = HardwareWatchdogManager(timeout=60)
    print(f"  Available: {hwdog.is_available}")
    print(f"  Status: {hwdog.get_status()}")

    print()
    print("Watchdog test passed (no system reset occurred)")
    print("To fully test, run with --enable flag (DANGEROUS)")

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
PYTEST
}

show_status() {
    print_section "Watchdog Protection Status"

    # Watchdog device
    echo -e "${BOLD}Hardware Watchdog:${NC}"
    if [[ -e /dev/watchdog ]]; then
        echo -e "  ${GREEN}●${NC} /dev/watchdog: present"
        if [[ -w /dev/watchdog ]]; then
            echo -e "  ${GREEN}●${NC} Writable: yes"
        else
            echo -e "  ${YELLOW}○${NC} Writable: no (need root)"
        fi
    else
        echo -e "  ${RED}●${NC} /dev/watchdog: not found"
    fi

    # Softdog module
    echo ""
    echo -e "${BOLD}Softdog Module:${NC}"
    if lsmod | grep -q softdog 2>/dev/null; then
        echo -e "  ${GREEN}●${NC} Status: loaded"
        local timeout=$(cat /sys/module/softdog/parameters/soft_margin 2>/dev/null || echo "?")
        echo -e "      Timeout: ${timeout}s"
    else
        echo -e "  ${YELLOW}○${NC} Status: not loaded"
    fi

    # Systemd watchdog
    echo ""
    echo -e "${BOLD}Systemd Watchdog:${NC}"
    if grep -q "WatchdogSec=" "$SYSTEMD_DIR/boundary-daemon.service" 2>/dev/null; then
        local watchdog_sec=$(grep "WatchdogSec=" "$SYSTEMD_DIR/boundary-daemon.service" | cut -d= -f2)
        echo -e "  ${GREEN}●${NC} WatchdogSec: ${watchdog_sec}"
    else
        echo -e "  ${YELLOW}○${NC} WatchdogSec: not configured"
    fi

    # Daemon service
    echo ""
    echo -e "${BOLD}Daemon Service:${NC}"
    if systemctl is-active --quiet boundary-daemon 2>/dev/null; then
        echo -e "  ${GREEN}●${NC} Status: running"
    else
        echo -e "  ${YELLOW}○${NC} Status: not running"
    fi

    # Lockdown markers
    echo ""
    echo -e "${BOLD}Lockdown Markers:${NC}"
    if [[ -f "$LIB_DIR/watchdog_lockdown_pending" ]]; then
        echo -e "  ${YELLOW}●${NC} Lockdown pending flag: SET"
        cat "$LIB_DIR/watchdog_lockdown_pending" | sed 's/^/      /'
    else
        echo -e "  ${GREEN}○${NC} Lockdown pending flag: not set"
    fi

    if [[ -f "$LIB_DIR/last_watchdog_reset" ]]; then
        echo -e "  ${RED}●${NC} Last watchdog reset detected!"
        cat "$LIB_DIR/last_watchdog_reset" | sed 's/^/      /'
    fi

    # Python module check
    echo ""
    echo -e "${BOLD}Module Check:${NC}"
    python3 << 'PYTEST' 2>/dev/null && echo -e "  ${GREEN}●${NC} hardware_watchdog module: OK" || echo -e "  ${RED}●${NC} hardware_watchdog module: error"
import sys
sys.path.insert(0, '/opt/boundary-daemon')
from daemon.enforcement.hardware_watchdog import HardwareWatchdogManager
PYTEST
}

disable_watchdog() {
    print_section "Disabling Watchdog Protection"

    print_warning "This will disable hardware watchdog protection."
    print_warning "The system will no longer reset if daemon is killed."
    read -p "Continue? (y/N) " -n 1 -r
    echo ""

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Cancelled"
        return
    fi

    # Remove softdog autoload
    if [[ -f /etc/modules-load.d/boundary-watchdog.conf ]]; then
        rm /etc/modules-load.d/boundary-watchdog.conf
        print_status "Removed softdog autoload config"
    fi

    # Remove modprobe config
    if [[ -f /etc/modprobe.d/boundary-watchdog.conf ]]; then
        rm /etc/modprobe.d/boundary-watchdog.conf
        print_status "Removed softdog modprobe config"
    fi

    # Unload softdog (if no watchdog is holding it)
    if lsmod | grep -q softdog 2>/dev/null; then
        print_info "Note: softdog module still loaded (will unload on reboot)"
    fi

    # Clear lockdown markers
    if [[ -f "$LIB_DIR/watchdog_lockdown_pending" ]]; then
        rm "$LIB_DIR/watchdog_lockdown_pending"
        print_status "Cleared lockdown pending flag"
    fi

    print_status "Watchdog protection disabled"
    print_info "Restart daemon to apply: systemctl restart boundary-daemon"
}

show_help() {
    echo "Phase 3 Hardware Watchdog Setup - Boundary Daemon"
    echo ""
    echo "Usage: sudo $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --install       Install and configure watchdog protection"
    echo "  --check         Check watchdog support"
    echo "  --test          Test watchdog (safe, no reset)"
    echo "  --status        Show watchdog status"
    echo "  --disable       Disable watchdog protection"
    echo "  --help          Show this help"
    echo ""
    echo "What Phase 3 Hardware Watchdog Does:"
    echo ""
    echo "  ┌────────────────────────────────────────────────────────────┐"
    echo "  │  PROBLEM: Daemon can be killed with SIGKILL                │"
    echo "  │                                                            │"
    echo "  │  SIGTERM → Caught, can trigger lockdown before exit        │"
    echo "  │  SIGKILL → NOT caught, daemon dies instantly               │"
    echo "  │            Protection rules may be lost!                   │"
    echo "  └────────────────────────────────────────────────────────────┘"
    echo ""
    echo "  ┌────────────────────────────────────────────────────────────┐"
    echo "  │  SOLUTION: Hardware Watchdog Timer                         │"
    echo "  │                                                            │"
    echo "  │  1. Daemon pings /dev/watchdog every 20 seconds            │"
    echo "  │  2. If daemon killed → pings stop                          │"
    echo "  │  3. After 60 seconds → hardware resets system              │"
    echo "  │  4. System reboots → daemon starts in LOCKDOWN             │"
    echo "  └────────────────────────────────────────────────────────────┘"
    echo ""
    echo "  ┌────────────────────────────────────────────────────────────┐"
    echo "  │  TIMELINE:                                                 │"
    echo "  │                                                            │"
    echo "  │  T+0s:  Attacker kills daemon (kill -9)                    │"
    echo "  │  T+0s:  Pings to /dev/watchdog stop                        │"
    echo "  │  T+10s: Pre-timeout warning (if supported)                 │"
    echo "  │  T+60s: Hardware watchdog resets system                    │"
    echo "  │  T+90s: System boots, daemon detects reset flag            │"
    echo "  │  T+90s: Daemon starts in LOCKDOWN mode                     │"
    echo "  │                                                            │"
    echo "  │  RESULT: Max 90 second exposure window vs infinite         │"
    echo "  └────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Requirements:"
    echo "  - Linux with watchdog support (or softdog module)"
    echo "  - Root privileges"
    echo "  - Phase 1 and 2 already installed"
    echo ""
    echo "WARNING:"
    echo "  Hardware watchdog WILL RESET your system if daemon stops."
    echo "  Ensure you have console access before enabling!"
    echo ""
    echo "Examples:"
    echo "  sudo $0 --check        # Check if watchdog will work"
    echo "  sudo $0 --install      # Install watchdog protection"
    echo "  sudo $0 --status       # Check current status"
    echo ""
}

# Main
print_banner

case "${1:-}" in
    --install)
        check_root

        print_warning "This will enable hardware watchdog protection."
        print_warning "Your system WILL RESET if the daemon is killed!"
        echo ""
        read -p "Type 'yes' to continue: "
        if [[ "$REPLY" != "yes" ]]; then
            print_info "Aborted"
            exit 1
        fi

        check_watchdog_support || load_softdog
        configure_softdog_autoload
        install_watchdog_module
        update_systemd_service
        update_enforcement_config
        create_lockdown_marker_dir

        echo ""
        echo -e "${GREEN}${BOLD}Phase 3 Hardware Watchdog Setup Complete!${NC}"
        echo ""
        echo "Next steps:"
        echo "  1. Check status:     sudo $0 --status"
        echo "  2. Restart daemon:   sudo systemctl restart boundary-daemon"
        echo "  3. Verify watchdog:  sudo $0 --test"
        echo ""
        echo -e "${YELLOW}WARNING: Daemon will now ping hardware watchdog.${NC}"
        echo "         If daemon is killed, system will reset in ~60 seconds."
        ;;

    --check)
        check_root
        check_watchdog_support
        ;;

    --test)
        check_root
        test_watchdog
        ;;

    --status)
        show_status
        ;;

    --disable)
        check_root
        disable_watchdog
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
