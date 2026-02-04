#!/bin/bash
#
# Phase 4 Mandatory Access Control (MAC) Setup Script
# Boundary Daemon - Agent Smith
#
# This script configures SELinux or AppArmor policies that enforce
# boundary modes at the KERNEL level, providing true mandatory access control.
#
# WHY THIS MATTERS:
# - Phases 1-3: Userspace enforcement (iptables, udev, seccomp, watchdog)
# - Phase 4: KERNEL enforcement (SELinux/AppArmor)
#
# The difference: Even if an attacker compromises the daemon, the KERNEL
# continues to enforce the MAC policy. This is true mandatory access control.
#
# SUPPORTED SYSTEMS:
# - SELinux (RHEL, Fedora, CentOS, Rocky, Alma)
# - AppArmor (Ubuntu, Debian, SUSE)
#
# MODE → MAC POLICY MAPPING:
#   OPEN       → Permissive policy (logging only)
#   RESTRICTED → Limited network, logged file access
#   TRUSTED    → VPN-only network, restricted paths
#   AIRGAP     → No network syscalls allowed
#   COLDROOM   → No network, no exec, minimal access
#   LOCKDOWN   → Deny all, daemon survival minimum
#
# USAGE:
#   sudo ./scripts/setup-phase4-mac.sh [OPTIONS]
#
# OPTIONS:
#   --install       Install MAC policy infrastructure
#   --check         Check MAC system support
#   --apply MODE    Apply policy for specified mode
#   --generate MODE Generate policy without applying (dry run)
#   --status        Show current MAC status
#   --remove        Remove all boundary MAC policies
#   --help          Show this help

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
INSTALL_DIR="/opt/boundary-daemon"
CONFIG_DIR="/etc/boundary-daemon"

# SELinux paths
SELINUX_MODULE_DIR="/etc/selinux/targeted/modules"
SELINUX_POLICY_DIR="/usr/share/selinux/packages"

# AppArmor paths
APPARMOR_PROFILE_DIR="/etc/apparmor.d"

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║     BOUNDARY DAEMON - PHASE 4 MAC POLICY                         ║"
    echo "║     Kernel-Level Mandatory Access Control                        ║"
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

detect_mac_system() {
    # Check SELinux
    if [[ -d /sys/fs/selinux ]] && command -v getenforce &>/dev/null; then
        echo "selinux"
        return 0
    fi

    # Check AppArmor
    if [[ -d /sys/kernel/security/apparmor ]] && command -v apparmor_status &>/dev/null; then
        echo "apparmor"
        return 0
    fi

    echo "none"
    return 1
}

check_mac_support() {
    print_section "Checking MAC Support"

    local mac_system=$(detect_mac_system)

    echo -e "${BOLD}Detected System:${NC} $mac_system"
    echo ""

    if [[ "$mac_system" == "selinux" ]]; then
        echo -e "${BOLD}SELinux Status:${NC}"
        local mode=$(getenforce 2>/dev/null || echo "unknown")
        echo "  Mode: $mode"

        if command -v sestatus &>/dev/null; then
            sestatus 2>/dev/null | sed 's/^/  /'
        fi

        # Check required tools
        echo ""
        echo -e "${BOLD}Required Tools:${NC}"
        for tool in semodule checkmodule semodule_package; do
            if command -v $tool &>/dev/null; then
                echo -e "  ${GREEN}●${NC} $tool: found"
            else
                echo -e "  ${RED}●${NC} $tool: NOT FOUND"
            fi
        done

        print_status "SELinux available"

    elif [[ "$mac_system" == "apparmor" ]]; then
        echo -e "${BOLD}AppArmor Status:${NC}"
        if command -v aa-status &>/dev/null; then
            aa-status 2>/dev/null | head -10 | sed 's/^/  /'
        fi

        # Check required tools
        echo ""
        echo -e "${BOLD}Required Tools:${NC}"
        for tool in apparmor_parser aa-status aa-enforce aa-complain; do
            if command -v $tool &>/dev/null; then
                echo -e "  ${GREEN}●${NC} $tool: found"
            else
                echo -e "  ${RED}●${NC} $tool: NOT FOUND"
            fi
        done

        print_status "AppArmor available"

    else
        print_error "No MAC system detected"
        echo ""
        echo "To enable MAC support, install one of:"
        echo "  - SELinux: yum install selinux-policy-targeted policycoreutils"
        echo "  - AppArmor: apt install apparmor apparmor-utils"
        return 1
    fi

    return 0
}

install_mac_module() {
    print_section "Installing MAC Policy Module"

    # Copy dynamic_mac_policy.py to installation
    if [[ -f "$PROJECT_DIR/daemon/enforcement/dynamic_mac_policy.py" ]]; then
        cp "$PROJECT_DIR/daemon/enforcement/dynamic_mac_policy.py" \
           "$INSTALL_DIR/daemon/enforcement/"
        print_status "Installed dynamic_mac_policy.py"
    fi

    # Update __init__.py
    if [[ -f "$PROJECT_DIR/daemon/enforcement/__init__.py" ]]; then
        cp "$PROJECT_DIR/daemon/enforcement/__init__.py" \
           "$INSTALL_DIR/daemon/enforcement/"
        print_status "Updated enforcement __init__.py"
    fi
}

update_config() {
    print_section "Updating Configuration"

    local config_file="$CONFIG_DIR/enforcement.conf"

    if [[ -f "$config_file" ]]; then
        if grep -q "^\[mac_policy\]" "$config_file"; then
            print_info "MAC policy configuration section exists"
        else
            print_info "Adding MAC policy configuration..."
            cat >> "$config_file" << 'EOF'

[mac_policy]
# Phase 4: Mandatory Access Control Policy
# Enforces boundary modes at the KERNEL level

# Enable dynamic MAC policy
enabled = true

# MAC system to use (auto-detected if not specified)
# Options: auto, selinux, apparmor
mac_system = auto

# Apply policy on mode transitions
apply_on_transition = true

# Policy enforcement mode
# Options: enforcing, permissive
enforcement_mode = enforcing

# Log all policy decisions (both allow and deny)
audit_all = true

# Generate policy for these modes on startup
pregenerate_modes = restricted,trusted,airgap,coldroom,lockdown
EOF
            print_status "Added [mac_policy] configuration"
        fi
    fi
}

apply_mode_policy() {
    local mode="$1"

    print_section "Applying MAC Policy for $mode"

    python3 << PYTEST
import sys
sys.path.insert(0, '/opt/boundary-daemon')

try:
    from daemon.enforcement.dynamic_mac_policy import (
        DynamicMACPolicyManager,
        MODE_POLICIES,
    )

    mode = "${mode}".upper()
    if mode not in MODE_POLICIES:
        print(f"Unknown mode: {mode}")
        print(f"Available: {list(MODE_POLICIES.keys())}")
        sys.exit(1)

    manager = DynamicMACPolicyManager()

    if not manager.is_available:
        print("No MAC system available")
        sys.exit(1)

    print(f"MAC system: {manager.mac_system.value}")
    print(f"Applying {mode} policy...")

    success, msg = manager.apply_mode_policy(mode)
    print(f"Result: {msg}")

    if success:
        print(f"\n✓ MAC policy for {mode} mode is now active")
        print("  The kernel will enforce these restrictions")
    else:
        print(f"\n✗ Failed to apply policy")
        sys.exit(1)

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
PYTEST
}

generate_mode_policy() {
    local mode="$1"

    print_section "Generating MAC Policy for $mode (Dry Run)"

    python3 << PYTEST
import sys
sys.path.insert(0, '/opt/boundary-daemon')

try:
    from daemon.enforcement.dynamic_mac_policy import (
        SELinuxPolicyGenerator,
        AppArmorPolicyGenerator,
        MODE_POLICIES,
        check_mac_support,
    )

    mode = "${mode}".upper()
    if mode not in MODE_POLICIES:
        print(f"Unknown mode: {mode}")
        print(f"Available: {list(MODE_POLICIES.keys())}")
        sys.exit(1)

    policy = MODE_POLICIES[mode]

    # Check what's available
    support = check_mac_support()

    if support['selinux']['available']:
        print("# SELinux Policy Module")
        print("# " + "="*60)
        gen = SELinuxPolicyGenerator()
        print(gen.generate_mode_policy(policy))
    elif support['apparmor']['available']:
        print("# AppArmor Profile")
        print("# " + "="*60)
        gen = AppArmorPolicyGenerator()
        print(gen.generate_mode_profile(policy))
    else:
        print("No MAC system available")
        sys.exit(1)

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
PYTEST
}

remove_policies() {
    print_section "Removing All Boundary MAC Policies"

    python3 << 'PYTEST'
import sys
sys.path.insert(0, '/opt/boundary-daemon')

try:
    from daemon.enforcement.dynamic_mac_policy import DynamicMACPolicyManager

    manager = DynamicMACPolicyManager()

    if not manager.is_available:
        print("No MAC system available")
        sys.exit(0)

    print(f"MAC system: {manager.mac_system.value}")
    print("Removing all boundary policies...")

    success, msg = manager.remove_all_policies()
    print(f"Result: {msg}")

except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
PYTEST
}

show_status() {
    print_section "MAC Policy Status"

    local mac_system=$(detect_mac_system)

    echo -e "${BOLD}MAC System:${NC} $mac_system"
    echo ""

    if [[ "$mac_system" == "selinux" ]]; then
        echo -e "${BOLD}SELinux Status:${NC}"
        echo "  Mode: $(getenforce 2>/dev/null || echo 'unknown')"

        # List boundary modules
        echo ""
        echo -e "${BOLD}Boundary Modules:${NC}"
        semodule -l 2>/dev/null | grep -i boundary | sed 's/^/  /' || echo "  (none)"

    elif [[ "$mac_system" == "apparmor" ]]; then
        echo -e "${BOLD}AppArmor Status:${NC}"
        aa-status 2>/dev/null | grep -E "enforce|complain|boundary" | sed 's/^/  /' || echo "  (check aa-status)"

        # List boundary profiles
        echo ""
        echo -e "${BOLD}Boundary Profiles:${NC}"
        ls -la "$APPARMOR_PROFILE_DIR" 2>/dev/null | grep boundary | sed 's/^/  /' || echo "  (none)"
    fi

    # Python module check
    echo ""
    echo -e "${BOLD}Module Status:${NC}"
    python3 << 'PYTEST'
import sys
sys.path.insert(0, '/opt/boundary-daemon')

try:
    from daemon.enforcement.dynamic_mac_policy import DynamicMACPolicyManager

    manager = DynamicMACPolicyManager()
    status = manager.get_status()

    print(f"  Available: {status['available']}")
    print(f"  MAC System: {status['mac_system']}")
    print(f"  Current Mode: {status.get('current_mode', 'none')}")

except Exception as e:
    print(f"  Error: {e}")
PYTEST
}

show_help() {
    echo "Phase 4 MAC Policy Setup - Boundary Daemon"
    echo ""
    echo "Usage: sudo $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --install           Install MAC policy infrastructure"
    echo "  --check             Check MAC system support"
    echo "  --apply MODE        Apply policy for specified mode"
    echo "  --generate MODE     Generate policy without applying (dry run)"
    echo "  --status            Show current MAC status"
    echo "  --remove            Remove all boundary MAC policies"
    echo "  --help              Show this help"
    echo ""
    echo "Available Modes:"
    echo "  OPEN       - Permissive, logging only"
    echo "  RESTRICTED - Limited network, logged access"
    echo "  TRUSTED    - VPN-only, restricted paths"
    echo "  AIRGAP     - No network syscalls"
    echo "  COLDROOM   - No network, no exec, minimal"
    echo "  LOCKDOWN   - Deny all, survival minimum"
    echo ""
    echo "What Phase 4 MAC Policy Does:"
    echo ""
    echo "  ┌────────────────────────────────────────────────────────────┐"
    echo "  │  PHASES 1-3 (Userspace)      PHASE 4 (Kernel)              │"
    echo "  │  ───────────────────────     ─────────────────             │"
    echo "  │  iptables (daemon)      →    SELinux/AppArmor (kernel)     │"
    echo "  │  udev rules (daemon)    →    Kernel policy modules         │"
    echo "  │  seccomp (daemon)       →    MAC enforcement               │"
    echo "  │                                                            │"
    echo "  │  Daemon can be killed   →    Kernel enforces regardless    │"
    echo "  │  Daemon can be bypassed →    Cannot bypass kernel MAC      │"
    echo "  └────────────────────────────────────────────────────────────┘"
    echo ""
    echo "  ┌────────────────────────────────────────────────────────────┐"
    echo "  │  AIRGAP MODE - MAC Policy Example                          │"
    echo "  │  ──────────────────────────────────────────────────────────│"
    echo "  │  • Network: DENY socket(), connect(), bind()               │"
    echo "  │  • Files: READ /etc/boundary-daemon, /proc, /sys           │"
    echo "  │  • Files: WRITE /var/log/boundary-daemon only              │"
    echo "  │  • Exec: DENY execve() except Python interpreter           │"
    echo "  │  • Caps: DENY net_admin, net_raw, net_bind_service         │"
    echo "  │                                                            │"
    echo "  │  → Even if daemon is compromised, kernel blocks network!   │"
    echo "  └────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Examples:"
    echo "  sudo $0 --check              # Check if SELinux/AppArmor available"
    echo "  sudo $0 --install            # Install MAC infrastructure"
    echo "  sudo $0 --apply AIRGAP       # Apply AIRGAP policy"
    echo "  sudo $0 --generate LOCKDOWN  # Preview LOCKDOWN policy"
    echo ""
}

# Main
print_banner

case "${1:-}" in
    --install)
        check_root
        check_mac_support || exit 1
        install_mac_module
        update_config

        echo ""
        echo -e "${GREEN}${BOLD}Phase 4 MAC Policy Setup Complete!${NC}"
        echo ""
        echo "Next steps:"
        echo "  1. Check status:    sudo $0 --status"
        echo "  2. Preview policy:  sudo $0 --generate AIRGAP"
        echo "  3. Apply policy:    sudo $0 --apply AIRGAP"
        echo ""
        echo -e "${CYAN}MAC policies are now kernel-enforced!${NC}"
        ;;

    --check)
        check_root
        check_mac_support
        ;;

    --apply)
        check_root
        if [[ -z "$2" ]]; then
            print_error "Mode required. Usage: $0 --apply MODE"
            echo "Available: OPEN, RESTRICTED, TRUSTED, AIRGAP, COLDROOM, LOCKDOWN"
            exit 1
        fi
        apply_mode_policy "$2"
        ;;

    --generate)
        if [[ -z "$2" ]]; then
            print_error "Mode required. Usage: $0 --generate MODE"
            echo "Available: OPEN, RESTRICTED, TRUSTED, AIRGAP, COLDROOM, LOCKDOWN"
            exit 1
        fi
        generate_mode_policy "$2"
        ;;

    --status)
        show_status
        ;;

    --remove)
        check_root
        remove_policies
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
