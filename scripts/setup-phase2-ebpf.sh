#!/bin/bash
#
# Phase 2 eBPF Setup Script
# Boundary Daemon - Agent Smith
#
# This script sets up eBPF-based real-time monitoring to eliminate the
# ~1 second race condition from Phase 1's polling-based detection.
#
# WHAT THIS DOES:
# - Installs BCC (BPF Compiler Collection) and dependencies
# - Verifies kernel support for eBPF
# - Enables real-time syscall monitoring
# - Integrates with existing Phase 1 enforcement
#
# REQUIREMENTS:
#   - Linux kernel 4.15+ (5.x recommended)
#   - Root privileges
#   - Phase 1 enforcement already installed
#   - Internet connection (for package installation)
#
# USAGE:
#   sudo ./scripts/setup-phase2-ebpf.sh [OPTIONS]
#
# OPTIONS:
#   --install       Install BCC and enable eBPF monitoring
#   --check         Check if eBPF requirements are met
#   --test          Run eBPF monitoring test
#   --status        Show eBPF monitoring status
#   --help          Show this help
#
# SECURITY NOTE:
#   eBPF programs run in kernel space. Only trusted code should be loaded.
#   The boundary daemon's eBPF programs are verified by the kernel's BPF verifier.

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

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║     BOUNDARY DAEMON - PHASE 2 eBPF SETUP                         ║"
    echo "║     Real-Time Kernel Event Monitoring                            ║"
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

check_platform() {
    if [[ "$(uname)" != "Linux" ]]; then
        print_error "eBPF monitoring requires Linux"
        exit 1
    fi
}

check_kernel_version() {
    print_section "Checking Kernel Version"

    local kernel_version=$(uname -r)
    local major=$(echo "$kernel_version" | cut -d. -f1)
    local minor=$(echo "$kernel_version" | cut -d. -f2)

    print_info "Kernel version: $kernel_version"

    if [[ $major -lt 4 ]] || [[ $major -eq 4 && $minor -lt 15 ]]; then
        print_error "Kernel version too old. eBPF requires 4.15+"
        print_info "Current: $major.$minor, Required: 4.15+"
        return 1
    fi

    if [[ $major -ge 5 ]]; then
        print_status "Kernel version $major.$minor - excellent eBPF support"
    else
        print_warning "Kernel version $major.$minor - basic eBPF support (5.x recommended)"
    fi

    return 0
}

check_kernel_config() {
    print_section "Checking Kernel Configuration"

    local config_file=""
    local configs_to_check=(
        "CONFIG_BPF=y"
        "CONFIG_BPF_SYSCALL=y"
        "CONFIG_BPF_JIT=y"
        "CONFIG_HAVE_EBPF_JIT=y"
        "CONFIG_BPF_EVENTS=y"
        "CONFIG_FTRACE_SYSCALLS=y"
    )

    # Try to find kernel config
    if [[ -f "/proc/config.gz" ]]; then
        config_file="/proc/config.gz"
        print_info "Using /proc/config.gz"
    elif [[ -f "/boot/config-$(uname -r)" ]]; then
        config_file="/boot/config-$(uname -r)"
        print_info "Using /boot/config-$(uname -r)"
    else
        print_warning "Kernel config not found - skipping detailed check"
        print_info "eBPF may still work if kernel was compiled with BPF support"
        return 0
    fi

    local missing=0
    for config in "${configs_to_check[@]}"; do
        local config_name=$(echo "$config" | cut -d= -f1)
        if [[ "$config_file" == *.gz ]]; then
            if zcat "$config_file" 2>/dev/null | grep -q "^$config_name="; then
                print_status "$config_name: enabled"
            else
                print_warning "$config_name: not found (may still work)"
                ((missing++)) || true
            fi
        else
            if grep -q "^$config_name=" "$config_file" 2>/dev/null; then
                print_status "$config_name: enabled"
            else
                print_warning "$config_name: not found (may still work)"
                ((missing++)) || true
            fi
        fi
    done

    if [[ $missing -gt 3 ]]; then
        print_warning "Several BPF configs not found - eBPF support may be limited"
    fi

    return 0
}

check_bpf_filesystem() {
    print_section "Checking BPF Filesystem"

    if mount | grep -q "type bpf"; then
        print_status "BPF filesystem mounted"
    elif [[ -d /sys/fs/bpf ]]; then
        print_info "BPF filesystem exists at /sys/fs/bpf"
        print_info "Attempting to mount..."
        mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
        if mount | grep -q "type bpf"; then
            print_status "BPF filesystem mounted successfully"
        else
            print_warning "Could not mount BPF filesystem"
        fi
    else
        print_warning "BPF filesystem not available"
        print_info "Creating mount point..."
        mkdir -p /sys/fs/bpf
        mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
    fi

    # Check debugfs (needed for tracepoints)
    if mount | grep -q debugfs; then
        print_status "debugfs mounted (required for tracepoints)"
    else
        print_warning "debugfs not mounted - mounting..."
        mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
    fi
}

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$ID"
    elif command -v lsb_release &>/dev/null; then
        lsb_release -si | tr '[:upper:]' '[:lower:]'
    else
        echo "unknown"
    fi
}

install_bcc_debian() {
    print_info "Installing BCC for Debian/Ubuntu..."

    # Update package list
    apt-get update

    # Install BCC and dependencies
    apt-get install -y \
        bpfcc-tools \
        python3-bpfcc \
        linux-headers-$(uname -r) \
        libbpfcc-dev \
        libbpf-dev

    print_status "BCC installed via apt"
}

install_bcc_rhel() {
    print_info "Installing BCC for RHEL/CentOS/Fedora..."

    if command -v dnf &>/dev/null; then
        dnf install -y \
            bcc \
            bcc-tools \
            python3-bcc \
            kernel-devel-$(uname -r) \
            kernel-headers-$(uname -r)
    else
        yum install -y \
            bcc \
            bcc-tools \
            python3-bcc \
            kernel-devel-$(uname -r) \
            kernel-headers-$(uname -r)
    fi

    print_status "BCC installed via dnf/yum"
}

install_bcc_arch() {
    print_info "Installing BCC for Arch Linux..."

    pacman -Sy --noconfirm \
        bcc \
        bcc-tools \
        python-bcc \
        linux-headers

    print_status "BCC installed via pacman"
}

install_bcc() {
    print_section "Installing BCC (BPF Compiler Collection)"

    # Check if already installed
    if python3 -c "from bcc import BPF" 2>/dev/null; then
        print_status "BCC Python bindings already installed"
        return 0
    fi

    local distro=$(detect_distro)
    print_info "Detected distribution: $distro"

    case "$distro" in
        ubuntu|debian|linuxmint|pop)
            install_bcc_debian
            ;;
        fedora|centos|rhel|rocky|alma)
            install_bcc_rhel
            ;;
        arch|manjaro)
            install_bcc_arch
            ;;
        *)
            print_error "Unsupported distribution: $distro"
            print_info "Please install BCC manually:"
            print_info "  https://github.com/iovisor/bcc/blob/master/INSTALL.md"
            return 1
            ;;
    esac

    # Verify installation
    if python3 -c "from bcc import BPF" 2>/dev/null; then
        print_status "BCC Python bindings verified"
    else
        print_error "BCC Python bindings not working"
        print_info "Try: pip3 install bcc"
        return 1
    fi
}

verify_bcc() {
    print_section "Verifying BCC Installation"

    # Check Python bindings
    if python3 -c "from bcc import BPF; print('BCC version:', BPF.get_kprobe_functions(b'')[:1] if hasattr(BPF, 'get_kprobe_functions') else 'ok')" 2>/dev/null; then
        print_status "BCC Python bindings working"
    else
        print_error "BCC Python bindings not working"
        return 1
    fi

    # Check kernel headers
    if [[ -d "/lib/modules/$(uname -r)/build" ]]; then
        print_status "Kernel headers found"
    else
        print_warning "Kernel headers not found at /lib/modules/$(uname -r)/build"
        print_info "Some eBPF features may not work"
    fi

    # Test simple BPF program
    print_info "Testing BPF program compilation..."
    python3 << 'PYTEST'
import sys
try:
    from bcc import BPF
    b = BPF(text='''
    int test(void *ctx) {
        return 0;
    }
    ''')
    print("BPF program compilation: OK")
    b.cleanup()
except Exception as e:
    print(f"BPF program compilation: FAILED - {e}")
    sys.exit(1)
PYTEST

    if [[ $? -eq 0 ]]; then
        print_status "BPF program compilation working"
    else
        print_error "BPF program compilation failed"
        return 1
    fi
}

update_daemon_config() {
    print_section "Updating Daemon Configuration"

    # Add eBPF configuration to enforcement.conf
    local config_file="$CONFIG_DIR/enforcement.conf"

    if [[ -f "$config_file" ]]; then
        # Check if eBPF section already exists
        if grep -q "^\[ebpf\]" "$config_file"; then
            print_info "eBPF configuration section already exists"
        else
            print_info "Adding eBPF configuration section..."
            cat >> "$config_file" << 'EOF'

[ebpf]
# Phase 2: eBPF Real-Time Monitoring
# Eliminates the ~1 second race condition from polling

# Enable eBPF monitoring (requires BCC and root)
enabled = true

# Monitor network syscalls (socket, connect, bind, etc.)
network_monitoring = true

# Monitor process execution (execve)
process_monitoring = true

# Monitor USB events (experimental)
usb_monitoring = false

# React to events in real-time
# Options: log, alert, block (block requires LSM hooks)
network_action = alert
process_action = alert

# Ignore these UIDs (system processes)
ignored_uids = 0

# Maximum events per second before throttling
max_events_per_second = 10000

# Event buffer size
event_buffer_size = 1000
EOF
            print_status "Added eBPF configuration to $config_file"
        fi
    else
        print_warning "Config file not found: $config_file"
        print_info "Run Phase 1 setup first: sudo ./scripts/setup-phase1-enforcement.sh --install"
    fi
}

install_daemon_module() {
    print_section "Installing eBPF Monitor Module"

    # Copy updated daemon code
    if [[ -d "$PROJECT_DIR/daemon" ]]; then
        cp -r "$PROJECT_DIR/daemon" "$INSTALL_DIR/"
        print_status "Updated daemon modules with eBPF support"
    fi
}

test_ebpf_monitoring() {
    print_section "Testing eBPF Monitoring"

    print_info "Starting eBPF monitor test (10 seconds)..."
    print_info "Try running: curl google.com (in another terminal)"
    echo ""

    python3 << 'PYTEST'
import sys
import time
sys.path.insert(0, '/opt/boundary-daemon')

try:
    from daemon.enforcement.ebpf_monitor import EBPFMonitor, EventType, MonitorAction, check_ebpf_requirements

    # Check requirements first
    all_met, issues = check_ebpf_requirements()
    if not all_met:
        print("Requirements not met:")
        for issue in issues:
            print(f"  - {issue}")
        sys.exit(1)

    print("Starting eBPF monitor...")
    monitor = EBPFMonitor(enable_network=True, enable_process=True)

    events_seen = []

    def on_network(event):
        events_seen.append(event)
        print(f"  Network: {event.comm} ({event.pid}) - {event.details.get('syscall', '?')}")
        return MonitorAction.LOG

    def on_process(event):
        events_seen.append(event)
        filename = event.details.get('filename', '')
        if filename and filename != '[EXIT]':
            print(f"  Process: {event.comm} ({event.pid}) exec {filename}")
        return MonitorAction.LOG

    monitor.add_callback(EventType.NETWORK_CONNECT, on_network)
    monitor.add_callback(EventType.NETWORK_SOCKET, on_network)
    monitor.add_callback(EventType.PROCESS_EXEC, on_process)

    monitor.set_monitoring_mode('RESTRICTED')

    success, msg = monitor.start()
    if not success:
        print(f"Failed to start: {msg}")
        sys.exit(1)

    print("Monitoring for 10 seconds...")
    print("-" * 40)

    for i in range(10):
        time.sleep(1)
        sys.stdout.write(f"\r{10-i} seconds remaining... ({len(events_seen)} events)")
        sys.stdout.flush()

    print(f"\n{'-' * 40}")

    monitor.stop()

    stats = monitor.get_stats()
    print(f"\nStatistics:")
    print(f"  Total events: {stats['events_total']}")
    print(f"  Network events: {stats['events_network']}")
    print(f"  Process events: {stats['events_process']}")

    if stats['events_total'] > 0:
        print("\n✓ eBPF monitoring is working!")
    else:
        print("\n! No events captured (try generating network/process activity)")

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
PYTEST

    if [[ $? -eq 0 ]]; then
        print_status "eBPF monitoring test completed"
    else
        print_error "eBPF monitoring test failed"
        return 1
    fi
}

show_status() {
    print_section "eBPF Monitoring Status"

    # Check BCC
    echo -e "${BOLD}BCC Installation:${NC}"
    if python3 -c "from bcc import BPF" 2>/dev/null; then
        echo -e "  ${GREEN}●${NC} BCC Python bindings: installed"
    else
        echo -e "  ${RED}●${NC} BCC Python bindings: not installed"
    fi

    # Check kernel
    echo ""
    echo -e "${BOLD}Kernel Support:${NC}"
    local kernel_version=$(uname -r)
    echo -e "  Kernel version: $kernel_version"

    if [[ -d /sys/fs/bpf ]]; then
        echo -e "  ${GREEN}●${NC} BPF filesystem: available"
    else
        echo -e "  ${RED}●${NC} BPF filesystem: not available"
    fi

    if [[ -d /sys/kernel/debug/tracing ]]; then
        echo -e "  ${GREEN}●${NC} Tracepoints: available"
    else
        echo -e "  ${YELLOW}○${NC} Tracepoints: may not be available"
    fi

    # Check daemon module
    echo ""
    echo -e "${BOLD}Daemon Module:${NC}"
    if [[ -f "$INSTALL_DIR/daemon/enforcement/ebpf_monitor.py" ]]; then
        echo -e "  ${GREEN}●${NC} eBPF monitor module: installed"
    else
        echo -e "  ${RED}●${NC} eBPF monitor module: not installed"
    fi

    # Check configuration
    echo ""
    echo -e "${BOLD}Configuration:${NC}"
    if grep -q "^\[ebpf\]" "$CONFIG_DIR/enforcement.conf" 2>/dev/null; then
        echo -e "  ${GREEN}●${NC} eBPF config section: present"
    else
        echo -e "  ${YELLOW}○${NC} eBPF config section: not configured"
    fi

    # Run Python check
    echo ""
    echo -e "${BOLD}Runtime Check:${NC}"
    python3 << 'PYTEST'
import sys
sys.path.insert(0, '/opt/boundary-daemon')

try:
    from daemon.enforcement.ebpf_monitor import check_ebpf_requirements
    all_met, issues = check_ebpf_requirements()

    if all_met:
        print("  \033[0;32m●\033[0m All requirements met - eBPF ready")
    else:
        print("  \033[0;33m○\033[0m Requirements not fully met:")
        for issue in issues:
            print(f"      - {issue}")
except Exception as e:
    print(f"  \033[0;31m●\033[0m Error checking requirements: {e}")
PYTEST
}

show_help() {
    echo "Phase 2 eBPF Setup - Boundary Daemon"
    echo ""
    echo "Usage: sudo $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --install       Install BCC and enable eBPF monitoring"
    echo "  --check         Check if eBPF requirements are met"
    echo "  --test          Run eBPF monitoring test"
    echo "  --status        Show eBPF monitoring status"
    echo "  --help          Show this help"
    echo ""
    echo "What Phase 2 eBPF Monitoring Does:"
    echo ""
    echo "  ┌────────────────────────────────────────────────────────────┐"
    echo "  │  PHASE 1 (Polling)           PHASE 2 (eBPF)                │"
    echo "  │  ─────────────────           ─────────────────             │"
    echo "  │  Check every 1 second   →    Real-time interception        │"
    echo "  │  ~1s race window        →    <100μs reaction time          │"
    echo "  │  Detection only         →    Can block operations          │"
    echo "  └────────────────────────────────────────────────────────────┘"
    echo ""
    echo "  ┌────────────────────────────────────────────────────────────┐"
    echo "  │  MONITORED EVENTS (Real-Time)                              │"
    echo "  │  ├─ Network: socket(), connect(), bind(), sendto()         │"
    echo "  │  ├─ Process: execve(), fork(), exit()                      │"
    echo "  │  └─ USB: device add/remove (experimental)                  │"
    echo "  └────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Requirements:"
    echo "  - Linux kernel 4.15+ (5.x recommended)"
    echo "  - Root privileges"
    echo "  - Phase 1 enforcement installed"
    echo "  - Internet connection (for BCC installation)"
    echo ""
    echo "Examples:"
    echo "  sudo $0 --check        # Check if eBPF will work"
    echo "  sudo $0 --install      # Install BCC and configure"
    echo "  sudo $0 --test         # Test eBPF monitoring"
    echo ""
}

# Main
print_banner

case "${1:-}" in
    --install)
        check_root
        check_platform
        check_kernel_version || exit 1
        check_kernel_config
        check_bpf_filesystem
        install_bcc || exit 1
        verify_bcc || exit 1
        install_daemon_module
        update_daemon_config

        echo ""
        echo -e "${GREEN}${BOLD}Phase 2 eBPF Setup Complete!${NC}"
        echo ""
        echo "Next steps:"
        echo "  1. Run test:        sudo $0 --test"
        echo "  2. Check status:    sudo $0 --status"
        echo "  3. Restart daemon:  sudo systemctl restart boundary-daemon"
        echo ""
        echo -e "${CYAN}eBPF eliminates the ~1s race condition from Phase 1${NC}"
        echo "Network/process events are now captured in real-time."
        ;;

    --check)
        check_root
        check_platform
        check_kernel_version
        check_kernel_config
        check_bpf_filesystem
        verify_bcc || print_warning "BCC verification failed - run --install"
        ;;

    --test)
        check_root
        test_ebpf_monitoring
        ;;

    --status)
        show_status
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
