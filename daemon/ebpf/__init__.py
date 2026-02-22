"""
eBPF Observability Module for Boundary Daemon

Provides kernel-level visibility WITHOUT requiring a kernel driver:
- Process execution monitoring
- File access monitoring
- Network connection monitoring
- System call tracing

Status: EXPERIMENTAL — Falls back to /proc polling when bcc is unavailable.
The eBPF code paths (eBPFObserverImpl, BPF_TEXT probe programs) are untested
in CI because bcc is not in requirements.txt. The ProcObserver fallback is
the only path exercised in practice.

Requirements (for eBPF mode):
- Linux kernel 4.15+ (for BPF CO-RE)
- bcc Python bindings: pip install bcc
- CAP_SYS_ADMIN or CAP_BPF capability

TODO: Add bcc to optional dependencies and CI test matrix
TODO: Add integration tests for eBPF probes on a capable kernel
"""

from .ebpf_observer import (
    eBPFObserver,
    eBPFCapability,
    ObservationEvent,
    ProcessEvent,
    FileEvent,
    NetworkEvent,
    SyscallEvent,
)

from .probes import (
    ProbeType,
    ProbeConfig,
    ProbeManager,
    ExecProbe,
    OpenProbe,
    ConnectProbe,
)

from .policy_integration import (
    eBPFPolicyProvider,
    ObservationBasedPolicy,
    RealTimeEnforcement,
)

__all__ = [
    # Observer
    'eBPFObserver',
    'eBPFCapability',
    'ObservationEvent',
    'ProcessEvent',
    'FileEvent',
    'NetworkEvent',
    'SyscallEvent',

    # Probes
    'ProbeType',
    'ProbeConfig',
    'ProbeManager',
    'ExecProbe',
    'OpenProbe',
    'ConnectProbe',

    # Policy integration
    'eBPFPolicyProvider',
    'ObservationBasedPolicy',
    'RealTimeEnforcement',
]
