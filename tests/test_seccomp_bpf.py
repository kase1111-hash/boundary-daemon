"""
Tests for the seccomp BPF program built by daemon.sandbox.seccomp_filter.

Regression test for a bug where the architecture check jumped over two
instructions instead of three, so an x86_64 process fell through to the
"unknown architecture" KILL and died with SIGSYS on its first syscall.
The tests interpret the generated classic-BPF program with a tiny
evaluator instead of installing it, so they run without root.
"""

import os
import struct
import subprocess
import sys
import textwrap

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.sandbox.seccomp_filter import (  # noqa: E402
    AUDIT_ARCH_I386,
    AUDIT_ARCH_X86_64,
    BPF_ABS,
    BPF_JEQ,
    BPF_JMP,
    BPF_K,
    BPF_LD,
    BPF_RET,
    BPF_W,
    SECCOMP_RET_ALLOW,
    SECCOMP_RET_ERRNO,
    SECCOMP_RET_KILL_PROCESS,
    SeccompAction,
    SeccompFilter,
    SeccompProfile,
)

SECCOMP_RET_ACTION_MASK = 0xFFFF0000


def run_bpf(program: bytes, arch: int, syscall_nr: int) -> int:
    """Evaluate a classic-BPF seccomp program against (arch, syscall_nr)."""
    insns = [struct.unpack('HBBI', program[i:i + 8]) for i in range(0, len(program), 8)]
    seccomp_data = {0: syscall_nr, 4: arch}
    acc = 0
    pc = 0
    while pc < len(insns):
        code, jt, jf, k = insns[pc]
        if code == (BPF_LD | BPF_W | BPF_ABS):
            acc = seccomp_data[k]
            pc += 1
        elif code == (BPF_JMP | BPF_JEQ | BPF_K):
            pc += 1 + (jt if acc == k else jf)
        elif code == (BPF_RET | BPF_K):
            return k
        else:
            raise AssertionError(f"unexpected BPF opcode {code:#x} at {pc}")
    raise AssertionError("BPF program fell off the end")


def _filter(default: SeccompAction, denied=(), allowed=()) -> SeccompFilter:
    flt = SeccompFilter()
    flt._arch = AUDIT_ARCH_X86_64
    flt.load_profile(SeccompProfile(
        name='test',
        default_action=default,
        denied_syscalls=set(denied),
        allowed_syscalls=set(allowed),
    ))
    return flt


@pytest.mark.security
class TestSeccompBpfProgram:
    def test_x86_64_allowed_syscall_reaches_default_allow(self):
        flt = _filter(SeccompAction.ALLOW, denied=['ptrace'])
        program = flt._build_bpf_program()
        getpid = flt._get_syscall_nr('getpid')
        assert run_bpf(program, AUDIT_ARCH_X86_64, getpid) == SECCOMP_RET_ALLOW

    def test_x86_64_denied_syscall_returns_eperm_not_kill(self):
        flt = _filter(SeccompAction.ALLOW, denied=['ptrace'])
        program = flt._build_bpf_program()
        ret = run_bpf(program, AUDIT_ARCH_X86_64, flt._get_syscall_nr('ptrace'))
        assert ret & SECCOMP_RET_ACTION_MASK == SECCOMP_RET_ERRNO
        assert ret & 0xFFFF == 1  # EPERM

    def test_default_deny_allows_explicit_syscalls(self):
        flt = _filter(SeccompAction.DENY, allowed=['read', 'write', 'exit_group'])
        program = flt._build_bpf_program()
        assert run_bpf(program, AUDIT_ARCH_X86_64, flt._get_syscall_nr('read')) == SECCOMP_RET_ALLOW
        ret = run_bpf(program, AUDIT_ARCH_X86_64, flt._get_syscall_nr('openat'))
        assert ret & SECCOMP_RET_ACTION_MASK == SECCOMP_RET_ERRNO

    def test_i386_and_unknown_arch_are_killed(self):
        flt = _filter(SeccompAction.ALLOW)
        program = flt._build_bpf_program()
        getpid = flt._get_syscall_nr('getpid')
        assert run_bpf(program, AUDIT_ARCH_I386, getpid) == SECCOMP_RET_KILL_PROCESS
        assert run_bpf(program, 0xDEADBEEF, getpid) == SECCOMP_RET_KILL_PROCESS

    def test_every_x86_64_syscall_has_a_non_kill_verdict(self):
        """No syscall number may reach the arch-mismatch kill on the native arch."""
        flt = _filter(SeccompAction.ALLOW, denied=['ptrace', 'mount'])
        program = flt._build_bpf_program()
        for nr in range(0, 460):
            assert run_bpf(program, AUDIT_ARCH_X86_64, nr) != SECCOMP_RET_KILL_PROCESS, nr


@pytest.mark.security
@pytest.mark.skipif(sys.platform != 'linux' or os.uname().machine != 'x86_64',
                    reason="applies a real seccomp filter; Linux x86_64 only")
class TestSeccompFilterApplied:
    def test_child_survives_its_own_filter(self):
        """Apply a real filter in a throwaway child: allowed syscalls work, denied get EPERM."""
        child = textwrap.dedent('''
            import os, sys, errno
            sys.path.insert(0, %r)
            from daemon.sandbox.seccomp_filter import SeccompFilter, SeccompProfile, SeccompAction
            flt = SeccompFilter()
            flt.load_profile(SeccompProfile(name="t", default_action=SeccompAction.ALLOW,
                                            denied_syscalls={"ptrace"}))
            if not flt.apply():
                print("APPLY_FAILED"); sys.exit(0)
            os.getpid()  # allowed
            import ctypes
            libc = ctypes.CDLL(None, use_errno=True)
            rc = libc.ptrace(0, 0, 0, 0)  # denied -> -1/EPERM instead of SIGSYS
            print("OK" if rc == -1 and ctypes.get_errno() == errno.EPERM else f"UNEXPECTED rc={rc} errno={ctypes.get_errno()}")
        ''') % (os.path.dirname(os.path.dirname(os.path.abspath(__file__))),)
        result = subprocess.run([sys.executable, '-c', child], capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, f"child died (rc={result.returncode}): {result.stderr[-500:]}"
        out = result.stdout.strip()
        if out == 'APPLY_FAILED':
            pytest.skip("seccomp could not be applied in this environment")
        assert out == 'OK', out
