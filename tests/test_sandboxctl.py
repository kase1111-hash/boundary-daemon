"""
Tests for the sandboxctl CLI (daemon/cli/sandboxctl.py).

The CLI was rewritten to talk to the real sandbox API in
daemon/sandbox/sandbox_manager.py. These tests pin the CLI to that API:

- every keyword the CLI passes to SandboxManager.run_sandboxed /
  terminate_sandbox is bound against the *real* method signature, so a
  renamed or removed parameter fails here instead of at runtime
- the dicts the CLI renders for ``list``/``inspect`` are shaped like
  Sandbox.get_info() (resource_usage is the NESTED ResourceUsage.to_dict()
  layout: {'cpu': {'total_us': ...}, 'memory': {'current_bytes': ...}, ...})
- profile overrides (--memory/--cpu/--timeout/--network-*) land on the
  CgroupLimits / NetworkPolicy attribute names the sandbox actually reads

Nothing here needs root, network access or real namespaces/cgroups: the
manager is a unittest.mock fake, urlopen is patched, and the real
Sandbox/SandboxManager objects that are exercised are built with Mock
namespace/cgroup managers and never started.
"""

import inspect
import json
import os
import sys
import threading
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.cli.sandboxctl import (  # noqa: E402
    Colors,
    SandboxCLI,
    create_parser,
    main,
)
from daemon.sandbox.cgroups import CgroupLimits, ResourceUsage  # noqa: E402
from daemon.sandbox.network_policy import NetworkPolicy  # noqa: E402
from daemon.sandbox.sandbox_manager import (  # noqa: E402
    Sandbox,
    SandboxError,
    SandboxManager,
    SandboxProfile,
    SandboxResult,
    SandboxState,
)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

_COLOR_ATTRS = ('RESET', 'BOLD', 'RED', 'GREEN', 'YELLOW', 'BLUE', 'CYAN', 'GRAY')


@pytest.fixture(autouse=True)
def plain_colors():
    """Strip ANSI codes so output assertions are plain text; restore afterwards."""
    saved = {name: getattr(Colors, name) for name in _COLOR_ATTRS}
    Colors.disable()
    yield
    for name, value in saved.items():
        setattr(Colors, name, value)


@pytest.fixture(autouse=True)
def empty_profile_loader():
    """Make profile-config lookups deterministic (no profiles loaded from disk)."""
    loader = Mock()
    loader.get_sandbox_profile.return_value = None
    loader.list_profiles.return_value = []
    with patch('daemon.cli.sandboxctl.get_profile_loader', return_value=loader) as get_loader:
        yield get_loader


@pytest.fixture(autouse=True)
def no_signal_handlers():
    """cmd_run installs SIGINT/SIGTERM handlers; keep them off the test process."""
    with patch('daemon.cli.sandboxctl.signal.signal') as sig:
        yield sig


def parse(*argv):
    """Parse argv exactly as main() would."""
    return create_parser().parse_args(list(argv))


def make_result(**overrides):
    """A real SandboxResult, as SandboxManager.run_sandboxed would return."""
    fields = dict(
        sandbox_id='x',
        command=['true'],
        exit_code=0,
        stdout='hi',
        stderr='',
        runtime_seconds=0.1,
    )
    fields.update(overrides)
    return SandboxResult(**fields)


def make_manager(**attrs):
    """A fake SandboxManager restricted to the real public API surface."""
    fake = Mock(spec=SandboxManager)
    fake.run_sandboxed.return_value = make_result()
    fake.list_sandboxes.return_value = []
    fake.get_sandbox.return_value = None
    fake.terminate_sandbox.return_value = True
    fake.get_capabilities.return_value = {}
    for name, value in attrs.items():
        setattr(fake, name, value)
    return fake


def make_cli(fake_manager=None):
    cli = SandboxCLI(socket_path='/nonexistent.sock', config_path='/nonexistent.yaml')
    cli._manager = fake_manager if fake_manager is not None else make_manager()
    return cli


def make_usage(**overrides):
    fields = dict(
        cpu_usage_us=1_500_000,
        memory_current_bytes=1024 * 1024,
        memory_peak_bytes=2 * 1024 * 1024,
        io_read_bytes=0,
        io_write_bytes=4096,
    )
    fields.update(overrides)
    return ResourceUsage(**fields)


def make_info(**overrides):
    """A dict shaped exactly like Sandbox.get_info()."""
    info = {
        'id': 'sb-1',
        'profile': 'standard',
        'state': 'RUNNING',
        'pid': 4242,
        'command': ['python3', 'job.py'],
        'created_at': '2026-09-20T10:00:00Z',
        'started_at': '2026-09-20T10:00:01Z',
        'uptime_seconds': 5.0,
        'cgroup_path': '/sys/fs/cgroup/boundary/sb-1',
        'namespace_flags': 'NamespaceFlags.STANDARD',
        'seccomp_enabled': True,
        'network_disabled': False,
        'readonly_filesystem': False,
        'network_policy': {
            'allow_all': False,
            'deny_all': True,
            'allowed_hosts': [],
            'allowed_ports': [],
            'blocked_hosts': [],
        },
        'resource_limits': {
            'memory_max_bytes': 1024 ** 3,
            'memory_high_bytes': None,
            'cpu_quota_us': None,
            'cpu_period_us': 100000,
            'cpu_max_cores': 2.0,
            'pids_max': 200,
        },
        'resource_usage': make_usage().to_dict(),
    }
    info.update(overrides)
    return info


def make_real_sandbox(profile=None, sandbox_id='sb-real'):
    """A real Sandbox object with Mock managers; it is never run."""
    return Sandbox(
        sandbox_id=sandbox_id,
        profile=profile or SandboxProfile.standard(),
        namespace_manager=Mock(),
        cgroup_manager=Mock(),
        sandbox_firewall=None,
    )


def make_bare_manager(**attrs):
    """SandboxManager without __init__ (no NamespaceManager/CgroupManager probing)."""
    manager = SandboxManager.__new__(SandboxManager)
    manager._lock = threading.Lock()
    manager._sandboxes = {}
    manager._telemetry = None
    manager._total_created = 0
    manager._total_completed = 0
    manager._total_failed = 0
    for name, value in attrs.items():
        setattr(manager, name, value)
    return manager


def bind_to(method, call):
    """Bind a mock call's args/kwargs against a real unbound method signature."""
    args, kwargs = call
    return inspect.signature(method).bind(None, *args, **kwargs)


# ---------------------------------------------------------------------------
# _resolve_profile
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestResolveProfile:

    @pytest.mark.parametrize('name, expected', [
        ('minimal', 'minimal'),
        ('standard', 'standard'),
        ('strict', 'strict'),
        ('untrusted', 'strict'),  # alias
    ])
    def test_builtin_profiles(self, name, expected):
        profile = make_cli()._resolve_profile(name)
        assert isinstance(profile, SandboxProfile)
        assert profile.name == expected

    @pytest.mark.parametrize('name', SandboxCLI._MODE_PROFILES)
    def test_boundary_mode_profiles(self, name):
        profile = make_cli()._resolve_profile(name)
        assert isinstance(profile, SandboxProfile)
        # from_boundary_mode(OPEN) is the minimal profile; every other mode
        # yields a profile named after the mode.
        expected = 'minimal' if name == 'open' else name
        assert profile.name == expected

    def test_airgap_is_network_isolated(self):
        profile = make_cli()._resolve_profile('airgap')
        assert profile.name == 'airgap'
        assert profile.network_disabled is True

    def test_name_is_normalised(self):
        assert make_cli()._resolve_profile('  Standard ').name == 'standard'
        assert make_cli()._resolve_profile('AIRGAP').name == 'airgap'

    def test_unknown_profile_raises(self):
        with pytest.raises(ValueError, match='no-such-profile'):
            make_cli()._resolve_profile('no-such-profile')

    def test_each_call_returns_a_fresh_profile(self):
        """cmd_run mutates the profile, so it must not be a shared instance."""
        cli = make_cli()
        assert cli._resolve_profile('standard') is not cli._resolve_profile('standard')

    def test_loaded_profile_takes_precedence(self, empty_profile_loader):
        custom = SandboxProfile(name='custom-standard')
        loader = Mock()
        loader.get_sandbox_profile.side_effect = (
            lambda key: custom if key == 'standard' else None
        )
        empty_profile_loader.return_value = loader

        cli = make_cli()
        assert cli._resolve_profile('Standard') is custom
        loader.get_sandbox_profile.assert_called_with('standard')
        # names the loader does not know still fall through to the built-ins
        assert cli._resolve_profile('strict').name == 'strict'

    def test_loader_failure_falls_back_to_builtins(self, empty_profile_loader):
        empty_profile_loader.side_effect = RuntimeError('no config')
        assert make_cli()._resolve_profile('standard').name == 'standard'


@pytest.mark.unit
class TestParseMemory:

    @pytest.mark.parametrize('text, expected', [
        ('512M', 512 * 1024 * 1024),
        ('512MB', 512 * 1024 * 1024),
        ('1G', 1024 ** 3),
        ('1.5g', int(1.5 * 1024 ** 3)),
        ('64K', 64 * 1024),
        ('2kb', 2 * 1024),
        ('100B', 100),
        ('4096', 4096),
        (' 8M ', 8 * 1024 * 1024),
    ])
    def test_parse_memory(self, text, expected):
        assert make_cli()._parse_memory(text) == expected


# ---------------------------------------------------------------------------
# cmd_run
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestCmdRun:

    def test_overrides_and_kwargs_match_run_sandboxed_signature(self, capsys):
        fake = make_manager()
        cli = make_cli(fake)
        args = parse(
            'run', '--profile', 'standard', '--memory', '512M', '--cpu', '50',
            '--timeout', '30', '--network-deny', '--', 'true',
        )
        # '--' hands the rest to the positional 'command'
        assert args.command == ['true']

        rc = cli.cmd_run(args)

        assert rc == 0
        assert 'hi' in capsys.readouterr().out
        fake.run_sandboxed.assert_called_once()

        # Every argument must be accepted by the real API.
        call_args, call_kwargs = fake.run_sandboxed.call_args
        assert call_args == ()
        bound = inspect.signature(SandboxManager.run_sandboxed).bind(None, **call_kwargs)

        assert bound.arguments['command'] == ['true']
        assert bound.arguments['timeout'] == 30
        assert bound.arguments['capture_output'] is True
        assert bound.arguments['env'] is None

        profile = bound.arguments['profile']
        assert isinstance(profile, SandboxProfile)
        assert profile.name == 'standard'
        assert isinstance(profile.cgroup_limits, CgroupLimits)
        assert profile.cgroup_limits.memory_max_bytes == 512 * 1024 * 1024
        assert profile.cgroup_limits.cpu_quota_us == 50000
        assert profile.cgroup_limits.cpu_period_us == 100000
        assert profile.max_runtime_seconds == 30
        assert isinstance(profile.network_policy, NetworkPolicy)
        assert profile.network_policy.deny_all is True

    def test_overrides_create_cgroup_limits_when_profile_has_none(self):
        fake = make_manager()
        cli = make_cli(fake)
        with patch.object(cli, '_resolve_profile', return_value=SandboxProfile(name='bare')):
            rc = cli.cmd_run(parse('run', '--memory', '1G', '--cpu', '25', '--', 'true'))
        assert rc == 0
        profile = fake.run_sandboxed.call_args.kwargs['profile']
        assert isinstance(profile.cgroup_limits, CgroupLimits)
        assert profile.cgroup_limits.memory_max_bytes == 1024 ** 3
        assert profile.cgroup_limits.cpu_quota_us == 25000

    def test_network_allow_builds_filtered_policy(self):
        fake = make_manager()
        cli = make_cli(fake)
        rc = cli.cmd_run(parse(
            'run', '--network-allow', 'a.example.com:443', '10.0.0.0/8', '--', 'true',
        ))
        assert rc == 0
        policy = fake.run_sandboxed.call_args.kwargs['profile'].network_policy
        assert isinstance(policy, NetworkPolicy)
        assert policy.allow_all is False
        assert policy.deny_all is False
        assert policy.allowed_hosts == ['a.example.com:443', '10.0.0.0/8']

    def test_no_overrides_leave_profile_untouched(self):
        fake = make_manager()
        cli = make_cli(fake)
        rc = cli.cmd_run(parse('run', '--profile', 'strict', '--', 'true'))
        assert rc == 0
        expected = SandboxProfile.strict()
        profile = fake.run_sandboxed.call_args.kwargs['profile']
        assert profile.name == 'strict'
        assert profile.cgroup_limits == expected.cgroup_limits
        assert profile.max_runtime_seconds == expected.max_runtime_seconds
        assert profile.network_policy == expected.network_policy
        assert fake.run_sandboxed.call_args.kwargs['timeout'] is None

    def test_interactive_passes_capture_output_false(self, capsys):
        fake = make_manager()
        cli = make_cli(fake)
        rc = cli.cmd_run(parse('run', '--interactive', '--', 'true'))
        assert rc == 0
        kwargs = fake.run_sandboxed.call_args.kwargs
        inspect.signature(SandboxManager.run_sandboxed).bind(None, **kwargs)
        assert kwargs['capture_output'] is False
        # nothing was captured, so the CLI must not echo result.stdout
        assert 'hi' not in capsys.readouterr().out

    def test_inherit_env_passes_environment_dict(self):
        fake = make_manager()
        cli = make_cli(fake)
        with patch.dict(os.environ, {'SANDBOXCTL_TEST_VAR': 'yes'}):
            rc = cli.cmd_run(parse('run', '--inherit-env', '--', 'true'))
        assert rc == 0
        env = fake.run_sandboxed.call_args.kwargs['env']
        assert isinstance(env, dict)
        assert env['SANDBOXCTL_TEST_VAR'] == 'yes'

    def test_unknown_profile_returns_1_without_running(self, capsys):
        fake = make_manager()
        cli = make_cli(fake)
        rc = cli.cmd_run(parse('run', '--profile', 'bogus', '--', 'true'))
        assert rc == 1
        fake.run_sandboxed.assert_not_called()
        assert 'E012' in capsys.readouterr().err

    def test_no_command_returns_1(self, capsys):
        fake = make_manager()
        cli = make_cli(fake)
        rc = cli.cmd_run(parse('run'))
        assert rc == 1
        fake.run_sandboxed.assert_not_called()
        assert 'E003' in capsys.readouterr().err

    def test_exit_code_is_propagated(self, capsys):
        fake = make_manager()
        fake.run_sandboxed.return_value = make_result(exit_code=3, stdout='', stderr='bad')
        cli = make_cli(fake)
        rc = cli.cmd_run(parse('run', '--', 'false'))
        assert rc == 3
        captured = capsys.readouterr()
        assert 'bad' in captured.err
        assert 'exited with code 3' in captured.out

    def test_killed_result_is_reported(self, capsys):
        fake = make_manager()
        fake.run_sandboxed.return_value = make_result(
            exit_code=137, stdout='', killed=True, kill_reason='timeout',
        )
        cli = make_cli(fake)
        rc = cli.cmd_run(parse('run', '--', 'sleep', '100'))
        assert rc == 137
        assert 'timeout' in capsys.readouterr().out

    def test_sandbox_error_returns_1(self, capsys):
        fake = make_manager()
        fake.run_sandboxed.side_effect = SandboxError('Ceremony required')
        cli = make_cli(fake)
        rc = cli.cmd_run(parse('run', '--', 'true'))
        assert rc == 1
        err = capsys.readouterr().err
        assert 'E010' in err
        assert 'Ceremony required' in err

    def test_verbose_prints_resource_usage_fields(self, capsys):
        """The verbose block reads real ResourceUsage attribute names."""
        fake = make_manager()
        fake.run_sandboxed.return_value = make_result(resource_usage=make_usage())
        cli = make_cli(fake)
        rc = cli.cmd_run(parse('-v', 'run', '--', 'true'))
        assert rc == 0
        out = capsys.readouterr().out
        assert 'Resource Usage:' in out
        assert 'CPU time:     1.50s' in out
        assert 'Memory peak:  2.0MB' in out
        assert 'I/O write:    4.0KB' in out

    def test_quiet_suppresses_info_lines(self, capsys):
        cli = make_cli()
        rc = cli.cmd_run(parse('run', '--quiet', '--', 'true'))
        assert rc == 0
        out = capsys.readouterr().out
        assert out == 'hi'

    def test_signal_handlers_are_installed(self, no_signal_handlers):
        import signal as _signal
        cli = make_cli()
        cli.cmd_run(parse('run', '--', 'true'))
        installed = {call.args[0] for call in no_signal_handlers.call_args_list}
        assert {_signal.SIGINT, _signal.SIGTERM} <= installed


# ---------------------------------------------------------------------------
# cmd_list
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestCmdList:

    def test_empty(self, capsys):
        cli = make_cli()
        assert cli.cmd_list(parse('list')) == 0
        assert 'No active sandboxes' in capsys.readouterr().out

    def test_ls_alias_parses(self):
        assert parse('ls', '-o', 'wide').output == 'wide'

    def test_table_output(self, capsys):
        fake = make_manager()
        fake.list_sandboxes.return_value = [
            make_info(),
            make_info(id='sb-2', profile='airgap', state='CREATED', pid=None,
                      uptime_seconds=None, resource_usage=None),
        ]
        cli = make_cli(fake)
        assert cli.cmd_list(parse('list')) == 0
        out = capsys.readouterr().out
        lines = out.splitlines()
        row1 = next(line for line in lines if line.startswith('sb-1'))
        row2 = next(line for line in lines if line.startswith('sb-2'))
        assert 'standard' in row1 and 'RUNNING' in row1 and '4242' in row1
        assert '5.0s' in row1
        assert '1.0MB' in row1  # resource_usage.memory.current_bytes
        assert 'airgap' in row2 and 'CREATED' in row2
        assert row2.split()[3:] == ['-', '-', '-']  # pid, uptime, memory placeholders
        assert '2 sandbox(es) total' in out

    def test_json_output(self, capsys):
        fake = make_manager()
        fake.list_sandboxes.return_value = [make_info()]
        cli = make_cli(fake)
        assert cli.cmd_list(parse('list', '--output', 'json')) == 0
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data, list) and len(data) == 1
        assert data[0]['id'] == 'sb-1'
        assert data[0]['resource_usage']['memory']['current_bytes'] == 1024 * 1024
        assert data[0]['resource_usage']['cpu']['total_us'] == 1_500_000

    def test_wide_output(self, capsys):
        fake = make_manager()
        fake.list_sandboxes.return_value = [make_info()]
        cli = make_cli(fake)
        assert cli.cmd_list(parse('list', '-o', 'wide')) == 0
        out = capsys.readouterr().out
        assert 'Sandbox: sb-1' in out
        assert 'Profile:  standard' in out
        assert 'State:    RUNNING' in out
        assert 'PID:      4242' in out
        assert 'Command:  python3 job.py' in out
        assert 'Cgroup:   /sys/fs/cgroup/boundary/sb-1' in out
        assert 'Memory: 1.0MB' in out
        assert 'CPU:    1.50s' in out

    def test_wide_output_without_usage(self, capsys):
        fake = make_manager()
        fake.list_sandboxes.return_value = [
            make_info(resource_usage=None, command=None, cgroup_path=None, pid=None),
        ]
        cli = make_cli(fake)
        assert cli.cmd_list(parse('list', '-o', 'wide')) == 0
        out = capsys.readouterr().out
        assert 'Resources:' not in out
        assert 'Command:  N/A' in out
        assert 'PID:      N/A' in out


# ---------------------------------------------------------------------------
# cmd_inspect
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestCmdInspect:

    def test_not_found_returns_1(self, capsys):
        fake = make_manager()
        cli = make_cli(fake)
        rc = cli.cmd_inspect(parse('inspect', 'nope'))
        assert rc == 1
        fake.get_sandbox.assert_called_once_with('nope')
        assert 'E011' in capsys.readouterr().err

    def test_text_output(self, capsys):
        fake = make_manager()
        sandbox = Mock(spec=Sandbox)
        sandbox.get_info.return_value = make_info()
        fake.get_sandbox.return_value = sandbox
        cli = make_cli(fake)

        rc = cli.cmd_inspect(parse('inspect', 'sb-1'))

        assert rc == 0
        out = capsys.readouterr().out
        assert 'Sandbox: sb-1' in out
        assert 'Profile:    standard' in out
        assert 'State:      RUNNING' in out
        assert 'PID:        4242' in out
        assert 'Command:    python3 job.py' in out
        assert 'Namespaces: NamespaceFlags.STANDARD' in out
        assert 'Seccomp:    enabled' in out
        assert 'Read-only:  no' in out
        assert 'Mode:       DENY ALL' in out
        assert 'Memory:     1.0GB' in out   # limit
        assert 'CPU:        2.0 cores' in out
        assert 'PIDs:       200' in out
        assert 'Memory:     1.0MB' in out   # usage (nested memory.current_bytes)
        assert 'CPU time:   1.50s' in out

    def test_text_output_cpu_quota_and_filtered_network(self, capsys):
        fake = make_manager()
        sandbox = Mock(spec=Sandbox)
        sandbox.get_info.return_value = make_info(
            network_policy={'allow_all': False, 'deny_all': False,
                            'allowed_hosts': ['a.example.com', 'b.example.com'],
                            'allowed_ports': [], 'blocked_hosts': []},
            resource_limits={'memory_max_bytes': None, 'memory_high_bytes': None,
                             'cpu_quota_us': 50000, 'cpu_period_us': 100000,
                             'cpu_max_cores': None, 'pids_max': None},
            resource_usage=None,
        )
        fake.get_sandbox.return_value = sandbox
        cli = make_cli(fake)
        assert cli.cmd_inspect(parse('inspect', 'sb-1')) == 0
        out = capsys.readouterr().out
        assert 'Mode:       FILTERED' in out
        assert 'Allowed:    a.example.com, b.example.com' in out
        assert 'CPU:        50%' in out
        assert 'Resource Usage:' not in out

    def test_text_output_network_disabled(self, capsys):
        fake = make_manager()
        sandbox = Mock(spec=Sandbox)
        sandbox.get_info.return_value = make_info(network_disabled=True, network_policy=None)
        fake.get_sandbox.return_value = sandbox
        cli = make_cli(fake)
        assert cli.cmd_inspect(parse('inspect', 'sb-1')) == 0
        assert 'Mode:       DISABLED' in capsys.readouterr().out

    def test_json_output(self, capsys):
        fake = make_manager()
        sandbox = Mock(spec=Sandbox)
        sandbox.get_info.return_value = make_info()
        fake.get_sandbox.return_value = sandbox
        cli = make_cli(fake)
        assert cli.cmd_inspect(parse('inspect', 'sb-1', '-o', 'json')) == 0
        data = json.loads(capsys.readouterr().out)
        assert data['id'] == 'sb-1'
        assert data['profile'] == 'standard'
        assert data['state'] == 'RUNNING'
        assert data['resource_usage']['memory']['peak_bytes'] == 2 * 1024 * 1024


# ---------------------------------------------------------------------------
# cmd_kill
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestCmdKill:

    def test_kill_calls_terminate_with_reason(self, capsys):
        fake = make_manager()
        cli = make_cli(fake)
        rc = cli.cmd_kill(parse('kill', 'sb-1'))
        assert rc == 0
        fake.terminate_sandbox.assert_called_once()
        bound = bind_to(SandboxManager.terminate_sandbox, fake.terminate_sandbox.call_args)
        assert bound.arguments['sandbox_id'] == 'sb-1'
        assert bound.arguments['reason'] == 'sandboxctl kill'
        assert 'reason' in fake.terminate_sandbox.call_args.kwargs
        assert 'Killed sandbox: sb-1' in capsys.readouterr().out

    def test_force_changes_reason(self):
        fake = make_manager()
        cli = make_cli(fake)
        assert cli.cmd_kill(parse('kill', '--force', 'sb-1')) == 0
        bound = bind_to(SandboxManager.terminate_sandbox, fake.terminate_sandbox.call_args)
        assert bound.arguments['reason'] == 'sandboxctl kill --force'

    def test_not_found_returns_1_and_prints_error(self, capsys):
        fake = make_manager()
        fake.terminate_sandbox.return_value = False
        cli = make_cli(fake)
        rc = cli.cmd_kill(parse('kill', 'ghost'))
        assert rc == 1
        err = capsys.readouterr().err
        assert 'E011' in err
        assert 'ghost' in err

    def test_multiple_ids_continue_after_failure(self, capsys):
        fake = make_manager()
        fake.terminate_sandbox.side_effect = [False, True]
        cli = make_cli(fake)
        rc = cli.cmd_kill(parse('kill', 'ghost', 'sb-2'))
        assert rc == 1
        assert fake.terminate_sandbox.call_count == 2
        captured = capsys.readouterr()
        assert 'Killed sandbox: sb-2' in captured.out
        assert 'ghost' in captured.err

    def test_exception_is_reported_not_raised(self, capsys):
        fake = make_manager()
        fake.terminate_sandbox.side_effect = OSError('permission denied')
        cli = make_cli(fake)
        rc = cli.cmd_kill(parse('kill', 'sb-1'))
        assert rc == 1
        err = capsys.readouterr().err
        assert 'E010' in err and 'permission denied' in err

    def test_all_uses_list_sandboxes_ids(self):
        fake = make_manager()
        fake.list_sandboxes.return_value = [make_info(id='sb-1'), make_info(id='sb-2')]
        cli = make_cli(fake)
        rc = cli.cmd_kill(parse('kill', '--all'))
        assert rc == 0
        fake.list_sandboxes.assert_called_once_with()
        killed = [
            bind_to(SandboxManager.terminate_sandbox, call).arguments['sandbox_id']
            for call in fake.terminate_sandbox.call_args_list
        ]
        assert killed == ['sb-1', 'sb-2']

    def test_all_with_nothing_running(self, capsys):
        fake = make_manager()
        cli = make_cli(fake)
        rc = cli.cmd_kill(parse('kill', '--all'))
        assert rc == 0
        fake.terminate_sandbox.assert_not_called()
        assert 'No sandboxes to kill' in capsys.readouterr().out

    def test_no_ids_and_no_all(self, capsys):
        fake = make_manager()
        cli = make_cli(fake)
        assert cli.cmd_kill(parse('kill')) == 0
        fake.terminate_sandbox.assert_not_called()
        assert 'No sandboxes to kill' in capsys.readouterr().out


# ---------------------------------------------------------------------------
# cmd_profiles
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestCmdProfiles:

    def test_json_lists_builtin_and_mode_profiles(self, capsys):
        cli = make_cli()
        assert cli.cmd_profiles(parse('profiles', '-o', 'json')) == 0
        data = json.loads(capsys.readouterr().out)
        names = {entry['name'] for entry in data}
        assert {'minimal', 'standard', 'strict', 'airgap', 'coldroom', 'lockdown'} <= names
        assert all(set(entry) == {'name', 'description'} for entry in data)

    def test_every_listed_profile_resolves(self, capsys):
        cli = make_cli()
        cli.cmd_profiles(parse('profiles', '-o', 'json'))
        for entry in json.loads(capsys.readouterr().out):
            assert isinstance(cli._resolve_profile(entry['name']), SandboxProfile)

    def test_json_includes_loaded_profiles(self, capsys, empty_profile_loader):
        empty_profile_loader.return_value.list_profiles.return_value = ['custom']
        cli = make_cli()
        assert cli.cmd_profiles(parse('profiles', '-o', 'json')) == 0
        names = [entry['name'] for entry in json.loads(capsys.readouterr().out)]
        assert 'custom' in names

    def test_text_output(self, capsys):
        cli = make_cli()
        assert cli.cmd_profiles(parse('profiles')) == 0
        out = capsys.readouterr().out
        assert 'Available Sandbox Profiles' in out
        assert 'standard' in out and 'airgap' in out

    def test_loader_failure_is_ignored(self, capsys, empty_profile_loader):
        empty_profile_loader.side_effect = RuntimeError('no config')
        cli = make_cli()
        assert cli.cmd_profiles(parse('profiles', '-o', 'json')) == 0
        assert 'standard' in {e['name'] for e in json.loads(capsys.readouterr().out)}


# ---------------------------------------------------------------------------
# cmd_test (against a fake manager, no real sandboxing)
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestCmdTest:

    @staticmethod
    def _fake_run(command, **kwargs):
        # 'true' succeeds; every probe command fails, which is the "isolated" outcome
        return make_result(command=command, exit_code=0 if command == ['true'] else 1,
                           stdout='', stderr='')

    def test_all_probes_use_real_signature(self, capsys):
        fake = make_manager()
        fake.run_sandboxed.side_effect = self._fake_run
        cli = make_cli(fake)
        rc = cli.cmd_test(parse('test', '--profile', 'airgap'))
        assert rc == 0
        assert fake.run_sandboxed.call_count == 4  # airgap includes the network probe
        for call in fake.run_sandboxed.call_args_list:
            bound = bind_to(SandboxManager.run_sandboxed, call)
            assert isinstance(bound.arguments['profile'], SandboxProfile)
            assert bound.arguments['profile'].name == 'airgap'
            assert bound.arguments['capture_output'] is True
        out = capsys.readouterr().out
        assert '4 passed, 0 failed' in out

    def test_failed_probe_returns_1(self, capsys):
        fake = make_manager()
        fake.run_sandboxed.return_value = make_result(exit_code=1, stdout='', stderr='')
        cli = make_cli(fake)
        rc = cli.cmd_test(parse('test', '--profile', 'standard'))
        assert rc == 1
        assert '3 passed, 1 failed' in capsys.readouterr().out  # cgroup probe needs exit 0

    def test_unknown_profile_returns_1(self, capsys):
        fake = make_manager()
        cli = make_cli(fake)
        rc = cli.cmd_test(parse('test', '--profile', 'bogus'))
        assert rc == 1
        fake.run_sandboxed.assert_not_called()
        assert 'E012' in capsys.readouterr().err


# ---------------------------------------------------------------------------
# cmd_metrics
# ---------------------------------------------------------------------------

PROM_TEXT = b'# HELP a b\n# TYPE a counter\na{x="1",y="z"} 3\nb 4.5\n'


def _urlopen_returning(payload):
    response = MagicMock()
    response.read.return_value = payload
    ctx = MagicMock()
    ctx.__enter__.return_value = response
    return Mock(return_value=ctx)


@pytest.mark.unit
class TestCmdMetrics:

    def test_json_output(self, capsys):
        urlopen = _urlopen_returning(PROM_TEXT)
        with patch('daemon.cli.sandboxctl.urllib.request.urlopen', urlopen):
            rc = make_cli().cmd_metrics(parse('metrics', '-o', 'json',
                                              '--metrics-url', 'http://127.0.0.1:9090/metrics'))
        assert rc == 0
        urlopen.assert_called_once()
        assert urlopen.call_args.args[0] == 'http://127.0.0.1:9090/metrics'
        assert urlopen.call_args.kwargs.get('timeout') == 5
        samples = json.loads(capsys.readouterr().out)
        assert samples == [
            {'name': 'a', 'labels': {'x': '1', 'y': 'z'}, 'value': 3.0},
            {'name': 'b', 'labels': {}, 'value': 4.5},
        ]

    def test_text_output(self, capsys):
        with patch('daemon.cli.sandboxctl.urllib.request.urlopen', _urlopen_returning(PROM_TEXT)):
            rc = make_cli().cmd_metrics(parse('metrics', '--metrics-url', 'http://localhost:1/m'))
        assert rc == 0
        out = capsys.readouterr().out
        assert 'Daemon Metrics (http://localhost:1/m)' in out
        assert 'a {x=1, y=z}: 3.0' in out
        assert 'b: 4.5' in out

    @pytest.mark.parametrize('url', ['file:///etc/passwd', 'ftp://host/metrics', 'localhost:9090'])
    def test_non_http_url_is_rejected_without_fetching(self, capsys, url):
        urlopen = _urlopen_returning(PROM_TEXT)
        with patch('daemon.cli.sandboxctl.urllib.request.urlopen', urlopen):
            rc = make_cli().cmd_metrics(parse('metrics', '--metrics-url', url))
        assert rc == 1
        urlopen.assert_not_called()
        assert 'E013' in capsys.readouterr().err

    def test_unreachable_exporter_returns_1(self, capsys):
        urlopen = Mock(side_effect=urllib.error.URLError('connection refused'))
        with patch('daemon.cli.sandboxctl.urllib.request.urlopen', urlopen):
            rc = make_cli().cmd_metrics(parse('metrics', '--metrics-url', 'http://127.0.0.1:1/m'))
        assert rc == 1
        err = capsys.readouterr().err
        assert 'E013' in err and 'connection refused' in err

    def test_default_url_is_http(self):
        from daemon.cli.sandboxctl import DEFAULT_METRICS_URL
        assert DEFAULT_METRICS_URL.startswith(('http://', 'https://'))
        assert parse('metrics').metrics_url is None

    def test_parse_prometheus_text(self):
        text = (
            '# HELP a b\n'
            '# TYPE a counter\n'
            '\n'
            'a{x="1",y="z"} 3\n'
            '  b 4.5  \n'
            'c{} 7\n'
            'broken not_a_number\n'
            'd 1e3\n'
        )
        samples = SandboxCLI._parse_prometheus_text(text)
        assert samples == [
            {'name': 'a', 'labels': {'x': '1', 'y': 'z'}, 'value': 3.0},
            {'name': 'b', 'labels': {}, 'value': 4.5},
            {'name': 'c', 'labels': {}, 'value': 7.0},
            {'name': 'd', 'labels': {}, 'value': 1000.0},
        ]

    def test_parse_prometheus_text_empty(self):
        assert SandboxCLI._parse_prometheus_text('') == []
        assert SandboxCLI._parse_prometheus_text('# only comments\n') == []


# ---------------------------------------------------------------------------
# Sandbox.get_info() and SandboxManager listing API (real objects, never run)
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSandboxGetInfo:

    EXPECTED_KEYS = {
        'id', 'profile', 'state', 'pid', 'command', 'created_at', 'started_at',
        'uptime_seconds', 'cgroup_path', 'namespace_flags', 'seccomp_enabled',
        'network_disabled', 'readonly_filesystem', 'network_policy',
        'resource_limits', 'resource_usage',
    }

    def test_fresh_sandbox_info(self):
        sandbox = make_real_sandbox()
        info = sandbox.get_info()

        assert set(info) == self.EXPECTED_KEYS
        assert info['id'] == 'sb-real'
        assert info['profile'] == 'standard'
        assert info['state'] == 'CREATED'
        assert sandbox.state is SandboxState.CREATED
        assert info['pid'] is None
        assert info['uptime_seconds'] is None
        assert info['started_at'] is None
        assert info['command'] is None
        assert info['cgroup_path'] is None
        assert info['resource_usage'] is None
        assert info['network_policy'] is None  # standard profile has no firewall policy
        assert info['seccomp_enabled'] is True
        assert info['network_disabled'] is False
        assert info['readonly_filesystem'] is False
        assert info['created_at'].endswith('Z')

        limits = CgroupLimits.standard()
        assert info['resource_limits'] == {
            'memory_max_bytes': limits.memory_max_bytes,
            'memory_high_bytes': limits.memory_high_bytes,
            'cpu_quota_us': limits.cpu_quota_us,
            'cpu_period_us': limits.cpu_period_us,
            'cpu_max_cores': limits.cpu_max_cores,
            'pids_max': limits.pids_max,
        }
        json.dumps(info)  # must be JSON-serialisable for `list -o json`

    def test_fake_info_matches_real_shape(self):
        """The dict the CLI tests feed in has the same keys as the real one."""
        assert set(make_info()) == set(make_real_sandbox().get_info())

    def test_info_with_cgroup_usage_is_nested(self):
        sandbox = make_real_sandbox()
        sandbox._cgroup_path = Path('/sys/fs/cgroup/boundary/sb-real')
        sandbox._cgroup_manager.get_usage.return_value = make_usage()

        info = sandbox.get_info()

        sandbox._cgroup_manager.get_usage.assert_called_once_with(sandbox._cgroup_path)
        assert info['cgroup_path'] == '/sys/fs/cgroup/boundary/sb-real'
        assert info['resource_usage'] == make_usage().to_dict()
        assert info['resource_usage']['memory']['current_bytes'] == 1024 * 1024
        assert info['resource_usage']['memory']['peak_bytes'] == 2 * 1024 * 1024
        assert info['resource_usage']['cpu']['total_us'] == 1_500_000

    def test_usage_read_error_yields_none(self):
        sandbox = make_real_sandbox()
        sandbox._cgroup_path = Path('/sys/fs/cgroup/boundary/gone')
        sandbox._cgroup_manager.get_usage.side_effect = OSError('cgroup removed')
        assert sandbox.get_info()['resource_usage'] is None

    def test_airgap_profile_network_policy_dict(self):
        info = make_real_sandbox(profile=SandboxProfile.from_boundary_mode(3)).get_info()
        assert info['profile'] == 'airgap'
        assert info['network_disabled'] is True
        policy = info['network_policy']
        assert set(policy) == {'allow_all', 'deny_all', 'allowed_hosts',
                               'allowed_ports', 'blocked_hosts'}
        assert isinstance(policy['allowed_hosts'], list)

    def test_real_info_renders_through_cli(self, capsys):
        """End to end: real get_info() dict -> cmd_list wide / cmd_inspect text."""
        sandbox = make_real_sandbox()
        sandbox._cgroup_path = Path('/sys/fs/cgroup/boundary/sb-real')
        sandbox._cgroup_manager.get_usage.return_value = make_usage()

        fake = make_manager()
        fake.list_sandboxes.return_value = [sandbox.get_info()]
        fake.get_sandbox.return_value = sandbox
        cli = make_cli(fake)

        assert cli.cmd_list(parse('list', '-o', 'wide')) == 0
        out = capsys.readouterr().out
        assert 'Sandbox: sb-real' in out
        assert 'State:    CREATED' in out
        assert 'Memory: 1.0MB' in out
        assert 'CPU:    1.50s' in out

        assert cli.cmd_list(parse('list')) == 0
        row = next(line for line in capsys.readouterr().out.splitlines()
                   if line.startswith('sb-real'))
        assert 'CREATED' in row and '1.0MB' in row

        assert cli.cmd_inspect(parse('inspect', 'sb-real')) == 0
        out = capsys.readouterr().out
        assert 'Profile:    standard' in out
        assert 'State:      CREATED' in out
        assert 'Memory:     1.0GB' in out
        assert 'Memory:     1.0MB' in out
        assert 'CPU time:   1.50s' in out


@pytest.mark.unit
class TestSandboxManagerApi:

    def test_list_sandboxes_returns_get_info_dicts(self):
        fake_sandbox = Mock(spec=Sandbox)
        fake_sandbox.get_info.return_value = make_info(id='a')
        manager = make_bare_manager(_sandboxes={'a': fake_sandbox})

        listed = manager.list_sandboxes()

        assert listed == [make_info(id='a')]
        fake_sandbox.get_info.assert_called_once_with()

    def test_list_sandboxes_with_real_sandbox(self):
        sandbox = make_real_sandbox(sandbox_id='real-1')
        manager = make_bare_manager(_sandboxes={'real-1': sandbox})
        listed = manager.list_sandboxes()
        assert len(listed) == 1
        assert listed[0]['id'] == 'real-1'
        assert listed[0]['state'] == 'CREATED'

    def test_get_sandbox(self):
        sandbox = Mock(spec=Sandbox)
        manager = make_bare_manager(_sandboxes={'a': sandbox})
        assert manager.get_sandbox('a') is sandbox
        assert manager.get_sandbox('zzz') is None

    def test_terminate_sandbox_forwards_reason(self):
        sandbox = Mock(spec=Sandbox)
        manager = make_bare_manager(_sandboxes={'a': sandbox})
        assert manager.terminate_sandbox('a', reason='sandboxctl kill') is True
        sandbox.terminate.assert_called_once_with(reason='sandboxctl kill')
        assert manager.terminate_sandbox('zzz', reason='sandboxctl kill') is False

    def test_run_sandboxed_forwards_capture_output(self):
        sandbox = Mock(spec=Sandbox)
        sandbox.sandbox_id = 'sb-tmp'
        sandbox.run.return_value = make_result(sandbox_id='sb-tmp')
        manager = make_bare_manager(_sandboxes={'sb-tmp': sandbox})

        with patch.object(manager, 'create_sandbox', return_value=sandbox) as create:
            result = manager.run_sandboxed(['true'], capture_output=False)

        assert result.sandbox_id == 'sb-tmp'
        create.assert_called_once()
        assert create.call_args.kwargs['profile'] is None

        sandbox.run.assert_called_once()
        bound = bind_to(Sandbox.run, sandbox.run.call_args)
        assert bound.arguments['command'] == ['true']
        assert bound.arguments['capture_output'] is False
        assert bound.arguments['env'] is None
        assert bound.arguments['stdin'] is None
        assert bound.arguments['timeout'] is None

        sandbox.cleanup.assert_called_once_with()
        assert manager._sandboxes == {}
        assert manager._total_completed == 1
        assert manager._total_failed == 0

    def test_run_sandboxed_forwards_all_cli_kwargs(self):
        sandbox = Mock(spec=Sandbox)
        sandbox.sandbox_id = 'sb-tmp'
        sandbox.run.return_value = make_result()
        manager = make_bare_manager()
        profile = SandboxProfile.strict()

        with patch.object(manager, 'create_sandbox', return_value=sandbox) as create:
            manager.run_sandboxed(
                command=['true'], env={'A': '1'}, profile=profile,
                timeout=30, capture_output=True,
            )

        assert create.call_args.kwargs['profile'] is profile
        bound = bind_to(Sandbox.run, sandbox.run.call_args)
        assert bound.arguments['env'] == {'A': '1'}
        assert bound.arguments['timeout'] == 30
        assert bound.arguments['capture_output'] is True

    def test_run_sandboxed_error_counts_failure_and_cleans_up(self):
        sandbox = Mock(spec=Sandbox)
        sandbox.sandbox_id = 'sb-tmp'
        sandbox.run.side_effect = SandboxError('boom')
        telemetry = Mock()
        manager = make_bare_manager(_sandboxes={'sb-tmp': sandbox}, _telemetry=telemetry)

        with patch.object(manager, 'create_sandbox', return_value=sandbox):
            with pytest.raises(SandboxError, match='boom'):
                manager.run_sandboxed(['true'])

        assert manager._total_failed == 1
        assert manager._total_completed == 0
        sandbox.cleanup.assert_called_once_with()
        telemetry.untrack_sandbox.assert_called_once_with('sb-tmp')
        assert manager._sandboxes == {}


# ---------------------------------------------------------------------------
# main() dispatch
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestMain:

    def test_no_arguments_prints_help(self, capsys):
        with patch.object(sys, 'argv', ['sandboxctl']):
            assert main() == 0
        assert 'usage: sandboxctl' in capsys.readouterr().out

    def test_dispatches_profiles(self, capsys):
        with patch.object(sys, 'argv', ['sandboxctl', 'profiles', '-o', 'json']):
            assert main() == 0
        names = {e['name'] for e in json.loads(capsys.readouterr().out)}
        assert 'standard' in names

    def test_dispatches_list_via_alias(self, capsys):
        fake = make_manager()
        with patch.object(SandboxCLI, '_get_manager', return_value=fake), \
                patch.object(sys, 'argv', ['sandboxctl', 'ls']):
            assert main() == 0
        assert 'No active sandboxes' in capsys.readouterr().out

    def test_dispatches_kill(self):
        fake = make_manager()
        with patch.object(SandboxCLI, '_get_manager', return_value=fake), \
                patch.object(sys, 'argv', ['sandboxctl', 'kill', 'sb-1']):
            assert main() == 0
        bound = bind_to(SandboxManager.terminate_sandbox, fake.terminate_sandbox.call_args)
        assert bound.arguments['sandbox_id'] == 'sb-1'

    def test_dispatches_run(self, capsys):
        """The subparser dest must not collide with run's positional 'command'."""
        fake = make_manager()
        with patch.object(SandboxCLI, '_get_manager', return_value=fake), \
                patch.object(sys, 'argv', ['sandboxctl', '--no-color', 'run', '--', 'true']):
            assert main() == 0
        fake.run_sandboxed.assert_called_once()
        bound = bind_to(SandboxManager.run_sandboxed, fake.run_sandboxed.call_args)
        assert bound.arguments['command'] == ['true']
        assert 'hi' in capsys.readouterr().out

    def test_run_without_command_is_an_error(self, capsys):
        fake = make_manager()
        with patch.object(SandboxCLI, '_get_manager', return_value=fake), \
                patch.object(sys, 'argv', ['sandboxctl', 'run']):
            assert main() == 1
        fake.run_sandboxed.assert_not_called()
        assert 'E003' in capsys.readouterr().err
