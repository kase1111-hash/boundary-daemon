# Contributing to Boundary Daemon

Thank you for your interest in contributing to Boundary Daemon (Agent Smith). This is a security-critical component, and we take contributions seriously.

## Security First

Before contributing, please understand that this project prioritizes security over convenience. All contributions must:

1. **Maintain fail-closed semantics** - Uncertainty must default to DENY
2. **Preserve immutable logging** - Never bypass or weaken audit trails
3. **Not introduce convenience features that weaken security**
4. **Include comprehensive tests**
5. **Pass security review**

## Documentation

Before diving in, familiarize yourself with the codebase:

| Document | Purpose |
|----------|---------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | System design and security model |
| [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md) | Practical guide for new contributors |
| [docs/MODULE_MAP.md](docs/MODULE_MAP.md) | Module organization and navigation |
| [SPEC.md](SPEC.md) | Formal specification |
| [ENFORCEMENT_MODEL.md](ENFORCEMENT_MODEL.md) | How enforcement works |

## Getting Started

### Prerequisites

- Python 3.9 or higher
- Git
- Understanding of security principles and threat modeling

### Development Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR-USERNAME/boundary-daemon-.git
   cd boundary-daemon
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```
4. Install in development mode:
   ```bash
   pip install -e .
   ```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=daemon --cov-report=html

# Run specific test file
pytest tests/test_policy_engine.py

# Run security-specific tests
pytest tests/test_security_stack_e2e.py
```

### Code Quality Checks

```bash
# Type checking
mypy daemon/

# Linting
ruff check daemon/

# Security scanning
bandit -r daemon/
```

## How to Contribute

### Reporting Bugs

- Check existing issues first to avoid duplicates
- Use the bug report template
- Include detailed reproduction steps
- Specify your environment (OS, Python version)
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)

### Suggesting Features

- Use the feature request template
- Explain the security implications
- Consider if the feature aligns with the project's fail-closed philosophy
- Features that introduce convenience at the cost of security will not be accepted

### Submitting Pull Requests

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**:
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation as needed

3. **Test thoroughly**:
   ```bash
   pytest
   mypy daemon/
   ruff check daemon/
   ```

4. **Commit with clear messages**:
   ```bash
   git commit -m "Add feature: brief description

   Detailed explanation of what this change does and why.
   Include any security considerations."
   ```

5. **Push and create PR**:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Fill out the PR template** completely

## Code Guidelines

### Style

- Follow PEP 8 with a line length of 100 characters
- Use type hints for all function signatures
- Use descriptive variable and function names
- Keep functions focused and small

### Security Requirements

- Never log sensitive data (passwords, keys, PII)
- Validate all inputs at trust boundaries
- Use cryptographic functions from `pynacl` or `cryptography` libraries
- Avoid shell injection vulnerabilities
- Handle errors without exposing internal details

### Documentation

- Add docstrings to all public functions and classes
- Update relevant markdown documentation
- Include usage examples for new features
- Document security implications

### Testing

- Write unit tests for all new code
- Include edge cases and error conditions
- Test security-sensitive code paths thoroughly
- Aim for high coverage on security-critical modules

## Review Process

1. **Automated checks** must pass (CI/CD pipeline)
2. **Code review** by at least one maintainer
3. **Security review** for changes affecting:
   - Authentication/authorization
   - Cryptography
   - Logging/audit
   - Policy engine
   - Tripwire system

## What We Accept

- Bug fixes with tests
- Security improvements
- Documentation improvements
- Performance improvements that don't compromise security
- New detection capabilities (YARA rules, Sigma rules, etc.)
- Platform support improvements

## What We Don't Accept

- Features that weaken security for convenience
- Changes that bypass fail-closed semantics
- Modifications to audit logging that reduce integrity
- Dependencies with known security vulnerabilities
- Machine learning-based detection (we use deterministic rules only)

## Communication

- Use GitHub Issues for bug reports and feature requests
- Use GitHub Discussions for questions and general discussion
- For security vulnerabilities, follow the process in [SECURITY.md](SECURITY.md)

## License

By contributing to Boundary Daemon, you agree that your contributions will be licensed under the GNU General Public License v3 (GPL-3.0).

## Recognition

Contributors will be recognized in release notes. Significant contributions may be acknowledged in the README.

---

Thank you for helping make AI systems more secure and trustworthy.

---

## Developer Guide


A practical guide for new contributors to the Boundary Daemon codebase.

## Quick Start (5 Minutes)

```bash
# Clone and setup
git clone https://github.com/YOUR-USERNAME/boundary-daemon.git
cd boundary-daemon
pip install -r requirements.txt -r requirements-dev.txt
pip install -e .

# Verify installation
python -c "from daemon import BoundaryDaemon; print('OK')"

# Run tests
pytest tests/ -v --tb=short

# Start the daemon (demo mode)
python -m daemon.tui.dashboard --matrix
```

## Understanding the Codebase

### Core Philosophy

1. **Fail-Closed**: When in doubt, DENY. Every ambiguous state defaults to the safest option.
2. **Immutable Audit**: Every security decision is logged with hash-chain integrity.
3. **Explicit Over Implicit**: No hidden behaviors. All policy decisions are traceable.

### The 4 Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                     boundary_daemon.py                       │
│                    (Main Orchestrator)                       │
└──────────┬────────────────┬────────────────┬───────────────┘
           │                │                │
     ┌─────▼─────┐    ┌─────▼─────┐    ┌─────▼─────┐
     │   State   │    │  Policy   │    │ Tripwire  │
     │  Monitor  │───▶│  Engine   │───▶│  System   │
     └───────────┘    └───────────┘    └───────────┘
           │                │                │
           └────────────────┼────────────────┘
                            ▼
                    ┌─────────────┐
                    │   Event     │
                    │   Logger    │
                    └─────────────┘
```

| Component | File | Purpose |
|-----------|------|---------|
| **State Monitor** | `state_monitor.py` | Senses environment (network, USB, processes) |
| **Policy Engine** | `policy_engine.py` | Evaluates requests against current mode |
| **Tripwire System** | `tripwires.py` | Detects violations, triggers lockdown |
| **Event Logger** | `event_logger.py` | Immutable hash-chain audit log |

### Boundary Modes

The daemon operates in one of 6 modes (strictest to most permissive):

```
LOCKDOWN → COLDROOM → AIRGAP → TRUSTED → RESTRICTED → OPEN
   ▲                                                      ▼
   └──────── Strictness increases ◄──────────────────────┘
```

| Mode | Network | USB | Memory Access | Use Case |
|------|---------|-----|---------------|----------|
| OPEN | Any | Any | Public only | Development |
| RESTRICTED | Any | Ceremony | Public/Internal | Normal operation |
| TRUSTED | VPN only | None | +Confidential | Secure work |
| AIRGAP | None | None | +Secret | High security |
| COLDROOM | None | None | +Crown Jewels | Maximum security |
| LOCKDOWN | None | None | None | Emergency |

## Directory Structure

```
daemon/
├── boundary_daemon.py      # Main orchestrator (3,800 lines) - START HERE
├── state_monitor.py        # Environment sensing
├── policy_engine.py        # Policy evaluation
├── tripwires.py            # Violation detection
├── event_logger.py         # Audit logging
├── constants.py            # All constants in one place
├── features.py             # Feature detection
│
├── auth/                   # Authentication & ceremonies
├── security/               # Security modules (23 files)
│   ├── prompt_injection.py # LLM attack detection
│   ├── antivirus.py        # Malware scanning
│   └── ...
├── enforcement/            # Kernel-level enforcement (Linux)
│   ├── network_enforcer.py # iptables integration
│   ├── usb_enforcer.py     # udev rules
│   └── process_enforcer.py # seccomp-bpf
├── tui/                    # Terminal dashboard
│   ├── dashboard.py        # Main TUI
│   └── ...                 # Visual components
└── [30+ other directories]
```

## Common Tasks

### 1. Adding a New Security Check

```python
# daemon/security/my_check.py
"""
My Security Check Module.

Detects [threat type] by [method].
"""
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class MySecurityChecker:
    """Checks for [threat]."""

    def __init__(self):
        self._enabled = True

    def check(self, input_data: str) -> Dict[str, Any]:
        """
        Check input for [threat].

        Args:
            input_data: The data to check

        Returns:
            Dict with 'safe' bool and 'reason' if unsafe
        """
        # Your detection logic here
        if self._is_suspicious(input_data):
            logger.warning(f"Detected [threat]: {input_data[:50]}...")
            return {'safe': False, 'reason': 'Suspicious pattern detected'}
        return {'safe': True}

    def _is_suspicious(self, data: str) -> bool:
        # Implementation
        return False
```

### 2. Adding a New Policy Rule

Edit `policy_engine.py`:

```python
def _check_my_new_rule(self, request: PolicyRequest, env: EnvironmentState) -> PolicyDecision:
    """Check my new rule."""
    if self._mode >= BoundaryMode.AIRGAP:
        if request.requires_my_feature:
            return PolicyDecision.DENY
    return PolicyDecision.ALLOW
```

### 3. Adding a New Event Type

Edit `event_logger.py`:

```python
class EventType(Enum):
    # ... existing types ...
    MY_NEW_EVENT = "my_new_event"
```

Then log it:

```python
self.event_logger.log_event(
    EventType.MY_NEW_EVENT,
    details="What happened",
    metadata={'key': 'value'}
)
```

### 4. Adding a New Enforcement Module

```python
# daemon/enforcement/my_enforcer.py
"""
My Enforcer Module.

Enforces [what] using [mechanism].
Requires: [root/specific privileges]
"""
import logging
import sys

logger = logging.getLogger(__name__)

IS_LINUX = sys.platform.startswith('linux')

class MyEnforcer:
    """Enforces [what]."""

    def __init__(self):
        self._enabled = IS_LINUX
        self._is_root = self._check_privileges()

        if not self._enabled:
            logger.info("MyEnforcer: Not on Linux, disabled")
        elif not self._is_root:
            logger.warning("MyEnforcer: Not root, enforcement limited")

    def _check_privileges(self) -> bool:
        """Check if we have required privileges."""
        if not IS_LINUX:
            return False
        import os
        return os.geteuid() == 0

    def enforce(self, target: str) -> bool:
        """Apply enforcement to target."""
        if not self._enabled or not self._is_root:
            return False
        # Implementation
        return True
```

## Testing Guidelines

### Unit Tests

```python
# tests/test_my_module.py
import pytest
from daemon.security.my_check import MySecurityChecker

class TestMySecurityChecker:
    def test_safe_input(self):
        checker = MySecurityChecker()
        result = checker.check("normal input")
        assert result['safe'] is True

    def test_malicious_input(self):
        checker = MySecurityChecker()
        result = checker.check("malicious pattern")
        assert result['safe'] is False
        assert 'reason' in result
```

### Running Specific Tests

```bash
# Run single test file
pytest tests/test_policy_engine.py -v

# Run single test
pytest tests/test_policy_engine.py::TestPolicyEngine::test_deny_in_lockdown -v

# Run with coverage
pytest tests/test_policy_engine.py --cov=daemon.policy_engine --cov-report=term-missing

# Run integration tests (requires Docker for privileged tests)
docker build -t bd-tests -f tests/integration/Dockerfile .
docker run --privileged --rm bd-tests
```

## Debugging Tips

### 1. Enable Debug Logging

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Or:

```bash
BOUNDARY_DEBUG=1 python -m daemon.boundary_daemon
```

### 2. Feature Availability Check

```bash
python -m daemon.features
```

This prints which features are available and why others are not.

### 3. TUI Connection Debug

If TUI isn't connecting to daemon:

```bash
cat ~/.boundary-daemon/logs/tui_connection_debug.log
```

### 4. Policy Decision Tracing

```python
# In policy_engine.py, add before return:
logger.debug(f"Policy decision: {request} + {env.mode} → {decision}")
```

## Key Files to Understand

| Priority | File | What It Does |
|----------|------|--------------|
| 1 | `boundary_daemon.py` | Main orchestrator - start here |
| 2 | `policy_engine.py` | Policy evaluation logic |
| 3 | `state_monitor.py` | Environment sensing |
| 4 | `event_logger.py` | Audit logging |
| 5 | `tripwires.py` | Violation detection |
| 6 | `constants.py` | All constants |
| 7 | `features.py` | Feature detection |

## Code Patterns

### 1. Optional Import Pattern

```python
try:
    from some_optional_module import Feature
    FEATURE_AVAILABLE = True
except ImportError:
    FEATURE_AVAILABLE = False
    Feature = None

# Usage
if FEATURE_AVAILABLE:
    feature = Feature()
```

### 2. Fail-Closed Pattern

```python
def check_permission(self, request) -> bool:
    """Always fail closed."""
    try:
        result = self._do_check(request)
        return result
    except Exception as e:
        logger.error(f"Permission check failed: {e}")
        return False  # DENY on error
```

### 3. Platform-Aware Pattern

```python
import sys

IS_WINDOWS = sys.platform == 'win32'
IS_LINUX = sys.platform.startswith('linux')

if IS_LINUX:
    # Linux-specific code
    pass
elif IS_WINDOWS:
    # Windows fallback
    pass
```

## Performance Benchmarking

Run the benchmark suite to measure component performance:

```bash
# Run all benchmarks (default: 10,000 iterations)
python -m benchmarks.run_benchmarks

# Quick run (1,000 iterations)
python -m benchmarks.run_benchmarks --quick

# Full run (50,000 iterations)
python -m benchmarks.run_benchmarks --full

# Run specific component
python -m benchmarks.run_benchmarks --component policy
python -m benchmarks.run_benchmarks --component eventlog
python -m benchmarks.run_benchmarks --component tripwire

# Export results as JSON
python -m benchmarks.run_benchmarks --json > results.json

# Save to file
python -m benchmarks.run_benchmarks --save results.json
```

### Performance Thresholds

| Benchmark | Max Latency | Min Throughput | Notes |
|-----------|-------------|----------------|-------|
| `policy_eval_simple` | 50 µs | 20,000 ops/sec | Core decision path |
| `policy_eval_complex` | 100 µs | 10,000 ops/sec | With network checks |
| `log_event_simple` | 5,000 µs | 200 ops/sec | Uses fsync() for durability |
| `check_violations_clean` | 100 µs | 10,000 ops/sec | Tripwire checks |

These thresholds ensure the daemon doesn't introduce noticeable latency to agent operations. Event logging is slower due to fsync() after each write, which ensures crash recovery.

## Getting Help

1. **Read the docs**: `ARCHITECTURE.md`, `SPEC.md`, `ENFORCEMENT_MODEL.md`
2. **Check existing code**: Find similar functionality and follow the pattern
3. **Run tests**: `pytest tests/ -v` shows how components are used
4. **Use feature detection**: `python -m daemon.features` shows what's available

## Checklist Before Submitting PR

- [ ] Tests pass: `pytest tests/`
- [ ] Type check passes: `mypy daemon/ --ignore-missing-imports`
- [ ] Lint passes: `ruff check daemon/`
- [ ] Security scan passes: `bandit -r daemon/`
- [ ] Documentation updated if needed
- [ ] No secrets/credentials in code
- [ ] Fail-closed semantics maintained
