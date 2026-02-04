# Integration Tests

This directory contains integration tests that validate the Boundary Daemon's interaction with real system resources.

## Test Suites

### Security Integration Tests (`test_security_integration.py`)
Tests the security policy enforcement across integrated repositories (Agent-OS, Memory Vault, etc.).

```bash
pytest tests/integration/test_security_integration.py -v
```

### Enforcement Integration Tests (`test_enforcement_integration.py`)
Tests kernel-level enforcement capabilities (network, USB, process sandboxing). **Requires Linux and root privileges.**

## Running Enforcement Tests

### Option 1: Docker (Recommended)

Build and run in an isolated container with full privileges:

```bash
# Build the test image
docker build -t boundary-daemon-tests -f tests/integration/Dockerfile .

# Run all enforcement tests
docker run --privileged --rm boundary-daemon-tests

# Run specific tests
docker run --privileged --rm boundary-daemon-tests \
    pytest tests/integration/test_enforcement_integration.py -v -k "network"

# Interactive debugging
docker run --privileged --rm -it boundary-daemon-tests bash
```

### Option 2: Local (Requires Root)

Run directly on a Linux system with root access:

```bash
# Install dependencies
pip install -r requirements.txt -r requirements-dev.txt

# Run with sudo
sudo pytest tests/integration/test_enforcement_integration.py -v
```

### Option 3: Skip Privileged Tests

Run only tests that don't require root:

```bash
pytest tests/integration/test_enforcement_integration.py -v -k "not requires_root"
```

## Test Categories

Tests are marked with decorators indicating their requirements:

| Decorator | Requirement |
|-----------|-------------|
| `@requires_root` | Root/sudo privileges |
| `@requires_linux` | Linux operating system |
| `@requires_iptables` | iptables available |
| `@pytest.mark.integration` | Full integration test |

## What Gets Tested

### Network Enforcement
- iptables rule creation/deletion
- IP blocking and unblocking
- Port blocking and unblocking
- Mode-based network restrictions

### USB Enforcement
- Device listing
- Device blocking via udev rules
- Policy-based USB access control

### Process Enforcement
- seccomp filter application
- Namespace isolation
- Process sandboxing

### Feature Detection
- Platform-appropriate feature availability
- Graceful degradation on unsupported platforms
- Clear error reporting

## CI/CD Integration

For CI systems that support Docker:

```yaml
# GitHub Actions example
enforcement-tests:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Build test image
      run: docker build -t bd-tests -f tests/integration/Dockerfile .
    - name: Run enforcement tests
      run: docker run --privileged --rm bd-tests
```

## Troubleshooting

### "Permission denied" errors
Enforcement tests require root. Use Docker or sudo.

### "iptables not found"
Install iptables: `apt install iptables`

### "seccomp not available"
Your kernel may not support seccomp. Check:
```bash
cat /proc/sys/kernel/seccomp/actions_avail
```

### Tests pass locally but fail in CI
CI environments may not support privileged operations. Use the Docker-based approach with `--privileged` flag.
