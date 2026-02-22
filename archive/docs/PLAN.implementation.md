# Implementation Plan: Fix All Security Audit Findings

## Overview

This plan addresses all 30+ findings from `AGENTIC_SECURITY_AUDIT.md` across 12 files.
Changes are grouped into 18 discrete steps ordered by priority (P0 first).

---

## P0 - Critical: Prevent Autonomous Agent Hierarchy Formation

### Step 1: Remove AGENT_DELEGATE from AGENT_SUPERVISE delegatable set

**File:** `daemon/security/agent_attestation.py`
**Lines:** 247-265

Remove `AgentCapability.AGENT_DELEGATE` from the `AGENT_SUPERVISE` entry in `DELEGATION_RULES`. This prevents supervisors from creating unbounded delegation chains.

Replace the `DELEGATION_RULES` dict with:
```python
DELEGATION_RULES: Dict[AgentCapability, Set[AgentCapability]] = {
    AgentCapability.AGENT_DELEGATE: {
        AgentCapability.FILE_READ,
        AgentCapability.NETWORK_LOCAL,
        AgentCapability.TOOL_INVOKE,
    },
    AgentCapability.AGENT_SUPERVISE: {
        AgentCapability.FILE_READ,
        AgentCapability.FILE_WRITE,
        AgentCapability.NETWORK_OUTBOUND,
        AgentCapability.NETWORK_LOCAL,
        AgentCapability.TOOL_INVOKE,
        AgentCapability.TOOL_CHAIN,
        # SECURITY: AGENT_DELEGATE intentionally excluded to prevent
        # autonomous hierarchy formation (Audit Finding 3.5.1)
    },
    AgentCapability.SYSTEM_ADMIN: {
        # SECURITY: Explicit capability enumeration instead of blanket grant
        # to prevent single-point-of-compromise (Audit Finding 3.5.2)
        AgentCapability.FILE_READ,
        AgentCapability.FILE_WRITE,
        AgentCapability.NETWORK_OUTBOUND,
        AgentCapability.NETWORK_LOCAL,
        AgentCapability.TOOL_INVOKE,
        AgentCapability.TOOL_CHAIN,
        AgentCapability.AGENT_SUPERVISE,
    },
}
```

### Step 2: Add human ceremony requirement for AGENT_DELEGATE delegation

**File:** `daemon/security/agent_attestation.py`
**Lines:** 441-458 (inside `issue_token`)

After the chain depth check, add a gate that requires ceremony approval when delegating `AGENT_DELEGATE` capability:

```python
        if parent_token_id:
            parent_token = self._tokens.get(parent_token_id)
            if not parent_token:
                logger.error(f"Parent token not found: {parent_token_id}")
                return None

            # Check chain depth
            chain_depth = self._get_chain_depth(parent_token_id)
            if chain_depth >= self.MAX_CHAIN_DEPTH:
                logger.error(f"Maximum delegation chain depth exceeded: {chain_depth}")
                return None

            # SECURITY (Audit 3.5.1): Block AGENT_DELEGATE in delegated tokens
            # Delegation of delegation authority requires human ceremony approval
            if capabilities and AgentCapability.AGENT_DELEGATE in capabilities:
                ceremony_approved = (constraints or {}).get('ceremony_approved_delegation', False)
                if not ceremony_approved:
                    logger.error(
                        f"AGENT_DELEGATE capability cannot be delegated without "
                        f"human ceremony approval (constraint: ceremony_approved_delegation=True)"
                    )
                    return None

            # Delegated capabilities must be subset of parent's delegatable capabilities
            parent_identity = self._identities.get(parent_token.agent_id)
            if parent_identity:
                delegatable = self._get_delegatable_capabilities(parent_identity)
                token_capabilities = token_capabilities & delegatable
```

### Step 3: Reduce MAX_CHAIN_DEPTH from 5 to 3

**File:** `daemon/security/agent_attestation.py`
**Line:** 244

Change: `MAX_CHAIN_DEPTH = 5` -> `MAX_CHAIN_DEPTH = 3`

---

## P0 - Critical: Add nonce replay detection

### Step 4: Add nonce tracking to attestation system

**File:** `daemon/security/agent_attestation.py`

In `__init__` (line ~290), add:
```python
self._used_nonces: Dict[str, datetime] = {}  # nonce -> first_seen
self._nonce_window = timedelta(hours=2)  # Reject nonces reused within window
```

In `verify_token` (after line ~593 where nonce is accessed), add nonce uniqueness check:
```python
        # SECURITY (Audit 3.2.2): Replay detection via nonce uniqueness
        if token_obj.nonce in self._used_nonces:
            return AttestationResult(
                status=AttestationStatus.INVALID_SIGNATURE,
                agent_identity=None,
                token=token_obj,
                verified_capabilities=set(),
                trust_level=TrustLevel.UNTRUSTED,
                chain_depth=0,
                verification_time=now,
                details={"error": "Token nonce already used (replay detected)"},
            )
        # Record nonce and prune expired entries
        self._used_nonces[token_obj.nonce] = now
        self._prune_expired_nonces(now)
```

Add helper method:
```python
    def _prune_expired_nonces(self, now: datetime) -> None:
        """Remove expired nonces outside the replay detection window."""
        cutoff = now - self._nonce_window
        expired = [n for n, t in self._used_nonces.items() if t < cutoff]
        for n in expired:
            del self._used_nonces[n]
```

---

## P1 - High Priority: Make attestation mandatory

### Step 5: Require attestation system for authority >= 2

**File:** `daemon/messages/message_checker.py`
**Lines:** 443-466

Change the attestation check so that when NO attestation system is configured, messages with `authority_level >= 2` are always rejected:

```python
        # SECURITY (Audit 2.1.2): Attestation is MANDATORY for authority >= 2
        attestation_token = message.metadata.get('attestation_token')
        if message.authority_level >= 2:
            if not self._attestation_system:
                violations.append(
                    f"No attestation system configured. Authority level "
                    f"{message.authority_level} messages REQUIRE cryptographic "
                    f"identity verification (attestation system is mandatory)"
                )
            elif attestation_token:
                result = self._attestation_system.verify_token(attestation_token)
                if not result.is_valid:
                    violations.append(
                        f"Agent attestation failed for sender '{message.sender_agent}': "
                        f"{result.status.value}. Authority level >= 2 requires "
                        f"cryptographic identity verification"
                    )
                elif result.agent_identity and result.agent_identity.agent_name != message.sender_agent:
                    violations.append(
                        f"Attestation token agent '{result.agent_identity.agent_name}' "
                        f"does not match sender '{message.sender_agent}' - "
                        f"possible identity spoofing"
                    )
            else:
                violations.append(
                    f"No attestation token provided for authority level "
                    f"{message.authority_level}. Agent identity verification "
                    f"required for authority >= 2 (anti-spoofing)"
                )
```

### Step 6: Default source_trust to "untrusted"

**File:** `daemon/messages/message_checker.py`
**Line:** 56

Change: `source_trust: str = "unknown"` -> `source_trust: str = "untrusted"`

---

## P1 - High Priority: Constitutional credential rule

### Step 7: Add NO_CREDENTIAL_TRANSMISSION policy constant

**File:** `daemon/messages/message_checker.py`

Add a class-level constant to `MessageChecker` (around line 110):
```python
    # SECURITY (Audit 2.3.1): Constitutional rule - credentials must never be transmitted
    CREDENTIAL_TRANSMISSION_PATTERNS = [
        r'(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*\S{8,}',
        r'(?:Bearer|Basic)\s+[A-Za-z0-9+/=_-]{20,}',
        r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
        r'AKIA[0-9A-Z]{16}',  # AWS access key
        r'ghp_[0-9a-zA-Z]{36}',  # GitHub token
        r'sk-[0-9a-zA-Z]{32,}',  # OpenAI key
    ]
```

Add credential scanning in the check method (after destructive action check, ~line 481):
```python
        # SECURITY (Audit 2.3.1): Constitutional NO_CREDENTIAL_TRANSMISSION rule
        for pattern in self.CREDENTIAL_TRANSMISSION_PATTERNS:
            if re.search(pattern, message.content):
                violations.append(
                    f"CONSTITUTIONAL VIOLATION: Credential pattern detected in message content. "
                    f"Agents must NEVER transmit credentials between agents. "
                    f"Recommend immediate LOCKDOWN investigation."
                )
                break
```

---

## P1 - High Priority: Fix silent privilege degradation

### Step 8: Add fail-closed enforcement check

**File:** `daemon/enforcement/network_enforcer.py`
**Lines:** 135-144

Replace the warning-only behavior with a mode-aware fail-closed check:
```python
        if self._backend == FirewallBackend.NONE:
            if IS_WINDOWS:
                logger.info("Network enforcement via iptables/nftables not available on Windows")
            else:
                logger.warning("No firewall backend available. Network enforcement disabled.")
        elif not self._has_root:
            if IS_WINDOWS:
                logger.warning("Not running as administrator. Network enforcement requires admin privileges.")
            else:
                logger.warning("Not running as root. Network enforcement requires CAP_NET_ADMIN.")

        # SECURITY (Audit 1.2.2): Fail-closed for high-security modes
        self._enforcement_degraded = (self._backend == FirewallBackend.NONE or not self._has_root)

    def check_enforcement_capability(self, mode: str) -> Tuple[bool, str]:
        """
        Check if enforcement is available for the requested mode.
        Modes >= TRUSTED require actual enforcement capability.

        Returns:
            (is_capable, error_message)
        """
        HIGH_SECURITY_MODES = {"TRUSTED", "AIRGAP", "COLDROOM", "LOCKDOWN"}
        if mode in HIGH_SECURITY_MODES and self._enforcement_degraded:
            return (False, f"Mode {mode} requires kernel-level network enforcement "
                          f"but enforcement is unavailable (root={self._has_root}, "
                          f"backend={self._backend}). Refusing to operate in "
                          f"monitoring-only mode for high-security modes.")
        return (True, "")
```

### Step 9: Same fail-closed check for USB enforcer

**File:** `daemon/enforcement/usb_enforcer.py`
**Lines:** 124-141

Add the same `_enforcement_degraded` flag and `check_enforcement_capability` method with the same logic (adapted for USB/udev context).

---

## P2 - Medium Priority: Pin dependencies to exact versions

### Step 10: Pin requirements.txt

**File:** `requirements.txt`

Replace with exact versions:
```
# Boundary Daemon Dependencies
# SECURITY (Audit 3.3.1): Exact version pins to prevent supply chain attacks

# System monitoring
psutil==5.9.8

# Cryptography (for signed event logger and config encryption)
cffi==1.17.1
pynacl==1.5.0
cryptography==44.0.0

# Detection engines
yara-python==4.5.1

# YAML parsing (optional, for Sigma rule support)
PyYAML==6.0.2

# No other dependencies required
# Minimal attack surface by design
```

---

## P2 - Medium Priority: Add secret scanner to CI

### Step 11: Add detect-secrets to CI pipeline

**File:** `.github/workflows/ci.yml`

Add a new step after the Bandit scanner step (after line 66):
```yaml
      - name: Scan for hardcoded secrets
        run: |
          pip install detect-secrets
          detect-secrets scan --all-files --exclude-files '\.git/.*' --exclude-files 'archive/.*' > .secrets-report.json
          python -c "
          import json, sys
          with open('.secrets-report.json') as f:
              data = json.load(f)
          results = data.get('results', {})
          total = sum(len(v) for v in results.values())
          if total > 0:
              print(f'ERROR: {total} potential secrets detected in {len(results)} files:')
              for f, secrets in results.items():
                  for s in secrets:
                      print(f'  {f}:{s[\"line_number\"]} - {s[\"type\"]}')
              sys.exit(1)
          print('No secrets detected.')
          "
```

---

## P2 - Medium Priority: Add reasoning chains to events

### Step 12: Extend BoundaryEvent with reasoning_chain

**File:** `daemon/event_logger.py`
**Lines:** 67-105 (BoundaryEvent dataclass)

Add `reasoning_chain` field:
```python
@dataclass
class BoundaryEvent:
    """A single boundary event in the log"""
    event_id: str
    timestamp: str
    event_type: EventType
    details: str
    metadata: Dict
    hash_chain: str  # Hash of previous event
    reasoning_chain: Optional[Dict] = None  # SECURITY (Audit 3.1.1): Decision reasoning

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        d = {
            'event_id': self.event_id,
            'timestamp': self.timestamp,
            'event_type': self.event_type.value,
            'details': self.details,
            'metadata': self.metadata,
            'hash_chain': self.hash_chain
        }
        if self.reasoning_chain:
            d['reasoning_chain'] = self.reasoning_chain
        return d
```

Update `log_event` to accept optional reasoning:
```python
    def log_event(self, event_type: EventType, details: str,
                  metadata: Optional[Dict] = None,
                  reasoning_chain: Optional[Dict] = None) -> BoundaryEvent:
```

And pass it through to BoundaryEvent construction.

---

## P2 - Medium Priority: Secure socket paths

### Step 13: Add peer credential verification to API socket

**File:** `api/boundary_api.py`
**Lines:** 207-227

After socket creation and accept, add peer credential check on Linux:
```python
                    conn, _ = self._socket.accept()
                    # SECURITY (Audit A.1): Verify connecting client UID
                    if HAS_UNIX_SOCKETS and not IS_WINDOWS:
                        try:
                            import struct
                            SO_PEERCRED = 17  # Linux-specific
                            cred = conn.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize('3i'))
                            pid, uid, gid = struct.unpack('3i', cred)
                            allowed_uids = {0, os.getuid()}  # root and daemon user
                            if uid not in allowed_uids:
                                logger.warning(f"Rejected connection from unauthorized UID {uid} (PID {pid})")
                                conn.close()
                                continue
                        except (OSError, struct.error) as e:
                            logger.debug(f"Peer credential check unavailable: {e}")
```

---

## P2 - Medium Priority: Add per-module capability declarations

### Step 14: Extend ModuleHash with capabilities

**File:** `daemon/integrity/code_signer.py`
**Lines:** 90-115

Add capabilities field:
```python
@dataclass
class ModuleHash:
    """Hash information for a single module."""
    path: str                    # Relative path from daemon root
    sha256: str                  # SHA-256 hash (hex)
    size: int                    # File size in bytes
    modified: str                # Last modified timestamp (ISO format)
    capabilities: Optional[List[str]] = None  # SECURITY (Audit 2.4.1): Module capability declarations

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        d = {
            'path': self.path,
            'sha256': self.sha256,
            'size': self.size,
            'modified': self.modified,
        }
        if self.capabilities is not None:
            d['capabilities'] = self.capabilities
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ModuleHash':
        """Create from dictionary."""
        return cls(
            path=data['path'],
            sha256=data['sha256'],
            size=data['size'],
            modified=data['modified'],
            capabilities=data.get('capabilities'),
        )
```

---

## P2 - Medium Priority: Dedicated daemon service user

### Step 15: Update systemd service to use dedicated user

**File:** `systemd/boundary-daemon.service`
**Lines:** 40-42

Replace:
```ini
# Run as dedicated service user with required capabilities only
# Create user: useradd -r -s /usr/sbin/nologin boundary-daemon
User=boundary-daemon
Group=boundary-daemon
```

Add capability bounding:
```ini
# SECURITY (Audit 1.2.1): Minimal capability set
AmbientCapabilities=CAP_NET_ADMIN CAP_KILL CAP_DAC_OVERRIDE CAP_CHOWN
CapabilityBoundingSet=CAP_NET_ADMIN CAP_KILL CAP_DAC_OVERRIDE CAP_CHOWN CAP_SYS_PTRACE
NoNewPrivileges=true
```

Note: Remove `CAP_SYS_ADMIN` unless strictly required for specific enforcement actions. If cgroups or namespaces require it, document the specific reason.

---

## P3 - Low Priority / Hardening

### Step 16: Replace documentation placeholder secrets

**File:** `SPEC.md`
**Line:** ~1795

Replace `auth_token = "boundary_secure_token"` with `auth_token = "<YOUR_GENERATED_TOKEN_HERE>"`

**File:** `daemon/identity/ldap_mapper.py`
**Lines:** 115, 426

Replace `bind_password="secret"` with `bind_password="<LDAP_BIND_PASSWORD>"`

### Step 17: Replace /tmp usage in cluster demo

**File:** `cluster_demo.py`
**Lines:** ~41, ~168

Replace `/tmp/boundary-cluster` with:
```python
import tempfile
_cluster_dir = tempfile.mkdtemp(prefix='boundary-cluster-')
```
And ensure cleanup on exit.

### Step 18: Review and document Bandit exclusions

**File:** `.github/workflows/ci.yml`
**Line:** 66

Add inline comments explaining each skip:
```yaml
      - name: Run Bandit security scanner
        run: |
          # B101: assert used in tests (not security-critical paths)
          # B404: subprocess import (required for enforcement modules)
          # B603: subprocess call without shell=True (intentional, args are validated)
          # B607: partial executable path (tools located via shutil.which)
          bandit -r daemon/ -ll --skip B101,B404,B603,B607
```

---

## Files Modified Summary

| # | File | Steps | Priority |
|---|------|-------|----------|
| 1 | `daemon/security/agent_attestation.py` | 1, 2, 3, 4 | P0 |
| 2 | `daemon/messages/message_checker.py` | 5, 6, 7 | P1 |
| 3 | `daemon/enforcement/network_enforcer.py` | 8 | P1 |
| 4 | `daemon/enforcement/usb_enforcer.py` | 9 | P1 |
| 5 | `requirements.txt` | 10 | P2 |
| 6 | `.github/workflows/ci.yml` | 11, 18 | P2 |
| 7 | `daemon/event_logger.py` | 12 | P2 |
| 8 | `api/boundary_api.py` | 13 | P2 |
| 9 | `daemon/integrity/code_signer.py` | 14 | P2 |
| 10 | `systemd/boundary-daemon.service` | 15 | P2 |
| 11 | `SPEC.md` | 16 | P3 |
| 12 | `daemon/identity/ldap_mapper.py` | 16 | P3 |
| 13 | `cluster_demo.py` | 17 | P3 |

---

## Testing Strategy

After all changes:
1. Run existing test suite: `pytest tests/ -v`
2. Verify delegation blocking works (new unit test for Step 2)
3. Verify attestation mandatory check rejects unattested authority >= 2 messages
4. Verify `source_trust` default change doesn't break existing tests
5. Verify BoundaryEvent backwards compatibility with `reasoning_chain=None` default
6. Verify ModuleHash backwards compatibility with `capabilities=None` default
7. Verify CI pipeline additions work locally before pushing
