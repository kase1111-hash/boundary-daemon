# Boundary Daemon API Contracts — v1

Versioned guarantees for integrators. If a contract is not listed here, it is not guaranteed.

---

## 1. Transport

| Property | Contract |
|---|---|
| Protocol | Unix domain socket, JSON over stream |
| Socket discovery | 1. `BOUNDARY_DAEMON_SOCKET` env var, 2. `/var/run/boundary-daemon/boundary.sock`, 3. `~/.agent-os/api/boundary.sock`, 4. `./api/boundary.sock` |
| Message framing | Single JSON object per request, single JSON object per response |
| Max message size | 64 KiB (65536 bytes) |
| Encoding | UTF-8 |

**Stability:** The 4-level socket discovery order will not change in v1.x releases. New levels may be appended.

---

## 2. Request Format

```json
{
  "command": "<string>",
  "params": { ... },
  "token": "<string, optional>"
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `command` | string | yes | One of the commands listed in section 4 |
| `params` | object | no | Command-specific parameters (defaults to `{}`) |
| `token` | string | no | API token prefixed with `bd_`. Required unless anonymous access is enabled. |

**Stability:** These three top-level fields will not change in v1.x.

---

## 3. Response Format

### Success

```json
{
  "success": true,
  "permitted": true,
  "reason": "Allowed in current mode",
  ...command-specific fields...
}
```

### Denial

```json
{
  "success": true,
  "permitted": false,
  "reason": "Mode OPEN does not meet minimum AIRGAP for TOP_SECRET"
}
```

### Error

```json
{
  "success": false,
  "error": "Human-readable error message",
  "auth_error": true
}
```

| Field | Type | Guaranteed | Notes |
|---|---|---|---|
| `success` | boolean | yes | `false` only for transport/auth errors, not policy denials |
| `permitted` | boolean | yes (for check commands) | Policy decision result |
| `reason` | string | yes | Human-readable explanation |
| `error` | string | on failure | Error description |
| `auth_error` | boolean | on auth failure | Present and `true` when token is invalid |

**Stability:** `success`, `permitted`, and `reason` are guaranteed present in their respective contexts for all v1.x releases. Additional fields may be added but will never be removed.

---

## 4. Commands

### 4.1 Policy Check Commands

#### `check_recall`

Check if memory recall is permitted in current mode.

| Param | Type | Required | Description |
|---|---|---|---|
| `memory_class` | int (0-5) | yes | Memory classification level |
| `memory_id` | string | no | Memory identifier for audit logging |

Response: `{ permitted, reason }`

**Fail-closed:** Unknown `memory_class` values result in `permitted: false`.

#### `check_tool`

Check if tool execution is permitted.

| Param | Type | Required | Description |
|---|---|---|---|
| `tool_name` | string | yes | Tool identifier |
| `requires_network` | boolean | no | Tool needs network access (default: false) |
| `requires_filesystem` | boolean | no | Tool needs filesystem access (default: false) |
| `requires_usb` | boolean | no | Tool needs USB access (default: false) |
| `context` | object | no | Additional context for audit logging |

Response: `{ permitted, reason }`

**Fail-closed:** Unknown tools with resource requirements are denied in restrictive modes.

#### `check_message`

Check message content for policy compliance.

| Param | Type | Required | Description |
|---|---|---|---|
| `content` | string | yes | Message content |
| `source` | string | no | Source identifier: `natlangchain`, `agent_os`, `unknown` |
| `context` | object | no | Additional context |

Response: `{ permitted, reason, result_type, violations, redacted_content }`

#### `check_natlangchain`

Check a NatLangChain blockchain entry.

| Param | Type | Required | Description |
|---|---|---|---|
| `author` | string | yes | Entry author |
| `intent` | string | yes | Intent description (prose) |
| `timestamp` | string | yes | ISO 8601 timestamp |
| `signature` | string | no | Cryptographic signature |
| `previous_hash` | string | no | Hash of previous entry |
| `metadata` | object | no | Additional metadata |

Response: `{ permitted, reason, result_type, violations }`

#### `check_agentos`

Check an Agent-OS inter-agent message.

| Param | Type | Required | Description |
|---|---|---|---|
| `sender_agent` | string | yes | Sending agent identifier |
| `recipient_agent` | string | yes | Receiving agent identifier |
| `content` | string | yes | Message content |
| `message_type` | string | no | `request`, `response`, `notification`, `command` |
| `authority_level` | int (0-5) | no | Authority level (default: 0) |
| `timestamp` | string | no | ISO 8601 timestamp (auto-generated if omitted) |
| `requires_consent` | boolean | no | Whether consent is required |
| `metadata` | object | no | Additional metadata |

Response: `{ permitted, reason, result_type, violations }`

### 4.2 Status Commands

#### `status`

Get daemon status. No parameters.

Response:
```json
{
  "success": true,
  "status": {
    "mode": "restricted",
    "online": true,
    "network_state": "online",
    "hardware_trust": "high",
    "lockdown_active": false,
    "tripwire_count": 0,
    "uptime_seconds": 3600.5
  }
}
```

#### `verify_log`

Verify event log integrity. No parameters.

Response: `{ success, valid, error }`

### 4.3 Mode Commands

#### `set_mode`

Request mode change (requires `SET_MODE` capability).

| Param | Type | Required | Description |
|---|---|---|---|
| `mode` | string | yes | Target mode: `open`, `restricted`, `trusted`, `airgap`, `coldroom` |
| `operator` | string | no | `human` or `system` (default: `human`) |
| `reason` | string | no | Reason for change |

Response: `{ success, message }`

**Constraint:** Cannot exit LOCKDOWN via `set_mode`. Use ceremony override instead.

### 4.4 Token Management Commands

#### `create_token`

Create a new API token (requires `MANAGE_TOKENS` capability).

| Param | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Human-readable name |
| `capabilities` | array | yes | Capability names or set names (`readonly`, `operator`, `admin`) |
| `expires_in_days` | int | no | Days until expiration (default: 365, null = never) |

#### `revoke_token`

Revoke a token (requires `MANAGE_TOKENS` capability).

| Param | Type | Required | Description |
|---|---|---|---|
| `token_id` | string | yes | Token ID (first 8 chars of hash) |

#### `list_tokens`

List tokens (requires `MANAGE_TOKENS` capability). Token hashes are never exposed.

---

## 5. Authentication

| Property | Contract |
|---|---|
| Token format | `bd_` prefix + 43 chars URL-safe base64 |
| Token storage | SHA-256 hash only; plaintext never persisted |
| Token validation | Constant-time comparison via `hmac.compare_digest` |
| Capability model | Capability-based; `ADMIN` implies all capabilities |
| Unknown commands | Denied (fail-closed) |

### Capability Matrix

| Capability | Commands |
|---|---|
| `STATUS` | `status` |
| `READ_EVENTS` | `get_events` |
| `VERIFY_LOG` | `verify_log` |
| `CHECK_RECALL` | `check_recall` |
| `CHECK_TOOL` | `check_tool` |
| `CHECK_MESSAGE` | `check_message`, `check_natlangchain`, `check_agentos` |
| `SET_MODE` | `set_mode` |
| `MANAGE_TOKENS` | `create_token`, `revoke_token`, `list_tokens`, `rate_limit_status` |
| `ADMIN` | All of the above |

### Predefined Capability Sets

| Set Name | Includes |
|---|---|
| `readonly` | STATUS, READ_EVENTS, VERIFY_LOG, CHECK_RECALL, CHECK_TOOL, CHECK_MESSAGE |
| `operator` | readonly + SET_MODE |
| `admin` | ADMIN (all) |

---

## 6. Rate Limiting

| Layer | Default | Window |
|---|---|---|
| Per-token | 100 requests | 60 seconds |
| Per-command | Varies (see below) | 60 seconds |
| Global | 1000 requests | 60 seconds |

### Per-Command Limits

| Command | Max/minute | Rationale |
|---|---|---|
| `check_recall` | 500 | Memory operations are frequent |
| `check_tool` | 300 | Tool calls are frequent |
| `check_message` | 200 | Content validation |
| `status` | 200 | Health checks |
| `set_mode` | 10 | Mode changes should be rare |
| `create_token` | 5 | Token creation is infrequent |

### Rate Limit Response Headers

Rate limit status is included in responses:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 45
X-RateLimit-Window: 60
```

**Stability:** Rate limit defaults may change between minor versions. The header format is stable.

---

## 7. Fail-Closed Guarantees

These are **hard invariants** — they hold regardless of daemon state:

| Scenario | Behavior |
|---|---|
| Daemon unreachable | Client returns `permitted: false` |
| Token invalid/missing | `success: false, auth_error: true` |
| Unknown command | `success: false, error: "Unknown command"` |
| Unknown memory class | `permitted: false` |
| Unknown request type | `permitted: false` (policy engine deny) |
| MessageChecker unavailable | All message checks return `permitted: false` |
| LOCKDOWN mode | All policy checks return `permitted: false` |
| Rate limit exceeded | `success: false` with retry-after information |

**Stability:** Fail-closed behavior will never be relaxed. New failure modes will always default to denial.

---

## 8. Latency Expectations

| Operation | Target | Notes |
|---|---|---|
| Policy check (local) | < 1 ms | No I/O, deterministic matrix lookup |
| Socket round-trip | < 5 ms | Unix domain socket, local only |
| Client timeout | 5 seconds | Default; configurable per-client |
| Client retry | 3 attempts | Exponential backoff: 0.5s, 1s, 2s |
| Log verification | < 100 ms | Scales with log size |

---

## 9. Versioning

| Property | Contract |
|---|---|
| Version scheme | Semantic versioning (major.minor.patch) |
| Breaking changes | Major version bump only |
| New fields in responses | May be added in minor versions |
| Field removal | Major version bump only |
| New commands | May be added in minor versions |
| Command removal | Major version bump only |

**Current version:** 1.0.0

---

## 10. Integration Quick Reference

### Python (shared client)

```python
from boundary_client import BoundaryClient

client = BoundaryClient()  # Auto-discovers socket
decision = client.check_recall(memory_class=3)
if decision.permitted:
    # proceed
```

### Python (Memory Vault)

```python
from boundary import RecallGate

gate = RecallGate()
if gate.can_recall(memory_class=3, memory_id="mem-001"):
    memory = vault.retrieve("mem-001")
```

### TypeScript (Agent-OS)

```typescript
import { AgentOSBoundaryIntegration } from './boundary';

const boundary = new AgentOSBoundaryIntegration();
if (await boundary.toolGate.canExecute('shell', { network: true })) {
    // proceed
}
```

### Decorator (Python)

```python
from boundary_client import boundary_protected

@boundary_protected(requires_network=True, memory_class=2)
def fetch_confidential_data():
    # Automatically denied if policy check fails
    ...
```
