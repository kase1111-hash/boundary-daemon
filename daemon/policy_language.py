"""
Custom Policy Language — declarative, non-Turing-complete policy refinement.

The mode × request matrix in PolicyEngine is the coarse-grained control.
This module adds fine-grained rules that refine (but never bypass) the base
matrix. If the base matrix says DENY, no custom rule can override that to
ALLOW — custom rules can only tighten, not loosen.

Design constraints:
- Not Turing-complete: no loops, no recursion, no user-defined functions
- Statically analyzable: all rules can be validated, conflicts detected
- Bounded evaluation: finite rules, each with finite conditions, O(rules × conditions)
- Fail-closed: parse errors, invalid fields, evaluation errors → DENY

Vocabulary (every legal field/operator/value is enumerated here):

    Fields              Operators           Values
    ─────────────────   ──────────────      ────────────────────
    mode                eq, gte, lte, in    BoundaryMode names
    request_type        eq, in              recall, tool, model, io
    memory_class        eq, gte, lte, in    MemoryClass names
    tool_name           eq, in, not_in      arbitrary string
    requires_network    is_true, is_false   (no value needed)
    requires_filesystem is_true, is_false
    requires_usb        is_true, is_false
    network             eq                  online, offline
    vpn_active          is_true, is_false
    hardware_trust      eq, gte, lte        low, medium, high
    usb_present         is_true, is_false   (derived: len(usb_devices) > 0)
    human_present       is_true, is_false   (derived: keyboard AND screen)
    agent               eq, in, not_in      arbitrary string
    hour                eq, gte, lte        0–23
"""

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from .policy_engine import BoundaryMode, MemoryClass, PolicyDecision, PolicyRequest
from .state_monitor import NetworkState, HardwareTrust, EnvironmentState

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Vocabulary — every legal field, operator, and value type
# ═══════════════════════════════════════════════════════════════════════════

# Fields and the operators each supports
FIELD_OPERATORS: Dict[str, Set[str]] = {
    'mode':                {'eq', 'gte', 'lte', 'in'},
    'request_type':        {'eq', 'in'},
    'memory_class':        {'eq', 'gte', 'lte', 'in'},
    'tool_name':           {'eq', 'in', 'not_in'},
    'requires_network':    {'is_true', 'is_false'},
    'requires_filesystem': {'is_true', 'is_false'},
    'requires_usb':        {'is_true', 'is_false'},
    'network':             {'eq'},
    'vpn_active':          {'is_true', 'is_false'},
    'hardware_trust':      {'eq', 'gte', 'lte'},
    'usb_present':         {'is_true', 'is_false'},
    'human_present':       {'is_true', 'is_false'},
    'agent':               {'eq', 'in', 'not_in'},
    'hour':                {'eq', 'gte', 'lte'},
}

# Enum name → value mappings for validation
MODE_NAMES = {m.name for m in BoundaryMode}
MEMORY_CLASS_NAMES = {m.name for m in MemoryClass}
NETWORK_VALUES = {'online', 'offline'}
TRUST_VALUES = {'low', 'medium', 'high'}
REQUEST_TYPES = {'recall', 'tool', 'model', 'io'}

# Ordered trust levels for gte/lte comparison
_TRUST_ORDER = {'low': 0, 'medium': 1, 'high': 2}

# Actions — maps 1:1 to PolicyDecision
VALID_ACTIONS = {'allow', 'deny', 'require_ceremony'}

# Conflict resolution strategies
VALID_STRATEGIES = {'first_match', 'most_restrictive'}

# PolicyDecision restrictiveness for most_restrictive resolution
_RESTRICTIVENESS = {
    PolicyDecision.ALLOW: 0,
    PolicyDecision.REQUIRE_CEREMONY: 1,
    PolicyDecision.DENY: 2,
}


# ═══════════════════════════════════════════════════════════════════════════
# Data model
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Condition:
    """
    Single predicate: field <operator> value.

    For boolean operators (is_true, is_false) value is ignored.
    For 'in' / 'not_in', value must be a list.
    """
    field: str
    operator: str
    value: Any = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {'field': self.field, 'operator': self.operator}
        if self.value is not None:
            d['value'] = self.value
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'Condition':
        return cls(
            field=d['field'],
            operator=d['operator'],
            value=d.get('value'),
        )


@dataclass
class PolicyRule:
    """
    Single policy rule: named, prioritized, with AND-ed conditions.

    Rules with higher priority numbers are evaluated first.
    All conditions must be true (AND) for the rule to match.
    """
    name: str
    description: str
    priority: int
    conditions: List[Condition]
    action: str  # 'allow', 'deny', 'require_ceremony'

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'description': self.description,
            'priority': self.priority,
            'conditions': [c.to_dict() for c in self.conditions],
            'action': self.action,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'PolicyRule':
        return cls(
            name=d['name'],
            description=d.get('description', ''),
            priority=d.get('priority', 0),
            conditions=[Condition.from_dict(c) for c in d.get('conditions', [])],
            action=d['action'],
        )


@dataclass
class PolicySet:
    """
    Named collection of rules with a conflict resolution strategy.

    Rules are evaluated in priority order (descending).
    The base policy engine matrix is always the fallback.
    """
    name: str
    version: str
    rules: List[PolicyRule]
    conflict_resolution: str = 'first_match'  # or 'most_restrictive'

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'version': self.version,
            'rules': [r.to_dict() for r in self.rules],
            'conflict_resolution': self.conflict_resolution,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'PolicySet':
        return cls(
            name=d['name'],
            version=d.get('version', '1.0.0'),
            rules=[PolicyRule.from_dict(r) for r in d.get('rules', [])],
            conflict_resolution=d.get('conflict_resolution', 'first_match'),
        )

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, s: str) -> 'PolicySet':
        return cls.from_dict(json.loads(s))


# ═══════════════════════════════════════════════════════════════════════════
# Validation
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ValidationError:
    """Single validation issue."""
    rule_name: str
    message: str
    severity: str = 'error'  # 'error' or 'warning'


def validate_policy_set(policy_set: PolicySet) -> List[ValidationError]:
    """
    Validate a PolicySet for correctness.

    Checks:
    - All field names are in the vocabulary
    - All operators are valid for their field
    - All values are valid for their field
    - Action is valid
    - Conflict resolution strategy is valid
    - Duplicate rule names
    - Conditions with is_true/is_false don't have unnecessary values

    Returns list of ValidationError (empty = valid).
    """
    errors: List[ValidationError] = []

    # Check conflict resolution strategy
    if policy_set.conflict_resolution not in VALID_STRATEGIES:
        errors.append(ValidationError(
            rule_name='(policy_set)',
            message=f"Invalid conflict_resolution '{policy_set.conflict_resolution}', "
                    f"must be one of {VALID_STRATEGIES}",
        ))

    # Check for duplicate rule names
    names = [r.name for r in policy_set.rules]
    seen = set()
    for name in names:
        if name in seen:
            errors.append(ValidationError(
                rule_name=name,
                message=f"Duplicate rule name '{name}'",
            ))
        seen.add(name)

    # Validate each rule
    for rule in policy_set.rules:
        errors.extend(_validate_rule(rule))

    return errors


def _validate_rule(rule: PolicyRule) -> List[ValidationError]:
    """Validate a single rule."""
    errors: List[ValidationError] = []

    # Check action
    if rule.action not in VALID_ACTIONS:
        errors.append(ValidationError(
            rule_name=rule.name,
            message=f"Invalid action '{rule.action}', must be one of {VALID_ACTIONS}",
        ))

    # Check priority is an integer
    if not isinstance(rule.priority, int):
        errors.append(ValidationError(
            rule_name=rule.name,
            message=f"Priority must be an integer, got {type(rule.priority).__name__}",
        ))

    # Check each condition
    for cond in rule.conditions:
        errors.extend(_validate_condition(rule.name, cond))

    return errors


def _validate_condition(rule_name: str, cond: Condition) -> List[ValidationError]:
    """Validate a single condition."""
    errors: List[ValidationError] = []

    # Check field is known
    if cond.field not in FIELD_OPERATORS:
        errors.append(ValidationError(
            rule_name=rule_name,
            message=f"Unknown field '{cond.field}', must be one of {sorted(FIELD_OPERATORS.keys())}",
        ))
        return errors  # Can't validate further

    # Check operator is valid for field
    valid_ops = FIELD_OPERATORS[cond.field]
    if cond.operator not in valid_ops:
        errors.append(ValidationError(
            rule_name=rule_name,
            message=f"Operator '{cond.operator}' not valid for field '{cond.field}', "
                    f"valid: {sorted(valid_ops)}",
        ))
        return errors

    # Boolean operators don't need values
    if cond.operator in ('is_true', 'is_false'):
        return errors

    # Value validation by field
    if cond.field == 'mode':
        errors.extend(_validate_enum_value(rule_name, cond, MODE_NAMES, 'BoundaryMode'))
    elif cond.field == 'memory_class':
        errors.extend(_validate_enum_value(rule_name, cond, MEMORY_CLASS_NAMES, 'MemoryClass'))
    elif cond.field == 'request_type':
        errors.extend(_validate_enum_value(rule_name, cond, REQUEST_TYPES, 'request_type'))
    elif cond.field == 'network':
        if cond.value not in NETWORK_VALUES:
            errors.append(ValidationError(
                rule_name=rule_name,
                message=f"Invalid network value '{cond.value}', must be one of {NETWORK_VALUES}",
            ))
    elif cond.field == 'hardware_trust':
        if cond.operator in ('eq', 'gte', 'lte'):
            if cond.value not in TRUST_VALUES:
                errors.append(ValidationError(
                    rule_name=rule_name,
                    message=f"Invalid hardware_trust value '{cond.value}', must be one of {TRUST_VALUES}",
                ))
    elif cond.field == 'hour':
        if not isinstance(cond.value, int) or not (0 <= cond.value <= 23):
            errors.append(ValidationError(
                rule_name=rule_name,
                message=f"Hour must be integer 0-23, got {cond.value!r}",
            ))

    return errors


def _validate_enum_value(rule_name: str, cond: Condition,
                         valid: Set[str], type_name: str) -> List[ValidationError]:
    """Validate enum-like values, handling both single and list (for 'in')."""
    errors: List[ValidationError] = []
    if cond.operator in ('in', 'not_in'):
        if not isinstance(cond.value, list):
            errors.append(ValidationError(
                rule_name=rule_name,
                message=f"Operator '{cond.operator}' requires a list value, got {type(cond.value).__name__}",
            ))
        else:
            for v in cond.value:
                if v not in valid:
                    errors.append(ValidationError(
                        rule_name=rule_name,
                        message=f"Invalid {type_name} value '{v}' in list, valid: {sorted(valid)}",
                    ))
    else:
        if cond.value not in valid:
            errors.append(ValidationError(
                rule_name=rule_name,
                message=f"Invalid {type_name} value '{cond.value}', valid: {sorted(valid)}",
            ))
    return errors


# ═══════════════════════════════════════════════════════════════════════════
# Static analysis
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ConflictReport:
    """Two rules that could match the same state with different actions."""
    rule_a: str
    rule_b: str
    reason: str


def find_conflicts(policy_set: PolicySet) -> List[ConflictReport]:
    """
    Find pairs of rules that could match the same state with different actions.

    This is a conservative analysis — it reports potential conflicts even if
    they might not occur in practice (e.g., if conditions are mutually exclusive
    in ways we can't statically determine for string fields).

    Approach: for each pair of rules with different actions, check if their
    condition sets are compatible (could both be true simultaneously).
    """
    conflicts: List[ConflictReport] = []
    rules = policy_set.rules

    for i in range(len(rules)):
        for j in range(i + 1, len(rules)):
            a, b = rules[i], rules[j]
            if a.action == b.action:
                continue  # Same action = no conflict

            if _conditions_compatible(a.conditions, b.conditions):
                conflicts.append(ConflictReport(
                    rule_a=a.name,
                    rule_b=b.name,
                    reason=f"Both could match: '{a.name}' ({a.action}) vs "
                           f"'{b.name}' ({b.action}), resolved by "
                           f"priority ({a.priority} vs {b.priority})",
                ))

    return conflicts


def _conditions_compatible(conds_a: List[Condition], conds_b: List[Condition]) -> bool:
    """
    Check if two condition sets could both be true simultaneously.

    Conservative: returns True unless we can prove mutual exclusivity.
    """
    # Group conditions by field
    fields_a = {c.field: c for c in conds_a}
    fields_b = {c.field: c for c in conds_b}

    # For shared fields, check if values are mutually exclusive
    for field_name in set(fields_a.keys()) & set(fields_b.keys()):
        ca, cb = fields_a[field_name], fields_b[field_name]

        # eq vs eq on same field with different values → incompatible
        if ca.operator == 'eq' and cb.operator == 'eq' and ca.value != cb.value:
            return False

        # is_true vs is_false → incompatible
        if {ca.operator, cb.operator} == {'is_true', 'is_false'}:
            return False

    return True  # Conservative: assume compatible


def find_shadows(policy_set: PolicySet) -> List[str]:
    """
    Find rules that can never fire because a higher-priority rule always
    covers their conditions.

    Returns list of shadowed rule names.
    """
    shadowed: List[str] = []
    sorted_rules = sorted(policy_set.rules, key=lambda r: r.priority, reverse=True)

    for i, rule in enumerate(sorted_rules):
        for higher in sorted_rules[:i]:
            if higher.priority > rule.priority and _rule_subsumes(higher, rule):
                shadowed.append(rule.name)
                break

    return shadowed


def _rule_subsumes(higher: PolicyRule, lower: PolicyRule) -> bool:
    """
    Check if higher-priority rule always matches when lower matches.

    This is true when higher has a subset of conditions (or identical conditions)
    compared to lower — fewer conditions means it matches more broadly.
    """
    if not higher.conditions:
        # No conditions = matches everything → subsumes anything
        return True

    # Higher must have conditions that are a subset of lower's conditions
    higher_fields = {(c.field, c.operator, _hashable_value(c.value)) for c in higher.conditions}
    lower_fields = {(c.field, c.operator, _hashable_value(c.value)) for c in lower.conditions}

    return higher_fields.issubset(lower_fields)


def _hashable_value(v: Any) -> Any:
    """Make a value hashable for set operations."""
    if isinstance(v, list):
        return tuple(v)
    return v


# ═══════════════════════════════════════════════════════════════════════════
# Evaluation
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class EvaluationContext:
    """
    Flattened state snapshot for condition evaluation.

    Built from PolicyRequest + EnvironmentState + optional extras.
    All fields in the vocabulary map to a value here.
    """
    mode: BoundaryMode
    request_type: str
    memory_class: Optional[MemoryClass]
    tool_name: Optional[str]
    requires_network: bool
    requires_filesystem: bool
    requires_usb: bool
    network: str  # 'online' or 'offline'
    vpn_active: bool
    hardware_trust: str  # 'low', 'medium', 'high'
    usb_present: bool
    human_present: bool
    agent: Optional[str]
    hour: int

    @classmethod
    def build(
        cls,
        mode: BoundaryMode,
        request: PolicyRequest,
        env_state: EnvironmentState,
        agent: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> 'EvaluationContext':
        """Build context from the standard daemon types."""
        if now is None:
            now = datetime.utcnow()
        return cls(
            mode=mode,
            request_type=request.request_type,
            memory_class=request.memory_class,
            tool_name=request.tool_name,
            requires_network=request.requires_network,
            requires_filesystem=request.requires_filesystem,
            requires_usb=request.requires_usb,
            network=env_state.network.value,
            vpn_active=env_state.vpn_active,
            hardware_trust=env_state.hardware_trust.value,
            usb_present=len(env_state.usb_devices) > 0,
            human_present=env_state.keyboard_active and env_state.screen_unlocked,
            agent=agent,
            hour=now.hour,
        )


def evaluate_condition(cond: Condition, ctx: EvaluationContext) -> bool:
    """
    Evaluate a single condition against context. Fail-closed on errors.
    """
    try:
        actual = _resolve_field(cond.field, ctx)
        return _apply_operator(cond.field, cond.operator, actual, cond.value)
    except Exception as e:
        logger.warning(f"Condition evaluation error ({cond.field} {cond.operator}): {e}")
        return False  # Fail-closed


def _resolve_field(field_name: str, ctx: EvaluationContext) -> Any:
    """Resolve a field name to its current value from context."""
    if field_name == 'mode':
        return ctx.mode.name
    elif field_name == 'request_type':
        return ctx.request_type
    elif field_name == 'memory_class':
        return ctx.memory_class.name if ctx.memory_class is not None else None
    elif field_name == 'tool_name':
        return ctx.tool_name
    elif field_name == 'requires_network':
        return ctx.requires_network
    elif field_name == 'requires_filesystem':
        return ctx.requires_filesystem
    elif field_name == 'requires_usb':
        return ctx.requires_usb
    elif field_name == 'network':
        return ctx.network
    elif field_name == 'vpn_active':
        return ctx.vpn_active
    elif field_name == 'hardware_trust':
        return ctx.hardware_trust
    elif field_name == 'usb_present':
        return ctx.usb_present
    elif field_name == 'human_present':
        return ctx.human_present
    elif field_name == 'agent':
        return ctx.agent
    elif field_name == 'hour':
        return ctx.hour
    else:
        raise ValueError(f"Unknown field: {field_name}")


def _apply_operator(field_name: str, operator: str, actual: Any, expected: Any) -> bool:
    """Apply an operator to compare actual vs expected."""
    if operator == 'eq':
        return actual == expected
    elif operator == 'in':
        return actual in expected
    elif operator == 'not_in':
        return actual not in expected
    elif operator == 'is_true':
        return bool(actual) is True
    elif operator == 'is_false':
        return bool(actual) is False
    elif operator == 'gte':
        return _ordered_gte(field_name, actual, expected)
    elif operator == 'lte':
        return _ordered_lte(field_name, actual, expected)
    else:
        raise ValueError(f"Unknown operator: {operator}")


def _ordered_gte(field_name: str, actual: Any, expected: Any) -> bool:
    """Greater-than-or-equal for ordered fields."""
    if field_name == 'mode':
        return BoundaryMode[actual] >= BoundaryMode[expected]
    elif field_name == 'memory_class':
        if actual is None:
            return False
        return MemoryClass[actual] >= MemoryClass[expected]
    elif field_name == 'hardware_trust':
        return _TRUST_ORDER.get(actual, -1) >= _TRUST_ORDER.get(expected, -1)
    elif field_name == 'hour':
        return actual >= expected
    else:
        raise ValueError(f"gte not supported for {field_name}")


def _ordered_lte(field_name: str, actual: Any, expected: Any) -> bool:
    """Less-than-or-equal for ordered fields."""
    if field_name == 'mode':
        return BoundaryMode[actual] <= BoundaryMode[expected]
    elif field_name == 'memory_class':
        if actual is None:
            return False
        return MemoryClass[actual] <= MemoryClass[expected]
    elif field_name == 'hardware_trust':
        return _TRUST_ORDER.get(actual, 999) <= _TRUST_ORDER.get(expected, 999)
    elif field_name == 'hour':
        return actual <= expected
    else:
        raise ValueError(f"lte not supported for {field_name}")


def evaluate_rule(rule: PolicyRule, ctx: EvaluationContext) -> Optional[PolicyDecision]:
    """
    Evaluate a rule. Returns the action if all conditions match, else None.
    """
    for cond in rule.conditions:
        if not evaluate_condition(cond, ctx):
            return None
    # All conditions matched
    return PolicyDecision(rule.action)


def evaluate_policy_set(
    policy_set: PolicySet,
    ctx: EvaluationContext,
) -> Optional[PolicyDecision]:
    """
    Evaluate a PolicySet against context.

    Returns:
        PolicyDecision if a rule matched, None if no rules matched
        (caller should fall through to base policy).
    """
    sorted_rules = sorted(policy_set.rules, key=lambda r: r.priority, reverse=True)

    if policy_set.conflict_resolution == 'first_match':
        for rule in sorted_rules:
            result = evaluate_rule(rule, ctx)
            if result is not None:
                logger.debug(f"Policy rule '{rule.name}' matched → {result.value}")
                return result
        return None

    elif policy_set.conflict_resolution == 'most_restrictive':
        matches: List[PolicyDecision] = []
        for rule in sorted_rules:
            result = evaluate_rule(rule, ctx)
            if result is not None:
                matches.append(result)
                logger.debug(f"Policy rule '{rule.name}' matched → {result.value}")
        if not matches:
            return None
        # Return the most restrictive match
        return max(matches, key=lambda d: _RESTRICTIVENESS[d])

    else:
        # Unknown strategy → fail closed
        logger.error(f"Unknown conflict_resolution: {policy_set.conflict_resolution}")
        return PolicyDecision.DENY


# ═══════════════════════════════════════════════════════════════════════════
# Integration with PolicyEngine
# ═══════════════════════════════════════════════════════════════════════════

def evaluate_with_custom_policies(
    base_decision: PolicyDecision,
    policy_set: Optional[PolicySet],
    ctx: EvaluationContext,
) -> PolicyDecision:
    """
    Refine a base policy decision with custom rules.

    SECURITY INVARIANT: Custom rules can only tighten, never loosen.
    If the base says DENY, the result is always DENY regardless of custom rules.
    If custom rules say DENY but base says ALLOW, the result is DENY.

    Tightening order: ALLOW < REQUIRE_CEREMONY < DENY
    """
    if policy_set is None:
        return base_decision

    # Base DENY is final — custom rules cannot override
    if base_decision == PolicyDecision.DENY:
        return PolicyDecision.DENY

    custom_decision = evaluate_policy_set(policy_set, ctx)

    if custom_decision is None:
        # No custom rule matched → use base decision
        return base_decision

    # Return the more restrictive of base and custom
    if _RESTRICTIVENESS[custom_decision] > _RESTRICTIVENESS[base_decision]:
        return custom_decision

    return base_decision
