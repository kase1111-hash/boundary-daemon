"""
Tests for the Custom Policy Language.

Covers:
- Condition evaluation: every field, every operator
- Rule matching: AND semantics, priority ordering
- PolicySet evaluation: first_match and most_restrictive strategies
- Validation: field names, operators, values, duplicate names
- Static analysis: conflict detection, shadow detection
- Security invariants: custom rules can only tighten, never loosen
- Serialization: JSON round-trip
- Integration: PolicyEngine.evaluate_policy with custom policies
- ROADMAP examples: conditional access, time-based, per-agent, escalation chains
"""

import json
import os
import sys
from datetime import datetime
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.policy_engine import (
    PolicyEngine, BoundaryMode, MemoryClass, PolicyDecision,
    PolicyRequest, Operator,
)
from daemon.state_monitor import (
    NetworkState, HardwareTrust, EnvironmentState, SpecialtyNetworkStatus,
)
from daemon.policy_language import (
    Condition, PolicyRule, PolicySet, ValidationError,
    EvaluationContext, evaluate_condition, evaluate_rule,
    evaluate_policy_set, evaluate_with_custom_policies,
    validate_policy_set, find_conflicts, find_shadows,
    FIELD_OPERATORS, VALID_ACTIONS,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _make_env_state(**overrides):
    """Build a minimal EnvironmentState for testing."""
    defaults = dict(
        timestamp=datetime.utcnow().isoformat() + "Z",
        network=NetworkState.OFFLINE,
        hardware_trust=HardwareTrust.HIGH,
        active_interfaces=[],
        interface_types={},
        has_internet=False,
        vpn_active=False,
        dns_available=False,
        specialty_networks=SpecialtyNetworkStatus(
            lora_devices=[], thread_devices=[], wimax_interfaces=[],
            irda_devices=[], ant_plus_devices=[], cellular_alerts=[],
        ),
        dns_security_alerts=[],
        arp_security_alerts=[],
        wifi_security_alerts=[],
        threat_intel_alerts=[],
        file_integrity_alerts=[],
        traffic_anomaly_alerts=[],
        process_security_alerts=[],
        usb_devices=set(),
        block_devices=set(),
        camera_available=False,
        mic_available=False,
        tpm_present=True,
        external_model_endpoints=[],
        suspicious_processes=[],
        shell_escapes_detected=0,
        keyboard_active=True,
        screen_unlocked=True,
        last_activity=None,
    )
    defaults.update(overrides)
    return EnvironmentState(**defaults)


def _make_ctx(mode=BoundaryMode.OPEN, request_type='recall',
              memory_class=MemoryClass.PUBLIC, tool_name=None,
              requires_network=False, requires_filesystem=False,
              requires_usb=False, network='offline', vpn_active=False,
              hardware_trust='high', usb_present=False,
              human_present=True, agent=None, hour=12):
    """Build an EvaluationContext directly for testing."""
    return EvaluationContext(
        mode=mode,
        request_type=request_type,
        memory_class=memory_class,
        tool_name=tool_name,
        requires_network=requires_network,
        requires_filesystem=requires_filesystem,
        requires_usb=requires_usb,
        network=network,
        vpn_active=vpn_active,
        hardware_trust=hardware_trust,
        usb_present=usb_present,
        human_present=human_present,
        agent=agent,
        hour=hour,
    )


def _make_rule(name='test', priority=10, conditions=None, action='deny'):
    """Shorthand to build a PolicyRule."""
    return PolicyRule(
        name=name,
        description=f"Test rule: {name}",
        priority=priority,
        conditions=conditions or [],
        action=action,
    )


def _make_policy_set(rules=None, strategy='first_match'):
    """Shorthand to build a PolicySet."""
    return PolicySet(
        name='test_policy',
        version='1.0.0',
        rules=rules or [],
        conflict_resolution=strategy,
    )


# ===========================================================================
# Condition Evaluation — every field × relevant operators
# ===========================================================================

class TestConditionEvaluation:
    # --- mode ---

    def test_mode_eq_match(self):
        ctx = _make_ctx(mode=BoundaryMode.AIRGAP)
        assert evaluate_condition(Condition('mode', 'eq', 'AIRGAP'), ctx) is True

    def test_mode_eq_no_match(self):
        ctx = _make_ctx(mode=BoundaryMode.OPEN)
        assert evaluate_condition(Condition('mode', 'eq', 'AIRGAP'), ctx) is False

    def test_mode_gte(self):
        ctx = _make_ctx(mode=BoundaryMode.TRUSTED)
        assert evaluate_condition(Condition('mode', 'gte', 'RESTRICTED'), ctx) is True
        assert evaluate_condition(Condition('mode', 'gte', 'TRUSTED'), ctx) is True
        assert evaluate_condition(Condition('mode', 'gte', 'AIRGAP'), ctx) is False

    def test_mode_lte(self):
        ctx = _make_ctx(mode=BoundaryMode.RESTRICTED)
        assert evaluate_condition(Condition('mode', 'lte', 'TRUSTED'), ctx) is True
        assert evaluate_condition(Condition('mode', 'lte', 'RESTRICTED'), ctx) is True
        assert evaluate_condition(Condition('mode', 'lte', 'OPEN'), ctx) is False

    def test_mode_in(self):
        ctx = _make_ctx(mode=BoundaryMode.AIRGAP)
        assert evaluate_condition(Condition('mode', 'in', ['AIRGAP', 'COLDROOM']), ctx) is True
        assert evaluate_condition(Condition('mode', 'in', ['OPEN', 'RESTRICTED']), ctx) is False

    # --- request_type ---

    def test_request_type_eq(self):
        ctx = _make_ctx(request_type='tool')
        assert evaluate_condition(Condition('request_type', 'eq', 'tool'), ctx) is True
        assert evaluate_condition(Condition('request_type', 'eq', 'recall'), ctx) is False

    def test_request_type_in(self):
        ctx = _make_ctx(request_type='model')
        assert evaluate_condition(Condition('request_type', 'in', ['model', 'tool']), ctx) is True

    # --- memory_class ---

    def test_memory_class_eq(self):
        ctx = _make_ctx(memory_class=MemoryClass.SECRET)
        assert evaluate_condition(Condition('memory_class', 'eq', 'SECRET'), ctx) is True

    def test_memory_class_gte(self):
        ctx = _make_ctx(memory_class=MemoryClass.TOP_SECRET)
        assert evaluate_condition(Condition('memory_class', 'gte', 'SECRET'), ctx) is True
        assert evaluate_condition(Condition('memory_class', 'gte', 'CROWN_JEWEL'), ctx) is False

    def test_memory_class_lte(self):
        ctx = _make_ctx(memory_class=MemoryClass.CONFIDENTIAL)
        assert evaluate_condition(Condition('memory_class', 'lte', 'SECRET'), ctx) is True
        assert evaluate_condition(Condition('memory_class', 'lte', 'INTERNAL'), ctx) is False

    def test_memory_class_none_gte_fails_closed(self):
        ctx = _make_ctx(memory_class=None)
        assert evaluate_condition(Condition('memory_class', 'gte', 'PUBLIC'), ctx) is False

    # --- tool_name ---

    def test_tool_name_eq(self):
        ctx = _make_ctx(tool_name='shell_execute')
        assert evaluate_condition(Condition('tool_name', 'eq', 'shell_execute'), ctx) is True

    def test_tool_name_in(self):
        ctx = _make_ctx(tool_name='curl')
        assert evaluate_condition(Condition('tool_name', 'in', ['curl', 'wget']), ctx) is True
        assert evaluate_condition(Condition('tool_name', 'in', ['ssh']), ctx) is False

    def test_tool_name_not_in(self):
        ctx = _make_ctx(tool_name='file_read')
        assert evaluate_condition(Condition('tool_name', 'not_in', ['curl', 'wget']), ctx) is True
        assert evaluate_condition(Condition('tool_name', 'not_in', ['file_read']), ctx) is False

    # --- boolean fields ---

    @pytest.mark.parametrize("field", [
        'requires_network', 'requires_filesystem', 'requires_usb',
        'vpn_active', 'usb_present', 'human_present',
    ])
    def test_boolean_is_true(self, field):
        ctx = _make_ctx(**{field: True})
        assert evaluate_condition(Condition(field, 'is_true'), ctx) is True
        assert evaluate_condition(Condition(field, 'is_false'), ctx) is False

    @pytest.mark.parametrize("field", [
        'requires_network', 'requires_filesystem', 'requires_usb',
        'vpn_active', 'usb_present', 'human_present',
    ])
    def test_boolean_is_false(self, field):
        ctx = _make_ctx(**{field: False})
        assert evaluate_condition(Condition(field, 'is_false'), ctx) is True
        assert evaluate_condition(Condition(field, 'is_true'), ctx) is False

    # --- network ---

    def test_network_eq(self):
        ctx = _make_ctx(network='online')
        assert evaluate_condition(Condition('network', 'eq', 'online'), ctx) is True
        assert evaluate_condition(Condition('network', 'eq', 'offline'), ctx) is False

    # --- hardware_trust ---

    def test_hardware_trust_eq(self):
        ctx = _make_ctx(hardware_trust='medium')
        assert evaluate_condition(Condition('hardware_trust', 'eq', 'medium'), ctx) is True

    def test_hardware_trust_gte(self):
        ctx = _make_ctx(hardware_trust='high')
        assert evaluate_condition(Condition('hardware_trust', 'gte', 'medium'), ctx) is True
        ctx = _make_ctx(hardware_trust='low')
        assert evaluate_condition(Condition('hardware_trust', 'gte', 'medium'), ctx) is False

    def test_hardware_trust_lte(self):
        ctx = _make_ctx(hardware_trust='low')
        assert evaluate_condition(Condition('hardware_trust', 'lte', 'medium'), ctx) is True
        ctx = _make_ctx(hardware_trust='high')
        assert evaluate_condition(Condition('hardware_trust', 'lte', 'medium'), ctx) is False

    # --- agent ---

    def test_agent_eq(self):
        ctx = _make_ctx(agent='planner-agent')
        assert evaluate_condition(Condition('agent', 'eq', 'planner-agent'), ctx) is True
        assert evaluate_condition(Condition('agent', 'eq', 'other'), ctx) is False

    def test_agent_in(self):
        ctx = _make_ctx(agent='executor')
        assert evaluate_condition(Condition('agent', 'in', ['executor', 'planner']), ctx) is True

    def test_agent_not_in(self):
        ctx = _make_ctx(agent='safe-agent')
        assert evaluate_condition(Condition('agent', 'not_in', ['rogue-agent']), ctx) is True

    # --- hour ---

    def test_hour_eq(self):
        ctx = _make_ctx(hour=14)
        assert evaluate_condition(Condition('hour', 'eq', 14), ctx) is True
        assert evaluate_condition(Condition('hour', 'eq', 15), ctx) is False

    def test_hour_gte(self):
        ctx = _make_ctx(hour=9)
        assert evaluate_condition(Condition('hour', 'gte', 9), ctx) is True
        assert evaluate_condition(Condition('hour', 'gte', 10), ctx) is False

    def test_hour_lte(self):
        ctx = _make_ctx(hour=17)
        assert evaluate_condition(Condition('hour', 'lte', 17), ctx) is True
        assert evaluate_condition(Condition('hour', 'lte', 16), ctx) is False

    # --- fail-closed ---

    def test_unknown_field_fails_closed(self):
        ctx = _make_ctx()
        assert evaluate_condition(Condition('nonexistent', 'eq', 'x'), ctx) is False


# ===========================================================================
# Rule Evaluation
# ===========================================================================

class TestRuleEvaluation:
    """Test AND semantics and rule matching."""

    def test_empty_conditions_always_matches(self):
        rule = _make_rule(conditions=[], action='deny')
        ctx = _make_ctx()
        assert evaluate_rule(rule, ctx) == PolicyDecision.DENY

    def test_single_matching_condition(self):
        rule = _make_rule(
            conditions=[Condition('mode', 'eq', 'AIRGAP')],
            action='deny',
        )
        ctx = _make_ctx(mode=BoundaryMode.AIRGAP)
        assert evaluate_rule(rule, ctx) == PolicyDecision.DENY

    def test_single_non_matching_condition(self):
        rule = _make_rule(
            conditions=[Condition('mode', 'eq', 'AIRGAP')],
            action='deny',
        )
        ctx = _make_ctx(mode=BoundaryMode.OPEN)
        assert evaluate_rule(rule, ctx) is None

    def test_and_semantics_all_must_match(self):
        """All conditions must be true (AND) for the rule to fire."""
        rule = _make_rule(conditions=[
            Condition('mode', 'gte', 'AIRGAP'),
            Condition('usb_present', 'is_false'),
            Condition('human_present', 'is_true'),
        ], action='allow')

        # All true
        ctx = _make_ctx(mode=BoundaryMode.AIRGAP, usb_present=False, human_present=True)
        assert evaluate_rule(rule, ctx) == PolicyDecision.ALLOW

        # One false
        ctx = _make_ctx(mode=BoundaryMode.AIRGAP, usb_present=True, human_present=True)
        assert evaluate_rule(rule, ctx) is None

    def test_action_mapping(self):
        """Actions map to PolicyDecision values."""
        for action in VALID_ACTIONS:
            rule = _make_rule(conditions=[], action=action)
            result = evaluate_rule(rule, _make_ctx())
            assert result == PolicyDecision(action)


# ===========================================================================
# PolicySet Evaluation
# ===========================================================================

class TestPolicySetEvaluation:
    def test_first_match_returns_highest_priority(self):
        ps = _make_policy_set(
            rules=[
                _make_rule('low', priority=1, conditions=[], action='allow'),
                _make_rule('high', priority=10, conditions=[], action='deny'),
            ],
            strategy='first_match',
        )
        result = evaluate_policy_set(ps, _make_ctx())
        assert result == PolicyDecision.DENY  # high priority wins

    def test_first_match_skips_non_matching(self):
        ps = _make_policy_set(
            rules=[
                _make_rule('narrow', priority=10,
                           conditions=[Condition('mode', 'eq', 'LOCKDOWN')],
                           action='deny'),
                _make_rule('broad', priority=5, conditions=[], action='allow'),
            ],
            strategy='first_match',
        )
        ctx = _make_ctx(mode=BoundaryMode.OPEN)
        result = evaluate_policy_set(ps, ctx)
        assert result == PolicyDecision.ALLOW  # narrow doesn't match, broad does

    def test_most_restrictive_picks_deny_over_allow(self):
        ps = _make_policy_set(
            rules=[
                _make_rule('permissive', priority=10, conditions=[], action='allow'),
                _make_rule('strict', priority=5, conditions=[], action='deny'),
            ],
            strategy='most_restrictive',
        )
        result = evaluate_policy_set(ps, _make_ctx())
        assert result == PolicyDecision.DENY

    def test_most_restrictive_picks_ceremony_over_allow(self):
        ps = _make_policy_set(
            rules=[
                _make_rule('a', priority=10, conditions=[], action='allow'),
                _make_rule('b', priority=5, conditions=[], action='require_ceremony'),
            ],
            strategy='most_restrictive',
        )
        result = evaluate_policy_set(ps, _make_ctx())
        assert result == PolicyDecision.REQUIRE_CEREMONY

    def test_no_matching_rules_returns_none(self):
        ps = _make_policy_set(
            rules=[
                _make_rule('impossible', priority=10,
                           conditions=[Condition('mode', 'eq', 'LOCKDOWN')],
                           action='deny'),
            ],
        )
        ctx = _make_ctx(mode=BoundaryMode.OPEN)
        assert evaluate_policy_set(ps, ctx) is None

    def test_empty_ruleset_returns_none(self):
        ps = _make_policy_set(rules=[])
        assert evaluate_policy_set(ps, _make_ctx()) is None

    def test_unknown_strategy_fails_closed(self):
        ps = _make_policy_set(rules=[_make_rule(conditions=[], action='allow')])
        ps.conflict_resolution = 'unknown_strategy'
        result = evaluate_policy_set(ps, _make_ctx())
        assert result == PolicyDecision.DENY


# ===========================================================================
# Security Invariant: custom rules can only tighten
# ===========================================================================

class TestTighteningInvariant:
    """
    SECURITY INVARIANT: evaluate_with_custom_policies can only make
    decisions more restrictive than the base, never less restrictive.
    """

    @pytest.mark.security
    def test_base_deny_cannot_be_overridden(self):
        """Custom 'allow' rule cannot override base DENY."""
        ps = _make_policy_set(rules=[_make_rule(conditions=[], action='allow')])
        ctx = _make_ctx()
        result = evaluate_with_custom_policies(PolicyDecision.DENY, ps, ctx)
        assert result == PolicyDecision.DENY

    @pytest.mark.security
    def test_base_ceremony_cannot_be_loosened(self):
        """Custom 'allow' rule cannot loosen base REQUIRE_CEREMONY."""
        ps = _make_policy_set(rules=[_make_rule(conditions=[], action='allow')])
        ctx = _make_ctx()
        result = evaluate_with_custom_policies(PolicyDecision.REQUIRE_CEREMONY, ps, ctx)
        assert result == PolicyDecision.REQUIRE_CEREMONY

    @pytest.mark.security
    def test_custom_deny_tightens_base_allow(self):
        """Custom 'deny' can tighten base ALLOW to DENY."""
        ps = _make_policy_set(rules=[_make_rule(conditions=[], action='deny')])
        ctx = _make_ctx()
        result = evaluate_with_custom_policies(PolicyDecision.ALLOW, ps, ctx)
        assert result == PolicyDecision.DENY

    @pytest.mark.security
    def test_custom_ceremony_tightens_base_allow(self):
        """Custom 'require_ceremony' can tighten base ALLOW."""
        ps = _make_policy_set(rules=[
            _make_rule(conditions=[], action='require_ceremony'),
        ])
        ctx = _make_ctx()
        result = evaluate_with_custom_policies(PolicyDecision.ALLOW, ps, ctx)
        assert result == PolicyDecision.REQUIRE_CEREMONY

    @pytest.mark.security
    def test_no_policy_set_returns_base(self):
        """None custom policies → base decision unchanged."""
        result = evaluate_with_custom_policies(PolicyDecision.ALLOW, None, _make_ctx())
        assert result == PolicyDecision.ALLOW

    @pytest.mark.security
    def test_no_matching_rule_returns_base(self):
        """No custom rule matches → base decision unchanged."""
        ps = _make_policy_set(rules=[
            _make_rule(conditions=[Condition('mode', 'eq', 'LOCKDOWN')], action='deny'),
        ])
        ctx = _make_ctx(mode=BoundaryMode.OPEN)
        result = evaluate_with_custom_policies(PolicyDecision.ALLOW, ps, ctx)
        assert result == PolicyDecision.ALLOW

    @pytest.mark.security
    @pytest.mark.parametrize("base,custom,expected", [
        (PolicyDecision.ALLOW,            'deny',              PolicyDecision.DENY),
        (PolicyDecision.ALLOW,            'require_ceremony',  PolicyDecision.REQUIRE_CEREMONY),
        (PolicyDecision.ALLOW,            'allow',             PolicyDecision.ALLOW),
        (PolicyDecision.REQUIRE_CEREMONY, 'deny',              PolicyDecision.DENY),
        (PolicyDecision.REQUIRE_CEREMONY, 'require_ceremony',  PolicyDecision.REQUIRE_CEREMONY),
        (PolicyDecision.REQUIRE_CEREMONY, 'allow',             PolicyDecision.REQUIRE_CEREMONY),
        (PolicyDecision.DENY,             'deny',              PolicyDecision.DENY),
        (PolicyDecision.DENY,             'require_ceremony',  PolicyDecision.DENY),
        (PolicyDecision.DENY,             'allow',             PolicyDecision.DENY),
    ], ids=lambda x: x if isinstance(x, str) else x.value)
    def test_tightening_truth_table(self, base, custom, expected):
        """SECURITY: exhaustive truth table for base × custom → result."""
        ps = _make_policy_set(rules=[_make_rule(conditions=[], action=custom)])
        ctx = _make_ctx()
        result = evaluate_with_custom_policies(base, ps, ctx)
        assert result == expected, (
            f"SECURITY INVARIANT VIOLATED: base={base.value}, custom={custom}, "
            f"expected={expected.value}, got={result.value}"
        )


# ===========================================================================
# Validation
# ===========================================================================

class TestValidation:
    def test_valid_policy_set_no_errors(self):
        ps = _make_policy_set(rules=[
            _make_rule('r1', conditions=[
                Condition('mode', 'gte', 'RESTRICTED'),
                Condition('memory_class', 'eq', 'SECRET'),
            ], action='deny'),
        ])
        assert validate_policy_set(ps) == []

    def test_unknown_field_rejected(self):
        ps = _make_policy_set(rules=[
            _make_rule(conditions=[Condition('nonexistent', 'eq', 'x')]),
        ])
        errors = validate_policy_set(ps)
        assert any('Unknown field' in e.message for e in errors)

    def test_invalid_operator_rejected(self):
        ps = _make_policy_set(rules=[
            _make_rule(conditions=[Condition('mode', 'like', 'OPEN')]),
        ])
        errors = validate_policy_set(ps)
        assert any('not valid for field' in e.message for e in errors)

    def test_invalid_mode_value_rejected(self):
        ps = _make_policy_set(rules=[
            _make_rule(conditions=[Condition('mode', 'eq', 'FANTASY')]),
        ])
        errors = validate_policy_set(ps)
        assert any('Invalid BoundaryMode' in e.message for e in errors)

    def test_invalid_action_rejected(self):
        ps = _make_policy_set(rules=[
            _make_rule(conditions=[], action='maybe'),
        ])
        errors = validate_policy_set(ps)
        assert any('Invalid action' in e.message for e in errors)

    def test_invalid_strategy_rejected(self):
        ps = _make_policy_set(strategy='random')
        errors = validate_policy_set(ps)
        assert any('conflict_resolution' in e.message for e in errors)

    def test_duplicate_rule_names_rejected(self):
        ps = _make_policy_set(rules=[
            _make_rule('same_name', action='deny'),
            _make_rule('same_name', action='allow'),
        ])
        errors = validate_policy_set(ps)
        assert any('Duplicate rule name' in e.message for e in errors)

    def test_invalid_hour_rejected(self):
        ps = _make_policy_set(rules=[
            _make_rule(conditions=[Condition('hour', 'eq', 25)]),
        ])
        errors = validate_policy_set(ps)
        assert any('Hour must be' in e.message for e in errors)

    def test_in_operator_requires_list(self):
        ps = _make_policy_set(rules=[
            _make_rule(conditions=[Condition('mode', 'in', 'OPEN')]),
        ])
        errors = validate_policy_set(ps)
        assert any('requires a list' in e.message for e in errors)

    def test_invalid_network_value_rejected(self):
        ps = _make_policy_set(rules=[
            _make_rule(conditions=[Condition('network', 'eq', 'maybe')]),
        ])
        errors = validate_policy_set(ps)
        assert any('Invalid network' in e.message for e in errors)

    def test_invalid_trust_value_rejected(self):
        ps = _make_policy_set(rules=[
            _make_rule(conditions=[Condition('hardware_trust', 'eq', 'ultra')]),
        ])
        errors = validate_policy_set(ps)
        assert any('Invalid hardware_trust' in e.message for e in errors)


# ===========================================================================
# Static Analysis
# ===========================================================================

class TestStaticAnalysis:
    def test_find_conflicts_different_actions(self):
        ps = _make_policy_set(rules=[
            _make_rule('a', priority=10, conditions=[], action='allow'),
            _make_rule('b', priority=5, conditions=[], action='deny'),
        ])
        conflicts = find_conflicts(ps)
        assert len(conflicts) == 1
        assert conflicts[0].rule_a == 'a'
        assert conflicts[0].rule_b == 'b'

    def test_no_conflicts_same_actions(self):
        ps = _make_policy_set(rules=[
            _make_rule('a', conditions=[], action='deny'),
            _make_rule('b', conditions=[], action='deny'),
        ])
        assert find_conflicts(ps) == []

    def test_no_conflicts_mutually_exclusive_mode(self):
        ps = _make_policy_set(rules=[
            _make_rule('a', conditions=[Condition('mode', 'eq', 'OPEN')], action='allow'),
            _make_rule('b', conditions=[Condition('mode', 'eq', 'AIRGAP')], action='deny'),
        ])
        assert find_conflicts(ps) == []

    def test_no_conflicts_mutually_exclusive_bool(self):
        ps = _make_policy_set(rules=[
            _make_rule('a', conditions=[Condition('vpn_active', 'is_true')], action='allow'),
            _make_rule('b', conditions=[Condition('vpn_active', 'is_false')], action='deny'),
        ])
        assert find_conflicts(ps) == []

    def test_find_shadow_unconditional_hides_conditional(self):
        ps = _make_policy_set(rules=[
            _make_rule('catch_all', priority=10, conditions=[], action='deny'),
            _make_rule('specific', priority=5,
                       conditions=[Condition('mode', 'eq', 'OPEN')],
                       action='allow'),
        ])
        shadows = find_shadows(ps)
        assert 'specific' in shadows

    def test_no_shadow_when_different_conditions(self):
        ps = _make_policy_set(rules=[
            _make_rule('a', priority=10,
                       conditions=[Condition('mode', 'eq', 'OPEN')],
                       action='deny'),
            _make_rule('b', priority=5,
                       conditions=[Condition('mode', 'eq', 'AIRGAP')],
                       action='allow'),
        ])
        assert find_shadows(ps) == []


# ===========================================================================
# Serialization
# ===========================================================================

class TestSerialization:
    def test_json_round_trip(self):
        ps = _make_policy_set(rules=[
            PolicyRule(
                name='business_hours',
                description='CROWN_JEWEL only during business hours',
                priority=100,
                conditions=[
                    Condition('memory_class', 'eq', 'CROWN_JEWEL'),
                    Condition('hour', 'gte', 9),
                    Condition('hour', 'lte', 17),
                    Condition('human_present', 'is_true'),
                ],
                action='require_ceremony',
            ),
        ])
        json_str = ps.to_json()
        ps2 = PolicySet.from_json(json_str)
        assert ps2.name == ps.name
        assert ps2.version == ps.version
        assert len(ps2.rules) == 1
        assert ps2.rules[0].name == 'business_hours'
        assert len(ps2.rules[0].conditions) == 4
        assert ps2.rules[0].action == 'require_ceremony'

    def test_condition_dict_round_trip(self):
        c = Condition('mode', 'in', ['AIRGAP', 'COLDROOM'])
        d = c.to_dict()
        c2 = Condition.from_dict(d)
        assert c2.field == c.field
        assert c2.operator == c.operator
        assert c2.value == c.value

    def test_boolean_condition_omits_value(self):
        c = Condition('vpn_active', 'is_true')
        d = c.to_dict()
        assert 'value' not in d


# ===========================================================================
# EvaluationContext.build
# ===========================================================================

class TestEvaluationContextBuild:
    def test_build_from_standard_types(self):
        env = _make_env_state(
            network=NetworkState.ONLINE,
            vpn_active=True,
            hardware_trust=HardwareTrust.LOW,
            usb_devices={'usb-stick-001'},
            keyboard_active=False,
            screen_unlocked=True,
        )
        request = PolicyRequest(
            request_type='tool',
            tool_name='shell',
            requires_network=True,
            requires_filesystem=True,
        )
        ctx = EvaluationContext.build(
            BoundaryMode.TRUSTED, request, env,
            agent='test-agent',
            now=datetime(2025, 6, 15, 14, 30),
        )
        assert ctx.mode == BoundaryMode.TRUSTED
        assert ctx.request_type == 'tool'
        assert ctx.tool_name == 'shell'
        assert ctx.requires_network is True
        assert ctx.network == 'online'
        assert ctx.vpn_active is True
        assert ctx.hardware_trust == 'low'
        assert ctx.usb_present is True
        assert ctx.human_present is False  # keyboard_active=False
        assert ctx.agent == 'test-agent'
        assert ctx.hour == 14


# ===========================================================================
# PolicyEngine Integration
# ===========================================================================

class TestPolicyEngineIntegration:
    def _make_engine_with_policy(self, mode, rules, strategy='first_match'):
        engine = PolicyEngine(initial_mode=mode)
        ps = _make_policy_set(rules=rules, strategy=strategy)
        success, msg = engine.load_custom_policies(ps)
        assert success, msg
        return engine

    def test_load_valid_policy(self):
        engine = PolicyEngine()
        ps = _make_policy_set(rules=[
            _make_rule(conditions=[Condition('mode', 'eq', 'OPEN')], action='allow'),
        ])
        success, msg = engine.load_custom_policies(ps)
        assert success is True
        assert engine.get_custom_policies() is ps

    def test_load_invalid_policy_rejected(self):
        engine = PolicyEngine()
        ps = _make_policy_set(rules=[
            _make_rule(conditions=[Condition('bad_field', 'eq', 'x')], action='deny'),
        ])
        success, msg = engine.load_custom_policies(ps)
        assert success is False
        assert engine.get_custom_policies() is None

    def test_clear_custom_policies(self):
        engine = PolicyEngine()
        ps = _make_policy_set(rules=[])
        engine.load_custom_policies(ps)
        engine.clear_custom_policies()
        assert engine.get_custom_policies() is None

    def test_custom_policy_tightens_recall(self):
        """Custom rule denies SECRET recall even though base would allow."""
        engine = self._make_engine_with_policy(
            BoundaryMode.TRUSTED,
            rules=[PolicyRule(
                name='no_secret_without_human',
                description='Deny SECRET recall without human',
                priority=10,
                conditions=[
                    Condition('memory_class', 'eq', 'SECRET'),
                    Condition('human_present', 'is_false'),
                ],
                action='deny',
            )],
        )
        env = _make_env_state(
            keyboard_active=False,
            screen_unlocked=False,
        )
        request = PolicyRequest(request_type='recall', memory_class=MemoryClass.SECRET)
        # Base: TRUSTED >= TRUSTED → ALLOW, custom: no human → DENY
        decision = engine.evaluate_policy(request, env)
        assert decision == PolicyDecision.DENY

    def test_custom_policy_does_not_loosen(self):
        """Custom allow rule cannot loosen a base DENY."""
        engine = self._make_engine_with_policy(
            BoundaryMode.OPEN,
            rules=[_make_rule(conditions=[], action='allow')],
        )
        env = _make_env_state()
        # OPEN mode + TOP_SECRET recall → base DENY (mode too low)
        request = PolicyRequest(request_type='recall', memory_class=MemoryClass.TOP_SECRET)
        decision = engine.evaluate_policy(request, env)
        assert decision == PolicyDecision.DENY

    @pytest.mark.security
    def test_lockdown_ignores_custom_policies(self):
        """LOCKDOWN denies everything regardless of custom rules."""
        engine = self._make_engine_with_policy(
            BoundaryMode.LOCKDOWN,
            rules=[_make_rule(conditions=[], action='allow')],
        )
        env = _make_env_state()
        request = PolicyRequest(request_type='recall', memory_class=MemoryClass.PUBLIC)
        assert engine.evaluate_policy(request, env) == PolicyDecision.DENY

    def test_per_agent_policy(self):
        """Per-agent rule: agent X denied tool access."""
        engine = self._make_engine_with_policy(
            BoundaryMode.OPEN,
            rules=[PolicyRule(
                name='block_rogue_agent',
                description='Block rogue-agent from all tools',
                priority=100,
                conditions=[
                    Condition('request_type', 'eq', 'tool'),
                    Condition('agent', 'eq', 'rogue-agent'),
                ],
                action='deny',
            )],
        )
        env = _make_env_state()
        request = PolicyRequest(request_type='tool', tool_name='anything')

        # rogue-agent → denied
        decision = engine.evaluate_policy(request, env, agent='rogue-agent')
        assert decision == PolicyDecision.DENY

        # safe-agent → allowed (custom rule doesn't match)
        decision = engine.evaluate_policy(request, env, agent='safe-agent')
        assert decision == PolicyDecision.ALLOW

    def test_time_based_policy(self):
        """Time-based rule: CROWN_JEWEL recall only during business hours."""
        engine = self._make_engine_with_policy(
            BoundaryMode.COLDROOM,
            rules=[PolicyRule(
                name='crown_jewel_business_hours',
                description='Deny CROWN_JEWEL outside 9-17',
                priority=50,
                conditions=[
                    Condition('memory_class', 'eq', 'CROWN_JEWEL'),
                    Condition('hour', 'lte', 8),  # before 9am
                ],
                action='deny',
            )],
        )
        env = _make_env_state()
        request = PolicyRequest(request_type='recall', memory_class=MemoryClass.CROWN_JEWEL)

        # Override the time in EvaluationContext via the integration path
        # We test this at the policy_language level directly since the engine
        # uses datetime.utcnow() internally
        from daemon.policy_language import EvaluationContext, evaluate_with_custom_policies
        base = PolicyDecision.ALLOW  # COLDROOM >= COLDROOM for CROWN_JEWEL

        # At 3am → deny (hour <= 8)
        ctx = EvaluationContext.build(
            BoundaryMode.COLDROOM, request, env,
            now=datetime(2025, 6, 15, 3, 0),
        )
        result = evaluate_with_custom_policies(base, engine.get_custom_policies(), ctx)
        assert result == PolicyDecision.DENY

        # At 14:00 → allow (hour > 8, rule doesn't match)
        ctx = EvaluationContext.build(
            BoundaryMode.COLDROOM, request, env,
            now=datetime(2025, 6, 15, 14, 0),
        )
        result = evaluate_with_custom_policies(base, engine.get_custom_policies(), ctx)
        assert result == PolicyDecision.ALLOW

    def test_cleanup_clears_custom_policies(self):
        engine = PolicyEngine()
        ps = _make_policy_set(rules=[])
        engine.load_custom_policies(ps)
        engine.cleanup()
        assert engine.get_custom_policies() is None

    def test_existing_tests_unaffected_without_custom_policies(self):
        """PolicyEngine without custom policies behaves identically to before."""
        engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)
        env = _make_env_state()
        request = PolicyRequest(request_type='recall', memory_class=MemoryClass.PUBLIC)
        assert engine.evaluate_policy(request, env) == PolicyDecision.ALLOW
        assert engine.get_custom_policies() is None


# ===========================================================================
# ROADMAP Examples — verifying the four use cases from the roadmap
# ===========================================================================

class TestRoadmapExamples:
    """
    Verify the exact examples from ROADMAP.md §2:
    1. Conditional access based on environment signal combinations
    2. Time-based policies
    3. Per-agent policies
    4. Escalation chains
    5. Policy composition
    """

    def test_conditional_access_combination(self):
        """
        'Allow SECRET recall only when offline AND no USB devices AND
         human presence confirmed'
        """
        ps = _make_policy_set(rules=[
            PolicyRule(
                name='secret_strict',
                description='SECRET only with offline + no USB + human',
                priority=100,
                conditions=[
                    Condition('memory_class', 'gte', 'SECRET'),
                    Condition('network', 'eq', 'online'),
                ],
                action='deny',
            ),
            PolicyRule(
                name='secret_no_usb',
                description='SECRET denied with USB present',
                priority=99,
                conditions=[
                    Condition('memory_class', 'gte', 'SECRET'),
                    Condition('usb_present', 'is_true'),
                ],
                action='deny',
            ),
            PolicyRule(
                name='secret_needs_human',
                description='SECRET denied without human',
                priority=98,
                conditions=[
                    Condition('memory_class', 'gte', 'SECRET'),
                    Condition('human_present', 'is_false'),
                ],
                action='deny',
            ),
        ])

        base = PolicyDecision.ALLOW

        # All conditions met → no custom rule fires → ALLOW
        ctx = _make_ctx(
            memory_class=MemoryClass.SECRET,
            network='offline', usb_present=False, human_present=True,
        )
        assert evaluate_with_custom_policies(base, ps, ctx) == PolicyDecision.ALLOW

        # Online → DENY
        ctx = _make_ctx(
            memory_class=MemoryClass.SECRET,
            network='online', usb_present=False, human_present=True,
        )
        assert evaluate_with_custom_policies(base, ps, ctx) == PolicyDecision.DENY

        # USB present → DENY
        ctx = _make_ctx(
            memory_class=MemoryClass.SECRET,
            network='offline', usb_present=True, human_present=True,
        )
        assert evaluate_with_custom_policies(base, ps, ctx) == PolicyDecision.DENY

        # No human → DENY
        ctx = _make_ctx(
            memory_class=MemoryClass.SECRET,
            network='offline', usb_present=False, human_present=False,
        )
        assert evaluate_with_custom_policies(base, ps, ctx) == PolicyDecision.DENY

    def test_time_based_crown_jewel(self):
        """'CROWN_JEWEL access only during business hours with ceremony'"""
        ps = _make_policy_set(rules=[
            PolicyRule(
                name='crown_jewel_after_hours',
                description='Deny CROWN_JEWEL before 9am',
                priority=100,
                conditions=[
                    Condition('memory_class', 'eq', 'CROWN_JEWEL'),
                    Condition('hour', 'lte', 8),
                ],
                action='deny',
            ),
            PolicyRule(
                name='crown_jewel_evening',
                description='Deny CROWN_JEWEL after 5pm',
                priority=100,
                conditions=[
                    Condition('memory_class', 'eq', 'CROWN_JEWEL'),
                    Condition('hour', 'gte', 18),
                ],
                action='deny',
            ),
            PolicyRule(
                name='crown_jewel_ceremony',
                description='CROWN_JEWEL requires ceremony during hours',
                priority=50,
                conditions=[
                    Condition('memory_class', 'eq', 'CROWN_JEWEL'),
                ],
                action='require_ceremony',
            ),
        ])
        base = PolicyDecision.ALLOW

        # 3am → DENY
        ctx = _make_ctx(memory_class=MemoryClass.CROWN_JEWEL, hour=3)
        assert evaluate_with_custom_policies(base, ps, ctx) == PolicyDecision.DENY

        # 10am → REQUIRE_CEREMONY
        ctx = _make_ctx(memory_class=MemoryClass.CROWN_JEWEL, hour=10)
        assert evaluate_with_custom_policies(base, ps, ctx) == PolicyDecision.REQUIRE_CEREMONY

        # 20:00 → DENY
        ctx = _make_ctx(memory_class=MemoryClass.CROWN_JEWEL, hour=20)
        assert evaluate_with_custom_policies(base, ps, ctx) == PolicyDecision.DENY

        # PUBLIC at 3am → ALLOW (rules don't match PUBLIC)
        ctx = _make_ctx(memory_class=MemoryClass.PUBLIC, hour=3)
        assert evaluate_with_custom_policies(base, ps, ctx) == PolicyDecision.ALLOW

    def test_per_agent_policies(self):
        """'Agent X can use network tools, agent Y cannot regardless of mode'"""
        ps = _make_policy_set(rules=[
            PolicyRule(
                name='block_agent_y_network',
                description='Agent Y cannot use network tools',
                priority=100,
                conditions=[
                    Condition('agent', 'eq', 'agent-y'),
                    Condition('requires_network', 'is_true'),
                ],
                action='deny',
            ),
        ])
        base = PolicyDecision.ALLOW

        # Agent X + network → ALLOW (rule doesn't match)
        ctx = _make_ctx(agent='agent-x', requires_network=True)
        assert evaluate_with_custom_policies(base, ps, ctx) == PolicyDecision.ALLOW

        # Agent Y + network → DENY
        ctx = _make_ctx(agent='agent-y', requires_network=True)
        assert evaluate_with_custom_policies(base, ps, ctx) == PolicyDecision.DENY

        # Agent Y + no network → ALLOW (requires_network is false)
        ctx = _make_ctx(agent='agent-y', requires_network=False)
        assert evaluate_with_custom_policies(base, ps, ctx) == PolicyDecision.ALLOW

    def test_escalation_chain(self):
        """
        'Deny, then offer ceremony, then require multi-party approval'
        Modeled as: low-trust → DENY, medium → CEREMONY, high → ALLOW
        """
        ps = _make_policy_set(rules=[
            PolicyRule(
                name='deny_low_trust',
                description='Deny when hardware trust is low',
                priority=100,
                conditions=[
                    Condition('hardware_trust', 'eq', 'low'),
                ],
                action='deny',
            ),
            PolicyRule(
                name='ceremony_medium_trust',
                description='Ceremony when hardware trust is medium',
                priority=90,
                conditions=[
                    Condition('hardware_trust', 'eq', 'medium'),
                ],
                action='require_ceremony',
            ),
        ])
        base = PolicyDecision.ALLOW

        # Low trust → DENY
        ctx = _make_ctx(hardware_trust='low')
        assert evaluate_with_custom_policies(base, ps, ctx) == PolicyDecision.DENY

        # Medium trust → CEREMONY
        ctx = _make_ctx(hardware_trust='medium')
        assert evaluate_with_custom_policies(base, ps, ctx) == PolicyDecision.REQUIRE_CEREMONY

        # High trust → ALLOW (no rule matches)
        ctx = _make_ctx(hardware_trust='high')
        assert evaluate_with_custom_policies(base, ps, ctx) == PolicyDecision.ALLOW

    def test_policy_composition_most_restrictive(self):
        """
        'Combining base policies with overrides without silent conflicts'
        Using most_restrictive strategy.
        """
        ps = _make_policy_set(
            rules=[
                PolicyRule(
                    name='allow_public',
                    description='Always allow PUBLIC',
                    priority=10,
                    conditions=[Condition('memory_class', 'eq', 'PUBLIC')],
                    action='allow',
                ),
                PolicyRule(
                    name='deny_no_vpn',
                    description='Deny without VPN',
                    priority=5,
                    conditions=[Condition('vpn_active', 'is_false')],
                    action='deny',
                ),
            ],
            strategy='most_restrictive',
        )
        base = PolicyDecision.ALLOW

        # PUBLIC + no VPN → both rules match, most_restrictive = DENY
        ctx = _make_ctx(memory_class=MemoryClass.PUBLIC, vpn_active=False)
        assert evaluate_with_custom_policies(base, ps, ctx) == PolicyDecision.DENY

        # PUBLIC + VPN → only allow_public matches → ALLOW
        ctx = _make_ctx(memory_class=MemoryClass.PUBLIC, vpn_active=True)
        assert evaluate_with_custom_policies(base, ps, ctx) == PolicyDecision.ALLOW
