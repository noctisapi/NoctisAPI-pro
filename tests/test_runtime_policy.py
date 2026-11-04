from app.catalog.builtin.loader import build_default_registry
from app.instance_config.models import (
    EndpointConfig,
    InstanceConfig,
    MutationConfig,
    ResponseRule,
    ResponseRuleAction,
    ResponseRuleMatch,
)
from app.runtime.builder import build_effective_runtime_config
from app.runtime.policy import resolve_runtime_request_policy


def _runtime(instance: InstanceConfig):
    return build_effective_runtime_config(instance, build_default_registry())


def test_runtime_policy_applies_endpoint_rule_and_mutation():
    runtime = _runtime(
        InstanceConfig(
            base_template_id="ecommerce",
            mutation_config=MutationConfig(policy="daily", intensity=2),
            response_rules=[
                ResponseRule(
                    id="rule_users",
                    match=ResponseRuleMatch(endpoint_id="users_list", method="GET"),
                    action=ResponseRuleAction(richness_delta=-1, extra_latency_ms=120, force_status=429),
                )
            ],
        )
    )
    endpoint = runtime.get_endpoint("users_list")
    policy = resolve_runtime_request_policy(
        runtime,
        endpoint=endpoint,
        path="/api/v1/users",
        method="GET",
        user_agent="curl/8.0",
        pro_enabled=True,
    )

    assert policy["endpoint_id"] == "users_list"
    assert policy["rules"]["matched_rule_ids"] == ["rule_users"]
    assert policy["latency_ms"] == 120
    assert policy["endpoint_config"]["fixed_status"] == 429
    assert policy["mutation"]["mutation_policy"] == "daily"
    assert policy["mutation"]["mutation_intensity"] == 2


def test_runtime_policy_uses_endpoint_override_match_type():
    runtime = _runtime(
        InstanceConfig(
            base_template_id="ecommerce",
            endpoint_configs={
                "orders_get": EndpointConfig(endpoint_id="orders_get", fixed_status=451),
            },
        )
    )
    endpoint = runtime.get_endpoint("orders_get")
    policy = resolve_runtime_request_policy(
        runtime,
        endpoint=endpoint,
        path="/api/v1/orders/123",
        method="GET",
        user_agent="curl/8.0",
        pro_enabled=True,
    )

    assert policy["endpoint_match_type"] == "endpoint_override"
    assert policy["endpoint_config"]["fixed_status"] == 451


def test_runtime_policy_disables_rules_when_pro_is_off():
    runtime = _runtime(
        InstanceConfig(
            base_template_id="ecommerce",
            mutation_config=MutationConfig(policy="weekly", intensity=3),
            response_rules=[
                ResponseRule(
                    id="rule_users",
                    match=ResponseRuleMatch(endpoint_id="users_list"),
                    action=ResponseRuleAction(extra_latency_ms=50),
                )
            ],
        )
    )
    endpoint = runtime.get_endpoint("users_list")
    policy = resolve_runtime_request_policy(
        runtime,
        endpoint=endpoint,
        path="/api/v1/users",
        method="GET",
        user_agent="curl/8.0",
        pro_enabled=False,
    )

    assert policy["rules"]["matched_rule_ids"] == []
    assert policy["latency_ms"] == 0
    assert policy["mutation"]["mutation_policy"] == "none"
    assert policy["mutation"]["mutation_intensity"] == 0
