import ast
import pytest
from app.schemas import WAFPolicy, DataScopePolicy
from app.rules.data_scope import DataScopeRule, SafeScopeEvaluator
from app.rules.engine import ToolInvocationContext, RuleEngine, FinalDisposition, RuleEvaluation

def get_scope_policy(mode="enforce", policies=None) -> WAFPolicy:
    if policies is None:
        policies = [
            DataScopePolicy(tool="crm.read", rule="customer_id == session.customer_id"),
            DataScopePolicy(tool="db.delete", rule="record_count <= 100")
        ]
    return WAFPolicy(
        policy_version="v1",
        mode=mode,
        rate_limits=[],
        parameter_validation=[],
        data_scope=policies,
        sequence_rules=[]
    )

@pytest.mark.asyncio
async def test_crm_scope_allowed():
    # 1. customer_id == session.customer_id -> ALLOWED
    rule = DataScopeRule()
    policy = get_scope_policy()
    context = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="crm.read",
        parameters={"customer_id": "CUST-1001"},
        session_context={"customer_id": "CUST-1001"}
    )
    res = await rule.evaluate(context, policy, db=None)
    assert res.passed is True
    assert res.reason == "Data scope validation passed"

@pytest.mark.asyncio
async def test_crm_scope_blocked():
    # 2. customer_id == session.customer_id -> BLOCKED (mismatch value)
    rule = DataScopeRule()
    policy = get_scope_policy()
    context = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="crm.read",
        parameters={"customer_id": "CUST-9999"},
        session_context={"customer_id": "CUST-1001"}
    )
    res = await rule.evaluate(context, policy, db=None)
    assert res.passed is False
    assert res.reason == "Requested data is outside the agent's declared scope"

@pytest.mark.asyncio
async def test_missing_parameters_fail_closed():
    # 3. Missing customer_id param -> BLOCKED
    rule = DataScopeRule()
    policy = get_scope_policy()
    context = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="crm.read",
        parameters={},
        session_context={"customer_id": "CUST-1001"}
    )
    res = await rule.evaluate(context, policy, db=None)
    assert res.passed is False

@pytest.mark.asyncio
async def test_missing_session_fail_closed():
    # 4. Missing session.customer_id -> BLOCKED
    rule = DataScopeRule()
    policy = get_scope_policy()
    context = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="crm.read",
        parameters={"customer_id": "CUST-1001"},
        session_context={}
    )
    res = await rule.evaluate(context, policy, db=None)
    assert res.passed is False

@pytest.mark.asyncio
async def test_numeric_comparisons():
    # 5. record_count = 50 <= 100 -> ALLOWED
    # 6. record_count = 100 <= 100 -> ALLOWED
    # 7. record_count = 101 <= 100 -> BLOCKED
    # 8. record_count = 500 <= 100 -> BLOCKED
    rule = DataScopeRule()
    policy = get_scope_policy()
    
    cases = [
        (50, True),
        (100, True),
        (101, False),
        (500, False),
    ]
    for count, should_pass in cases:
        context = ToolInvocationContext(
            agent_id="agent-A",
            session_id="session-1",
            tool_name="db.delete",
            parameters={"record_count": count},
            session_context={}
        )
        res = await rule.evaluate(context, policy, db=None)
        assert res.passed is should_pass

@pytest.mark.asyncio
async def test_type_safety_no_coercion():
    # 9. record_count = "100" (string) <= 100 (numeric) -> BLOCKED
    rule = DataScopeRule()
    policy = get_scope_policy()
    context = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="db.delete",
        parameters={"record_count": "100"},
        session_context={}
    )
    res = await rule.evaluate(context, policy, db=None)
    assert res.passed is False

@pytest.mark.asyncio
async def test_string_compare_no_normalization():
    # 10. exact case-sensitive -> ALLOWED when identical
    # 11. exact case-sensitive -> BLOCKED when case differs
    rule = DataScopeRule()
    policy = get_scope_policy()

    # Identical
    ctx_match = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="crm.read",
        parameters={"customer_id": "CUST-1001"},
        session_context={"customer_id": "CUST-1001"}
    )
    assert (await rule.evaluate(ctx_match, policy, db=None)).passed is True

    # Case difference
    ctx_diff = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="crm.read",
        parameters={"customer_id": "cust-1001"},
        session_context={"customer_id": "CUST-1001"}
    )
    assert (await rule.evaluate(ctx_diff, policy, db=None)).passed is False

@pytest.mark.asyncio
async def test_tool_matching_semantics():
    # 12. crm.read uses crm.read policy.
    # 13. db.delete uses db.delete policy.
    # 14. unrelated tool (e.g. email.send) with no policy -> ALLOWED.
    rule = DataScopeRule()
    policy = get_scope_policy()

    # unrelated tool
    context_unrelated = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="email.send",
        parameters={"to": "someone@example.com"},
        session_context={}
    )
    res = await rule.evaluate(context_unrelated, policy, db=None)
    assert res.passed is True
    assert res.reason == "No data scope policy configured for tool"

@pytest.mark.asyncio
async def test_wildcard_scope_matching():
    # 15. wildcard policy applies when present
    rule = DataScopeRule()
    policies = [
        DataScopePolicy(tool="*", rule="record_count <= 200")
    ]
    policy = get_scope_policy(policies=policies)
    
    # Matches since tool wildcard checks all tools
    context = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="email.send",
        parameters={"record_count": 150},
        session_context={}
    )
    res = await rule.evaluate(context, policy, db=None)
    assert res.passed is True

@pytest.mark.asyncio
async def test_combining_wildcard_and_exact_policy():
    # 16. exact + wildcard policies both apply
    # 17. one failing applicable policy -> BLOCKED
    rule = DataScopeRule()
    policies = [
        DataScopePolicy(tool="db.delete", rule="record_count <= 100"),
        DataScopePolicy(tool="*", rule="customer_id == session.customer_id")
    ]
    policy = get_scope_policy(policies=policies)

    # Both valid -> ALLOWED
    ctx_both_ok = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="db.delete",
        parameters={"record_count": 50, "customer_id": "CUST-1111"},
        session_context={"customer_id": "CUST-1111"}
    )
    assert (await rule.evaluate(ctx_both_ok, policy, db=None)).passed is True

    # One fails (record_count exceeds exact limit 100) -> BLOCKED
    ctx_len_fail = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="db.delete",
        parameters={"record_count": 150, "customer_id": "CUST-1111"},
        session_context={"customer_id": "CUST-1111"}
    )
    assert (await rule.evaluate(ctx_len_fail, policy, db=None)).passed is False

    # One fails (customer_id differs) -> BLOCKED
    ctx_cust_fail = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="db.delete",
        parameters={"record_count": 50, "customer_id": "CUST-9999"},
        session_context={"customer_id": "CUST-1111"}
    )
    assert (await rule.evaluate(ctx_cust_fail, policy, db=None)).passed is False

@pytest.mark.asyncio
async def test_unsafe_expression_rejections():
    # Testing that dangerous / unsupported expressions are completely blocked
    # 18. __import__("os") -> BLOCKED
    # 19. os.system("whoami") -> BLOCKED
    # 20. session.__class__ -> BLOCKED
    # 21. session.__dict__ -> BLOCKED
    # 22. open("/etc/passwd") -> BLOCKED
    # 23. eval("1==1") -> BLOCKED
    # 24. exec("...") -> BLOCKED
    # 25. lambda expression -> BLOCKED
    # 26. function call -> BLOCKED
    # 27. unsupported arithmetic: record_count + 1 <= 100 -> BLOCKED
    # 28. Deep attribute chain: session.foo.bar -> BLOCKED
    # 29. Dunder access: session.__dict__ -> BLOCKED
    # 30. Unexpected AST node -> BLOCKED
    
    unsafe_expressions = [
        '__import__("os")',
        'os.system("whoami")',
        "session.__class__",
        "session.__dict__",
        'open("/etc/passwd")',
        'eval("1==1")',
        'exec("x = 1")',
        "lambda x: x == 1",
        "int(customer_id)",
        "record_count + 1 <= 100",
        "session.foo.bar",
        "session._internal_secret"
    ]
    
    rule = DataScopeRule()
    params = {"customer_id": "CUST-1001", "record_count": 50}
    session = {"customer_id": "CUST-1001", "foo": "bar", "_internal_secret": "xyz"}
    
    for expr in unsafe_expressions:
        policy = get_scope_policy(policies=[DataScopePolicy(tool="crm.read", rule=expr)])
        context = ToolInvocationContext(
            agent_id="agent-A",
            session_id="session-1",
            tool_name="crm.read",
            parameters=params,
            session_context=session
        )
        res = await rule.evaluate(context, policy, db=None)
        assert res.passed is False
        assert res.reason == "Requested data is outside the agent's declared scope"

@pytest.mark.asyncio
async def test_malformed_syntax_fails_closed():
    # 31. Malformed expression: customer_id == -> BLOCKED
    # 32. Malformed/invalid syntax: customer_id === session.customer_id -> BLOCKED
    rule = DataScopeRule()
    malformed_expressions = [
        "customer_id ==",
        "customer_id === session.customer_id",
        "== session.customer_id",
        "customer_id && session.customer_id"
    ]
    for expr in malformed_expressions:
        policy = get_scope_policy(policies=[DataScopePolicy(tool="crm.read", rule=expr)])
        context = ToolInvocationContext(
            agent_id="agent-A",
            session_id="session-1",
            tool_name="crm.read",
            parameters={"customer_id": "CUST-1001"},
            session_context={"customer_id": "CUST-1001"}
        )
        res = await rule.evaluate(context, policy, db=None)
        assert res.passed is False
        assert res.reason == "Requested data is outside the agent's declared scope"

@pytest.mark.asyncio
async def test_rule_engine_integration():
    # 33. Data scope failure causes final disposition: BLOCKED in enforce mode.
    # 34. Data scope success allows evaluation to continue.
    # Test Enforce mode
    policy_enforce = get_scope_policy(mode="enforce")
    engine = RuleEngine(policy=policy_enforce, rules=[DataScopeRule()])
    
    # Success -> FinalDisposition.ALLOWED
    ctx_ok = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="crm.read",
        parameters={"customer_id": "CUST-1001"},
        session_context={"customer_id": "CUST-1001"}
    )
    res_ok = await engine.evaluate(ctx_ok, db=None)
    assert res_ok.final_disposition == FinalDisposition.ALLOWED

    # Failure -> FinalDisposition.BLOCKED
    ctx_fail = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="crm.read",
        parameters={"customer_id": "CUST-9999"},
        session_context={"customer_id": "CUST-1001"}
    )
    res_fail = await engine.evaluate(ctx_fail, db=None)
    assert res_fail.final_disposition == FinalDisposition.BLOCKED

    # Test Shadow mode
    policy_shadow = get_scope_policy(mode="shadow")
    engine_shadow = RuleEngine(policy=policy_shadow, rules=[DataScopeRule()])
    res_shadow = await engine_shadow.evaluate(ctx_fail, db=None)
    assert res_shadow.final_disposition == FinalDisposition.SHADOW_BLOCKED

@pytest.mark.asyncio
async def test_evaluation_cumulative_blocked_priority():
    # 35. A previous rate-limit BLOCKED result cannot become ALLOWED because data scope passes.
    policy = get_scope_policy(mode="enforce")
    
    # Mock rate limit rule that fails
    class FailingRateLimitRule:
        async def evaluate(self, context, policy, db):
            return RuleEvaluation(rule="rate_limit", passed=False, reason="Rate limit exceeded")

    engine = RuleEngine(policy=policy, rules=[FailingRateLimitRule(), DataScopeRule()])
    context = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="crm.read",
        parameters={"customer_id": "CUST-1001"},
        session_context={"customer_id": "CUST-1001"}
    )
    # The rate limit fails (passed=False) but data scope passes (passed=True).
    # The final outcome must still be BLOCKED!
    result = await engine.evaluate(context, db=None)
    assert result.final_disposition == FinalDisposition.BLOCKED
    
    eval_rate = next(e for e in result.evaluations if e.rule == "rate_limit")
    eval_scope = next(e for e in result.evaluations if e.rule == "data_scope")
    assert eval_rate.passed is False
    assert eval_scope.passed is True

def test_security_regression_exploit_prevention():
    # Security regression test: verify that dangerous payload syntax is rejected by evaluator before execution
    exploit_str = '__import__("os").system("whoami")'
    params = {}
    session = {}
    
    with pytest.raises(ValueError) as exc:
        SafeScopeEvaluator.evaluate_ast(
            ast.parse(exploit_str, mode="eval").body,
            params,
            session
        )
    assert "Unpermitted AST syntax node detected" in str(exc.value)
