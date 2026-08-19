import pytest
from pydantic import BaseModel, ValidationError
import json
from app.rules.engine import (
    RuleEvaluation,
    ToolInvocationContext,
    FinalDisposition,
    RuleEngine,
    RuleEvaluationError,
    BaseRule
)
from app.rules.rate_limit import RateLimitRule
from app.rules.param_validation import ParameterValidationRule
from app.rules.data_scope import DataScopeRule
from app.rules.sequence import SequenceRule
from app.schemas import WAFPolicy

# Mock Policy for testing namespaces
def get_mock_policy(mode="enforce") -> WAFPolicy:
    return WAFPolicy(
        policy_version="v1_test",
        mode=mode,
        rate_limits=[],
        parameter_validation=[],
        data_scope=[],
        sequence_rules=[]
    )

def test_rule_evaluation_creation():
    # 1. RuleEvaluation can be created.
    eval_obj = RuleEvaluation(rule="rate_limit", passed=True, reason="Pass status")
    assert eval_obj.rule == "rate_limit"
    assert eval_obj.passed is True
    assert eval_obj.reason == "Pass status"

def test_rule_evaluation_serializable():
    # 2. RuleEvaluation is serializable.
    eval_obj = RuleEvaluation(rule="data_scope", passed=False, reason="Out of bounds")
    dumped = eval_obj.model_dump_json()
    loaded = json.loads(dumped)
    assert loaded["rule"] == "data_scope"
    assert loaded["passed"] is False
    assert loaded["reason"] == "Out of bounds"

def test_tool_invocation_context_creation():
    # 3. ToolInvocationContext can be created.
    context = ToolInvocationContext(
        agent_id="test-agent",
        session_id="session-123",
        tool_name="crm.read",
        parameters={"customer_id": 10},
        session_context={"customer_id": 10}
    )
    assert context.agent_id == "test-agent"
    assert context.tool_name == "crm.read"
    assert context.parameters["customer_id"] == 10
    
    # Read-only test
    with pytest.raises(ValidationError):
        # Trying to mutate value on frozen Pydantic model raises ValidationError
        context.agent_id = "new-agent"

def test_final_disposition_values():
    # 4. FinalDisposition accepts ALLOWED, BLOCKED, SHADOW_BLOCKED
    assert FinalDisposition.ALLOWED == "ALLOWED"
    assert FinalDisposition.BLOCKED == "BLOCKED"
    assert FinalDisposition.SHADOW_BLOCKED == "SHADOW_BLOCKED"

def test_invalid_disposition_rejected():
    # 5. Invalid disposition is rejected.
    class TestModel(BaseModel):
        disp: FinalDisposition
        
    with pytest.raises(ValidationError):
        TestModel(disp="INVALID")

def test_rule_engine_accepts_policy():
    # 6. RuleEngine can accept a policy.
    policy = get_mock_policy()
    engine = RuleEngine(policy=policy, rules=[])
    assert engine.policy.policy_version == "v1_test"

def test_deterministic_rule_execution_order():
    # 7. RuleEngine executes rules in deterministic order.
    # Pass in reverse/scrambled order: sequence -> data_scope -> param_val -> rate_limit
    rules = [
        SequenceRule(),
        DataScopeRule(),
        ParameterValidationRule(),
        RateLimitRule()
    ]
    policy = get_mock_policy()
    engine = RuleEngine(policy=policy, rules=rules)
    
    # Assert sorted order: RateLimitRule(1), ParameterValidationRule(2), DataScopeRule(3), SequenceRule(4)
    ordered_names = [rule.__class__.__name__ for rule in engine.rules]
    assert ordered_names == [
        "RateLimitRule",
        "ParameterValidationRule",
        "DataScopeRule",
        "SequenceRule"
    ]

@pytest.mark.asyncio
async def test_rule_engine_returns_structured_evaluations():
    # 8. RuleEngine returns structured evaluations.
    # 9. With the placeholder rules, the engine returns ALLOWED.
    rules = [
        RateLimitRule(),
        ParameterValidationRule(),
        DataScopeRule(),
        SequenceRule()
    ]
    policy = get_mock_policy(mode="enforce")
    engine = RuleEngine(policy=policy, rules=rules)
    
    context = ToolInvocationContext(
        agent_id="test-agent",
        session_id="session-123",
        tool_name="crm.read",
        parameters={},
        session_context={}
    )
    
    result = await engine.evaluate(context, None)
    assert result.final_disposition == FinalDisposition.ALLOWED
    assert len(result.evaluations) == 4
    for eval_obj in result.evaluations:
        assert isinstance(eval_obj, RuleEvaluation)
        assert eval_obj.passed is True

@pytest.mark.asyncio
async def test_rule_exceptions_not_silent():
    # 10. Rule exceptions are not silently swallowed.
    class BrokenRule(BaseRule):
        async def evaluate(self, context, policy, db):
            raise RuntimeError("Database disconnected or internal failure")
            
    policy = get_mock_policy()
    engine = RuleEngine(policy=policy, rules=[BrokenRule()])
    
    context = ToolInvocationContext(
        agent_id="test-agent",
        session_id="session-123",
        tool_name="crm.read",
        parameters={},
        session_context={}
    )
    
    with pytest.raises(RuleEvaluationError) as exc_info:
        await engine.evaluate(context, None)
        
    assert "BrokenRule failed execution" in str(exc_info.value)
