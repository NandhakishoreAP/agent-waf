from app.rules.engine import BaseRule, RuleEvaluation, ToolInvocationContext
from app.schemas import WAFPolicy

class SequenceRule(BaseRule):
    def evaluate(self, context: ToolInvocationContext, policy: WAFPolicy) -> RuleEvaluation:
        # Placeholder for sequence rule (prior tool calls history logic is a future milestone)
        return RuleEvaluation(
            rule="sequence",
            passed=True,
            reason="Sequence placeholder (not implemented)"
        )
