from app.rules.engine import BaseRule, RuleEvaluation, ToolInvocationContext
from app.schemas import WAFPolicy

class ParameterValidationRule(BaseRule):
    def evaluate(self, context: ToolInvocationContext, policy: WAFPolicy) -> RuleEvaluation:
        # Placeholder for parameter validation rule (blocklist matching and max param length check are future milestones)
        return RuleEvaluation(
            rule="parameter_validation",
            passed=True,
            reason="Parameter validation placeholder (not implemented)"
        )
