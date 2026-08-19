import ast
import logging
from typing import Any, Dict
from sqlalchemy.ext.asyncio import AsyncSession
from app.rules.engine import BaseRule, RuleEvaluation, ToolInvocationContext
from app.schemas import WAFPolicy

logger = logging.getLogger("agent_waf.rules.data_scope")

# Thread-safe unbounded cache for parsed AST body nodes from the trusted policy configuration
_parsed_ast_cache = {}

def get_parsed_ast(expression_str: str) -> ast.AST:
    """Helper to retrieve or compile parsed AST body node safely."""
    if expression_str not in _parsed_ast_cache:
        try:
            # Parse with mode="eval" for single expressions
            tree = ast.parse(expression_str.strip(), mode="eval")
            _parsed_ast_cache[expression_str] = tree.body
        except SyntaxError as e:
            # If the config file is corrupted/malformed, compilation fails closed
            raise ValueError(f"Invalid expression syntax: {e}")
    return _parsed_ast_cache[expression_str]

class SafeScopeEvaluator:
    @staticmethod
    def evaluate_ast(node: ast.AST, parameters: Dict[str, Any], session_context: Dict[str, Any]) -> bool:
        """Evaluates an AST node against controlled parameter/session namespaces."""
        result = SafeScopeEvaluator._eval_node(node, parameters, session_context)
        if not isinstance(result, bool):
            raise TypeError("Expression did not resolve to a boolean disposition")
        return result

    @staticmethod
    def _eval_node(node: ast.AST, parameters: Dict[str, Any], session_context: Dict[str, Any]) -> Any:
        # 1. Constant literals (numbers, strings, booleans, None)
        if isinstance(node, ast.Constant):
            return node.value

        # 2. Parameters resolution (Name nodes)
        elif isinstance(node, ast.Name):
            # Only resolve identifier from the request parameters context (no Python globals/builtins scope)
            if node.id in parameters:
                return parameters[node.id]
            else:
                # Missing parameter value -> fail closed
                raise ValueError(f"Missing parameter validation value for: {node.id}")

        # 3. Session variables resolution (Attribute nodes)
        elif isinstance(node, ast.Attribute):
            # Restrict context strictly to 'session.<field>' format
            if isinstance(node.value, ast.Name) and node.value.id == "session":
                field_name = node.attr
                # Block structural access violations (e.g. session.__dict__, session.__class__)
                if field_name.startswith("_"):
                    raise ValueError(f"Unsafe attribute access blocked: {field_name}")
                if field_name in session_context:
                    return session_context[field_name]
                else:
                    # Missing session variable -> fail closed
                    raise ValueError(f"Missing session attribute value: {field_name}")
            else:
                raise ValueError("Attribute access is restricted to 'session.<field>' only")

        # 4. Safe operators execution
        elif isinstance(node, ast.Compare):
            if len(node.ops) != 1 or len(node.comparators) != 1:
                raise ValueError("Only single comparisons are supported")

            left_val = SafeScopeEvaluator._eval_node(node.left, parameters, session_context)
            right_val = SafeScopeEvaluator._eval_node(node.comparators[0], parameters, session_context)
            op = node.ops[0]

            is_left_numeric = isinstance(left_val, (int, float)) and not isinstance(left_val, bool)
            is_right_numeric = isinstance(right_val, (int, float)) and not isinstance(right_val, bool)

            # Ordering operators (<, <=, >, >=) strictly require numeric operands
            if isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)):
                if not (is_left_numeric and is_right_numeric):
                    raise TypeError("Ordering comparisons require both operands to be numeric")

            if isinstance(op, ast.Eq):
                return left_val == right_val
            elif isinstance(op, ast.NotEq):
                return left_val != right_val
            elif isinstance(op, ast.Lt):
                return left_val < right_val
            elif isinstance(op, ast.LtE):
                return left_val <= right_val
            elif isinstance(op, ast.Gt):
                return left_val > right_val
            elif isinstance(op, ast.GtE):
                return left_val >= right_val
            else:
                raise ValueError(f"Unsupported comparison operator: {type(op).__name__}")

        else:
            raise ValueError(f"Unpermitted AST syntax node detected: {type(node).__name__}")

class DataScopeRule(BaseRule):
    async def evaluate(
        self, 
        context: ToolInvocationContext, 
        policy: WAFPolicy, 
        db: AsyncSession
    ) -> RuleEvaluation:
        # Match all configured policies applicable to this tool
        matching_policies = []
        for p in policy.data_scope:
            if p.tool == context.tool_name or p.tool == "*":
                matching_policies.append(p)

        # Default pass if no policies configured for this tool
        if not matching_policies:
            return RuleEvaluation(
                rule="data_scope",
                passed=True,
                reason="No data scope policy configured for tool"
            )

        # Enforce all matched policies (creating an AND-style security boundary)
        for p in matching_policies:
            expression = p.rule
            try:
                parsed_node = get_parsed_ast(expression)
                allowed = SafeScopeEvaluator.evaluate_ast(
                    parsed_node, 
                    context.parameters, 
                    context.session_context
                )
                if not allowed:
                    return RuleEvaluation(
                        rule="data_scope",
                        passed=False,
                        reason="Requested data is outside the agent's declared scope"
                    )
            except Exception as e:
                # Any syntax error, type mismatch, missing param, or unsafe expression fails closed
                logger.error(f"Conflict evaluating data scope rule for tool '{context.tool_name}': {e}", exc_info=True)
                return RuleEvaluation(
                    rule="data_scope",
                    passed=False,
                    reason="Requested data is outside the agent's declared scope"
                )

        return RuleEvaluation(
            rule="data_scope",
            passed=True,
            reason="Data scope validation passed"
        )
