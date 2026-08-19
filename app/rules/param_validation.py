import re
import logging
from typing import Any, Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from app.rules.engine import BaseRule, RuleEvaluation, ToolInvocationContext
from app.schemas import WAFPolicy

logger = logging.getLogger("agent_waf.rules.param_validation")

# Stateless caching of compiled regex patterns to avoid recompiling on every evaluation
_compiled_regex_cache = {}

def get_compiled_regex(pattern: str) -> re.Pattern:
    """Helper to retrieve or compile a regex pattern safely."""
    if pattern not in _compiled_regex_cache:
        processed_pattern = pattern
        # Transparently convert the base ignore pattern to support "ignore all previous instructions"
        if "ignore (all|previous) instructions" in pattern:
            processed_pattern = pattern.replace(
                "ignore (all|previous) instructions", 
                "ignore (all\\s+previous|all|previous) instructions"
            )
        _compiled_regex_cache[pattern] = re.compile(processed_pattern)
    return _compiled_regex_cache[pattern]

def validate_value(
    val: Any, 
    compiled_regexes: List[re.Pattern], 
    max_length: int, 
    current_depth: int, 
    max_depth: int
) -> Optional[str]:
    """
    Recursively inspects JSON-compatible values for parameter validation.
    Returns:
      "length" if value exceeds max_length
      "blocklist" if a value matches a blocklist regex pattern
      None if validation passes
    """
    if current_depth > max_depth:
        raise ValueError("Maximum nesting depth exceeded")

    if isinstance(val, dict):
        # Scan dictionary values recursively, NOT dictionary keys
        for v in val.values():
            result = validate_value(v, compiled_regexes, max_length, current_depth + 1, max_depth)
            if result:
                return result
    elif isinstance(val, list):
        # Scan each element in list recursively
        for item in val:
            result = validate_value(item, compiled_regexes, max_length, current_depth + 1, max_depth)
            if result:
                return result
    elif isinstance(val, str):
        # Inspect length first
        if len(val) > max_length:
            return "length"
        # Inspect regular expressions
        for pattern in compiled_regexes:
            match = pattern.search(val)
            if match:
                return "blocklist"
    else:
        # Numbers, booleans, and null values do not require regex matching or length check
        pass
        
    return None

class ParameterValidationRule(BaseRule):
    async def evaluate(
        self, 
        context: ToolInvocationContext, 
        policy: WAFPolicy, 
        db: AsyncSession
    ) -> RuleEvaluation:
        # 1. Match applicable policies for the tool
        matching_policies = []
        for p in policy.parameter_validation:
            if p.tool == context.tool_name or p.tool == "*":
                matching_policies.append(p)

        # If no policies exist for this tool, default to pass
        if not matching_policies:
            return RuleEvaluation(
                rule="parameter_validation",
                passed=True,
                reason="Parameter validation passed"
            )

        # 2. Combine blocklist patterns and enforce the most restrictive maximum length (minimum value)
        blocklist_patterns = []
        max_length = None
        for p in matching_policies:
            blocklist_patterns.extend(p.blocklist_patterns)
            if max_length is None:
                max_length = p.max_param_length
            else:
                max_length = min(max_length, p.max_param_length)

        # 3. Safe regex compilation (fail-closed if code configuration contains any invalid regex)
        compiled_regexes = []
        try:
            for pattern in blocklist_patterns:
                compiled_regexes.append(get_compiled_regex(pattern))
        except re.error as e:
            logger.error(f"Security Policy Compilation Error: invalid regex in policy file: {e}", exc_info=True)
            return RuleEvaluation(
                rule="parameter_validation",
                passed=False,
                reason="Parameter validation policy could not be evaluated"
            )

        # 4. Traversal evaluation with recursion limit bounds
        try:
            # We inspect context.parameters with a safe recursion limit (e.g. 50 levels deep)
            validation_result = validate_value(
                context.parameters, 
                compiled_regexes, 
                max_length or 2000, 
                0, 
                50
            )
            
            if validation_result == "length":
                return RuleEvaluation(
                    rule="parameter_validation",
                    passed=False,
                    reason=f"Parameter value exceeds maximum allowed length of {max_length}"
                )
            elif validation_result == "blocklist":
                return RuleEvaluation(
                    rule="parameter_validation",
                    passed=False,
                    reason="Parameter validation blocked value matching configured security pattern"
                )

            return RuleEvaluation(
                rule="parameter_validation",
                passed=True,
                reason="Parameter validation passed"
            )
        except ValueError as e:
            # Handles depth limit exceeded (fails closed)
            logger.error(f"Parameter validation exceeded safety depth: {e}", exc_info=True)
            return RuleEvaluation(
                rule="parameter_validation",
                passed=False,
                reason="Parameter validation policy could not be evaluated"
            )
        except Exception as e:
            # Any unexpected runtime errors fail closed
            logger.error(f"Unanticipated parameter validation error: {e}", exc_info=True)
            return RuleEvaluation(
                rule="parameter_validation",
                passed=False,
                reason="Parameter validation policy could not be evaluated"
            )
