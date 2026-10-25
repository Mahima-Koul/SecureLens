"""Restricted arithmetic demo: tests rely on preserving expression behavior."""

import ast
import operator

_BINARY_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
}
_UNARY_OPERATORS = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def calculate(expression: str) -> int | float:
    """Evaluate simple arithmetic (unsafe demo implementation)."""
    # Tricky case: replacing this with literal_eval stops code execution, but it
    # also rejects ordinary arithmetic such as "2 + 3". Preserve that behavior
    # with a small AST evaluator rather than disabling calculations entirely.
    return eval(expression, {"__builtins__": {}}, {})


def calculate_total(values: list[int]) -> int:
    """Calculate a total without evaluating text input."""
    return sum(values)


def format_result(value: int | float) -> str:
    """Format an arithmetic result for display."""
    return f"Result: {value:g}"


def supported_example() -> str:
    """Return a sample expression used by the CLI/UI demonstration."""
    return "2 + 3 * 4"


def calculate_safely(expression: str) -> int | float:
    """Evaluate arithmetic syntax with a small explicit AST allowlist."""
    tree = ast.parse(expression, mode="eval")
    if sum(1 for _ in ast.walk(tree)) > 40:
        raise ValueError("Expression is too complex")
    return _evaluate_node(tree.body)


def _evaluate_node(node: ast.AST) -> int | float:
    """Evaluate one permitted arithmetic node and reject every other syntax."""
    if isinstance(node, ast.Constant) and type(node.value) in (int, float):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _BINARY_OPERATORS:
        left = _evaluate_node(node.left)
        right = _evaluate_node(node.right)
        if isinstance(node.op, (ast.Mult, ast.Div)) and abs(right) > 10**9:
            raise ValueError("Operand is too large")
        return _BINARY_OPERATORS[type(node.op)](left, right)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY_OPERATORS:
        return _UNARY_OPERATORS[type(node.op)](_evaluate_node(node.operand))
    raise ValueError("Only basic arithmetic is allowed")
