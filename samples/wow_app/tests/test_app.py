import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import calculate, calculate_safely, calculate_total, format_result, supported_example


def test_calculate_preserves_precedence():
    assert calculate("2 + 3 * 4") == 14


def test_calculate_supports_parentheses():
    assert calculate("(10 - 2) / 4") == 2


def test_total_is_independent_of_expression_evaluator():
    assert calculate_total([2, 3, 4]) == 9


def test_demo_expression_and_format():
    assert calculate(supported_example()) == 14
    assert format_result(14) == "Result: 14"


def test_safe_evaluator_preserves_arithmetic_without_eval():
    assert calculate_safely("2 + 3 * 4") == 14


def test_safe_evaluator_rejects_calls():
    try:
        calculate_safely("__import__('os').system('echo no')")
    except ValueError:
        pass
    else:
        raise AssertionError("function calls must be rejected")
