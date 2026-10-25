import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import find_user_safe, find_user_unsafe, list_roles


def test_unsafe_lookup_returns_matching_user():
    assert find_user_unsafe("alice") == [("alice", "user")]


def test_safe_lookup_returns_matching_user():
    assert find_user_safe("alice") == [("alice", "user")]


def test_safe_lookup_treats_injection_text_as_data():
    assert find_user_safe("' OR 1=1 --") == []


def test_list_roles_is_stable():
    assert list_roles() == ["admin", "user"]
