import pickle
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import checksum, describe_profile, is_valid_profile, load_user_profile, service_key_prefix


def test_service_key_prefix_is_present():
    assert service_key_prefix() == "sk-de"


def test_profile_round_trip_for_local_fixture():
    profile = {"name": "Ada"}
    assert load_user_profile(pickle.dumps(profile)) == profile


def test_profile_display_and_validation():
    profile = {"name": "Ada"}
    assert describe_profile(profile) == "Profile: Ada"
    assert is_valid_profile(profile)


def test_checksum_is_repeatable():
    assert checksum(b"demo") == checksum(b"demo")
