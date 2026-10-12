"""Tests for master-key handling and mission key derivation."""

from pathlib import Path

import pytest

from uavsec.keys import derive_keys, generate_master_key, load_master_key


def test_derivation_is_deterministic() -> None:
    """The same master key and mission produce the same key set."""
    master_key = bytes(range(32))

    assert derive_keys(master_key, "mission-7") == derive_keys(master_key, "mission-7")


def test_derived_keys_are_distinct() -> None:
    """Each pipeline purpose receives a distinct key."""
    key_set = derive_keys(bytes(range(32)), "mission-7")

    assert len({key_set.k_enc, key_set.k_shuf, key_set.k_loc}) == 3


def test_mission_or_master_change_changes_keys() -> None:
    """Changing either derivation input changes the resulting key set."""
    master_key = bytes(range(32))

    assert derive_keys(master_key, "mission-7") != derive_keys(master_key, "mission-8")
    assert derive_keys(master_key, "mission-7") != derive_keys(bytes(reversed(range(32))), "mission-7")


def test_generate_master_key_has_expected_length() -> None:
    """Generated master keys are 32 random bytes."""
    assert len(generate_master_key()) == 32


def test_bad_master_key_length_raises() -> None:
    """Derivation rejects master keys of the wrong length."""
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        derive_keys(b"too short", "mission-7")


def test_environment_key_is_loaded(monkeypatch: pytest.MonkeyPatch) -> None:
    """The environment key takes precedence over the file path."""
    expected = bytes(range(32))
    monkeypatch.setenv("UAVSEC_MASTER_KEY", expected.hex())

    assert load_master_key(Path("does-not-exist.key")) == expected


def test_missing_key_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing environment and file key produces a clear error."""
    monkeypatch.delenv("UAVSEC_MASTER_KEY", raising=False)

    with pytest.raises(ValueError, match="Master key is missing"):
        load_master_key(tmp_path / "missing.key")


def test_invalid_file_key_length_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A file key with the wrong decoded length is rejected."""
    monkeypatch.delenv("UAVSEC_MASTER_KEY", raising=False)
    key_file = tmp_path / "master.key"
    key_file.write_text("00", encoding="ascii")

    with pytest.raises(ValueError, match="exactly 32 bytes"):
        load_master_key(key_file)