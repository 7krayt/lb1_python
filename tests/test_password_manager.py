"""Tests for password hashing, encrypted records, and password generation."""

import json
from pathlib import Path

import pytest

from password_manager import PasswordManager, generate_password

MASTER_PASSWORD = "VeryStrongMaster123!"


@pytest.fixture
def unlocked_manager(tmp_path: Path) -> PasswordManager:
    """Return a manager with a newly created and unlocked temporary vault."""
    manager = PasswordManager(tmp_path / "vault.json")
    manager.init_master(MASTER_PASSWORD)
    assert manager.unlock(MASTER_PASSWORD)
    return manager


def test_unlock_accepts_correct_password_and_rejects_wrong_one(
    tmp_path: Path,
) -> None:
    """Only the correct master password unlocks the vault."""
    manager = PasswordManager(tmp_path / "vault.json")
    manager.init_master(MASTER_PASSWORD)

    assert manager.unlock(MASTER_PASSWORD) is True
    assert manager.unlock("wrong-password") is False


def test_init_cannot_overwrite_existing_vault(tmp_path: Path) -> None:
    """A second initialization must not replace the first master hash."""
    path = tmp_path / "vault.json"
    manager = PasswordManager(path)
    manager.init_master(MASTER_PASSWORD)
    original_content = path.read_text(encoding="utf-8")

    with pytest.raises(ValueError, match="уже существует"):
        manager.init_master("AnotherStrongPassword123!")

    assert path.read_text(encoding="utf-8") == original_content


def test_add_list_and_get_entry(unlocked_manager: PasswordManager) -> None:
    """An added record appears in the list and can be decrypted."""
    unlocked_manager.add_entry("GitHub", "student", "GitHubSecret!23")

    assert unlocked_manager.list_entries() == ["GitHub"]
    assert unlocked_manager.get_entry("GitHub") == ("student", "GitHubSecret!23")


def test_delete_entry(unlocked_manager: PasswordManager) -> None:
    """Deleting a record removes it from the list and lookup."""
    unlocked_manager.add_entry("Mail", "student", "MailSecret!23")
    unlocked_manager.delete_entry("Mail")

    assert unlocked_manager.list_entries() == []
    with pytest.raises(KeyError):
        unlocked_manager.get_entry("Mail")


def test_vault_does_not_store_master_or_entry_password_in_plain_text(
    tmp_path: Path,
) -> None:
    """The JSON file contains a hash and ciphertext, not clear-text passwords."""
    path = tmp_path / "vault.json"
    manager = PasswordManager(path)
    manager.init_master(MASTER_PASSWORD)
    assert manager.unlock(MASTER_PASSWORD)
    manager.add_entry("Example", "student", "EntrySecret!23")

    content = path.read_text(encoding="utf-8")
    saved_data = json.loads(content)
    assert "master_hash" in saved_data
    assert MASTER_PASSWORD not in content
    assert "EntrySecret!23" not in content
    assert "student" not in content


def test_vault_can_be_opened_after_restart(tmp_path: Path) -> None:
    """Encrypted records remain available after creating a new manager object."""
    path = tmp_path / "vault.json"
    first_manager = PasswordManager(path)
    first_manager.init_master(MASTER_PASSWORD)
    assert first_manager.unlock(MASTER_PASSWORD)
    first_manager.add_entry("GitHub", "student", "GitHubSecret!23")

    second_manager = PasswordManager(path)
    assert second_manager.unlock(MASTER_PASSWORD)
    assert second_manager.get_entry("GitHub") == ("student", "GitHubSecret!23")


def test_records_require_unlock(tmp_path: Path) -> None:
    """Records cannot be listed before successful authentication."""
    manager = PasswordManager(tmp_path / "vault.json")
    manager.init_master(MASTER_PASSWORD)

    with pytest.raises(PermissionError):
        manager.list_entries()


def test_generated_password_has_all_character_groups() -> None:
    """The generated password has the requested length and four character types."""
    password = generate_password(24)

    assert len(password) == 24
    assert any(char.islower() for char in password)
    assert any(char.isupper() for char in password)
    assert any(char.isdigit() for char in password)
    assert any(char in "!@#$%^&*()-_=+[]{};:,.?" for char in password)


def test_generator_rejects_too_short_password() -> None:
    """A generated password must be long enough for all required character groups."""
    with pytest.raises(ValueError):
        generate_password(3)
