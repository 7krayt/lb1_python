"""A small encrypted password manager for the terminal."""

from password_manager.core import PasswordManager, StorageError, generate_password

__all__ = ["PasswordManager", "StorageError", "generate_password"]
