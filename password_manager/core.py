"""Password storage, master-password verification, and password generation."""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import secrets
import string
from pathlib import Path
from typing import cast

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_ITERATIONS = 600_000
_SALT_SIZE = 16


class StorageError(Exception):
    """Raised when the vault cannot be read, written, or decrypted."""


class PasswordManager:
    """Manage encrypted login records in a JSON file."""

    def __init__(self, storage_path: str | Path = "vault.json") -> None:
        """Create a manager connected to the selected vault file."""
        self.storage_path = Path(storage_path)
        self._data = self._load()
        self._fernet: Fernet | None = None

    def init_master(self, password: str) -> None:
        """Create the master-password hash and encryption salt once."""
        if self.storage_path.exists() or self._data:
            raise ValueError("Хранилище уже существует. Перезапись запрещена.")
        if len(password) < 8:
            raise ValueError("Мастер-пароль должен содержать минимум 8 символов.")

        master_salt = secrets.token_bytes(_SALT_SIZE)
        encryption_salt = secrets.token_bytes(_SALT_SIZE)
        master_hash = self._derive_key(password, master_salt).hex()

        self._data = {
            "version": 1,
            "master_salt": base64.b64encode(master_salt).decode("ascii"),
            "master_hash": master_hash,
            "encryption_salt": base64.b64encode(encryption_salt).decode("ascii"),
            "entries": {},
        }
        self._persist()

    def unlock(self, password: str) -> bool:
        """Check the master password and unlock the encrypted records."""
        self._fernet = None
        if not self.verify_master_password(password):
            return False

        encryption_salt = self._get_salt("encryption_salt")
        key = base64.urlsafe_b64encode(self._derive_key(password, encryption_salt))
        self._fernet = Fernet(key)
        return True

    def verify_master_password(self, password: str) -> bool:
        """Verify the master password without changing the current lock state."""
        if not self._data:
            raise StorageError("Мастер-пароль ещё не создан. Используйте --init.")

        salt = self._get_salt("master_salt")
        saved_hash = self._get_text("master_hash")
        entered_hash = self._derive_key(password, salt).hex()
        return hmac.compare_digest(entered_hash, saved_hash)

    def add_entry(self, name: str, login: str, password: str) -> None:
        """Encrypt and save a new service record."""
        fernet = self._require_unlocked()
        clean_name = name.strip()
        clean_login = login.strip()
        if not clean_name or not clean_login or not password:
            raise ValueError("Название, логин и пароль не должны быть пустыми.")

        entries = self._get_entries()
        if clean_name in entries:
            raise ValueError("Запись с таким названием уже существует.")

        payload = json.dumps(
            {"login": clean_login, "password": password}, ensure_ascii=False
        ).encode("utf-8")
        entries[clean_name] = fernet.encrypt(payload).decode("ascii")
        self._data["entries"] = entries
        self._persist()

    def list_entries(self) -> list[str]:
        """Return sorted service names without revealing credentials."""
        self._require_unlocked()
        return sorted(self._get_entries())

    def get_entry(self, name: str) -> tuple[str, str]:
        """Return the login and password for one saved service."""
        fernet = self._require_unlocked()
        entries = self._get_entries()
        if name not in entries:
            raise KeyError(f"Запись '{name}' не найдена.")

        try:
            decrypted = fernet.decrypt(entries[name].encode("ascii"))
            payload = json.loads(decrypted.decode("utf-8"))
        except (InvalidToken, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise StorageError("Не удалось расшифровать запись.") from error

        if not isinstance(payload, dict):
            raise StorageError("Некорректный формат зашифрованной записи.")
        login = payload.get("login")
        password = payload.get("password")
        if not isinstance(login, str) or not isinstance(password, str):
            raise StorageError("В записи отсутствуют логин или пароль.")
        return login, password

    def delete_entry(self, name: str) -> None:
        """Delete a saved service record."""
        self._require_unlocked()
        entries = self._get_entries()
        if name not in entries:
            raise KeyError(f"Запись '{name}' не найдена.")
        del entries[name]
        self._data["entries"] = entries
        self._persist()

    def _load(self) -> dict[str, object]:
        """Read the vault JSON or return an empty structure for a new vault."""
        if not self.storage_path.exists():
            return {}
        try:
            raw_data = json.loads(self.storage_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise StorageError("Не удалось прочитать файл хранилища.") from error
        if not isinstance(raw_data, dict):
            raise StorageError("Файл хранилища имеет неверный формат.")
        return cast(dict[str, object], raw_data)

    def _persist(self) -> None:
        """Write the vault atomically and restrict file permissions where possible."""
        temporary_path = self.storage_path.with_name(self.storage_path.name + ".tmp")
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            content = json.dumps(self._data, ensure_ascii=False, indent=2)
            temporary_path.write_text(content, encoding="utf-8")
            if temporary_path != self.storage_path:
                temporary_path.chmod(0o600)
            temporary_path.replace(self.storage_path)
        except OSError as error:
            raise StorageError("Не удалось сохранить файл хранилища.") from error
        finally:
            if temporary_path.exists():
                temporary_path.unlink(missing_ok=True)

    def _get_text(self, key: str) -> str:
        """Return a required text value from the vault."""
        value = self._data.get(key)
        if not isinstance(value, str):
            raise StorageError(f"В хранилище отсутствует поле '{key}'.")
        return value

    def _get_salt(self, key: str) -> bytes:
        """Decode and validate a salt stored as Base64 text."""
        try:
            salt = base64.b64decode(self._get_text(key), validate=True)
        except (binascii.Error, ValueError) as error:
            raise StorageError(f"Соль '{key}' повреждена.") from error
        if len(salt) < _SALT_SIZE:
            raise StorageError(f"Соль '{key}' имеет неверную длину.")
        return salt

    def _get_entries(self) -> dict[str, str]:
        """Return the encrypted records after checking their JSON structure."""
        value = self._data.get("entries")
        if not isinstance(value, dict):
            raise StorageError("Список записей в хранилище повреждён.")

        entries: dict[str, str] = {}
        for name, token in value.items():
            if not isinstance(name, str) or not isinstance(token, str):
                raise StorageError("Одна из записей в хранилище повреждена.")
            entries[name] = token
        return entries

    def _require_unlocked(self) -> Fernet:
        """Return the cipher or explain that authentication is required."""
        if self._fernet is None:
            raise PermissionError("Сначала войдите с помощью --unlock.")
        return self._fernet

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        """Derive a 32-byte key with PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=_ITERATIONS,
        )
        return kdf.derive(password.encode("utf-8"))


def generate_password(length: int = 20) -> str:
    """Generate a password containing lower, upper, digit, and special chars."""
    if length < 4:
        raise ValueError("Длина пароля должна быть не меньше 4 символов.")

    groups = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        "!@#$%^&*()-_=+[]{};:,.?",
    ]
    password_chars = [secrets.choice(group) for group in groups]
    alphabet = "".join(groups)
    password_chars.extend(secrets.choice(alphabet) for _ in range(length - 4))
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)
