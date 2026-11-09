"""Command-line interface for the password manager."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from getpass import getpass
from pathlib import Path

from password_manager.core import PasswordManager, StorageError, generate_password


def _create_vault(manager: PasswordManager) -> int:
    """Ask for a new master password and create the vault."""
    password = getpass("Придумайте мастер-пароль: ")
    confirmation = getpass("Повторите мастер-пароль: ")
    if password != confirmation:
        print("Ошибка: пароли не совпадают.")
        return 1
    try:
        manager.init_master(password)
    except (ValueError, StorageError) as error:
        print(f"Ошибка: {error}")
        return 1
    print("Мастер-пароль создан. Хранилище готово к работе.")
    return 0


def _run_menu(manager: PasswordManager) -> int:
    """Run the interactive menu until the user selects exit."""
    print("Команды: add, list, get, delete, exit")
    while True:
        try:
            command = input("password-manager> ").strip().lower()
            if command == "exit":
                return 0
            if command == "add":
                name = input("Название сервиса: ")
                login = input("Логин: ")
                password = getpass("Пароль: ")
                manager.add_entry(name, login, password)
                print("Запись добавлена.")
            elif command == "list":
                names = manager.list_entries()
                print("\n".join(names) if names else "Записей пока нет.")
            elif command == "get":
                name = input("Название сервиса: ").strip()
                confirmation = getpass("Подтвердите мастер-пароль: ")
                if not manager.verify_master_password(confirmation):
                    print("Ошибка: неверный мастер-пароль.")
                    continue
                login, password = manager.get_entry(name)
                print(f"Логин: {login}\nПароль: {password}")
            elif command == "delete":
                name = input("Название сервиса: ").strip()
                manager.delete_entry(name)
                print("Запись удалена.")
            else:
                print("Неизвестная команда. Доступно: add, list, get, delete, exit.")
        except (ValueError, KeyError, PermissionError, StorageError) as error:
            print(f"Ошибка: {error}")
        except EOFError:
            print()
            return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Parse command-line options and start the requested action."""
    parser = argparse.ArgumentParser(description="Менеджер паролей в терминале")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--init", action="store_true", help="создать хранилище")
    action.add_argument("--unlock", action="store_true", help="войти в хранилище")
    action.add_argument(
        "--generate", action="store_true", help="сгенерировать надёжный пароль"
    )
    parser.add_argument("--file", default="vault.json", help="путь к JSON-хранилищу")
    parser.add_argument("--length", type=int, default=20, help="длина нового пароля")
    args = parser.parse_args(argv)

    if args.generate:
        try:
            print(generate_password(args.length))
        except ValueError as error:
            parser.error(str(error))
        return 0

    try:
        manager = PasswordManager(Path(args.file))
        if args.init:
            return _create_vault(manager)

        password = getpass("Мастер-пароль: ")
        if not manager.unlock(password):
            print("Ошибка: неверный мастер-пароль.")
            return 1
        print("Вход выполнен.")
        return _run_menu(manager)
    except StorageError as error:
        print(f"Ошибка хранилища: {error}")
        return 1
    except KeyboardInterrupt:
        print("\nРабота завершена.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
