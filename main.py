"""Command-line menu for the secure login system."""

from getpass import getpass

from database import init_db
from service import login_user, register_user


def main() -> None:
    init_db()
    while True:
        print("\n=== Secure Login System ===")
        print("1. Register")
        print("2. Log in")
        print("3. Quit")
        choice = input("Choose an option: ").strip()

        if choice == "1":
            username = input("Choose a username: ")
            password = getpass("Choose a password: ")
            confirm = getpass("Repeat the password: ")
            if password != confirm:
                print("Passwords do not match.")
                continue
            _, message = register_user(username, password)
            print(message)

        elif choice == "2":
            username = input("Username: ")
            password = getpass("Password: ")
            ok, message = login_user(username, password)
            print(message)
            if ok:
                print(f"Welcome, {username.strip()}! You are now logged in.")

        elif choice == "3":
            print("Goodbye.")
            break

        else:
            print("Please enter 1, 2 or 3.")


if __name__ == "__main__":
    main()