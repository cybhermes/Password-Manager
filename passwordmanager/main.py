from password_manager import PasswordManager
import getpass

def main():

    pm = PasswordManager()

    while True:

        print("""
        (1) Create a new vault
        (2) Load an existing vault
        (3) Add a new password
        (4) Delete a password
        (5) Update a password
        (6) Get a password
        (7) List passwords
        (8) Change master password
        (9) Lock vault
        (q) Quit
        """)

        choice = input("Enter your choice: ").strip().lower()

        # Create vault
        if choice == "1":
            path = input("Enter vault path: ").strip()
            pm.create_password_file(path)

        # Load vault
        elif choice == "2":
            path = input("Enter vault path: ").strip()
            pm.load_password_file(path)

        # Add password
        elif choice == "3":
            if not pm.is_unlocked():
                print("Unlock a vault first")
                continue

            site = input("Enter the site: ").strip()
            username = input("Enter the username: ").strip()

            gen_pass = input("Do you want to generate a password (y/n): ").strip().lower()
            if gen_pass == 'y':
                password = pm.generate_password()
                print(f"Generated password: {password}")
            elif gen_pass == 'n':
                password = getpass("Enter the password: ")
            else:
                print("Invalid choice")
                continue

            url = input("Enter URL: ").strip()

            pm.add_password(
                site,
                username,
                password,
                url
            )

        # Delete a password
        elif choice == "4":
            if not pm.is_unlocked():
                print("Unlock a vault first")
                continue

            site = input("Enter the site: ").strip()
            pm.delete_password(site)

        # Update a password
        elif choice == "5":
            if not pm.is_unlocked():
                print("Unlock a vault first")
                continue

            site = input("Enter the site: ").strip()

            gen_pass = input("Do you want to generate the new password (y/n): ").strip().lower()
            if gen_pass == 'y':
                new_password = pm.generate_password()
                print(f"Generated password: {new_password}")
            elif gen_pass == 'n':
                new_password = getpass("Enter the password: ")
            else:
                print("Invalid choice")
                continue

            pm.update_password(site, new_password)

        # Get a password
        elif choice == "6":
            if not pm.is_unlocked():
                print("Unlock a vault first")
                continue

            site = input("What site do you want: ").strip()
            password = pm.get_password(site)

            if password is not None:
                print(f"Password for {site}: {password}")

        # List passwords
        elif choice == "7":
            pm.list_passwords()

        # Change master password
        elif choice == "8":
            pm.change_master_password

        # Lock vault
        elif choice == "9":
            pm.lock_vault()

        # Exit
        elif choice == "q":
            if pm.is_unlocked():
                pm.lock_vault()

            break

        else:
            print("Invalid choice")

if __name__ == "__main__":
    main()
