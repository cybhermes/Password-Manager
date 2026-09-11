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
        (5) Update a new password
        (6) Get a password
        (q) Quit
        """)

        choice = input("Enter your choice: ")

        # New vault
        if choice == "1":
            path = input("Enter vault path: ")
            pm.create_password_file(path)

        # Load vault
        elif choice == "2":
            path = input("Enter vault path: ")
            pm.load_password_file(path)

        # Add a password
        elif choice == "3":
            if pm.key is None:
                print("Unlock a vault first")
                continue

            site = input("Enter the site: ")
            username = input("Enter the username: ")

            gen_pass = input("Do you want to generate a password (y/n): ").lower()
            if gen_pass == 'y':
                password = pm.generate_password()
            elif gen_pass == 'n':
                password = getpass("Enter the password: ")
            else:
                print("Invalid choice")
                continue

            url = input("Enter URL: ")

            pm.add_password(
                site,
                username,
                password,
                url
            )

        # Delete a password
        elif choice == "4":
            if pm.key is None:
                print("Unlock a vault first")
                continue

            site = input("Enter the site: ")
            pm.delete_password(site)

        # Update a password
        elif choice == "5":
            if pm.key is None:
                print("Unlock a vault first")
                continue

            site = input("Enter the site: ")

            gen_pass = input("Do you want to generate the new password (y/n): ").lower()
            if gen_pass == 'y':
                new_password = pm.generate_password()
            elif gen_pass == 'n':
                new_password = getpass("Enter the password: ")
            else:
                print("Invalid choice")
                continue

            pm.update_password(site, new_password)

        # Get a password
        elif choice == "6":
            if pm.key is None:
                print("Unlock a vault first")
                continue

            site = input("What site do you want: ")
            password = pm.get_password(site)

            if password is not None:
                print(f"Password for {site}: {password}")

        # Exit
        elif choice == "q":
            break

        else:
            print("Invalid choice")

if __name__ == "__main__":
    main()
