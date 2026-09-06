from cryptography.fernet import Fernet
from getpass import getpass
import json
import os

class PasswordManager:

    def __init__(self):
        self.key = None
        self.password_file = None
        self.password_dict = {}

    def create_key(self, path):
        self.key = Fernet.generate_key()

        with open(path, "wb") as f:
            f.write(self.key)

        print("Key created successfully")

    def load_key(self, path):
        with open(path, "rb") as f:
            self.key = f.read()

        print("Key loaded successfully")

    def save_vault(self):
        if self.password_file is None:
            print("No password file loaded")
            return

        with open(self.password_file, "w", encoding="utf-8") as f:
            json.dump(self.password_dict, f, indent=4)

        print("Vault saved successfully")

    def create_password_file(self, path, initial_values=None):
        self.password_file = path

        data = {}

        if initial_values is not None:
            for site, values in initial_values.items():
                encrypted = Fernet(self.key).encrypt(
                    values["password"].encode()
                ).decode()

                data[site] = {
                    "username": values["username"],
                    "password": encrypted,
                    "url": values["url"]
                }

        with open(self.password_file, "w") as f:
            json.dump(data, f, indent=4)

        print("Password file created successfully")

    def load_password_file(self, path):
        self.password_file = path

        if not os.path.exists(path):
            self.password_dict = {}
            return

        with open(path, "r", encoding="utf-8") as f:
            self.password_dict = json.load(f)

        print("Vault loaded")

    def add_password(self, site, username, password, url):

        encrypted = Fernet(self.key).encrypt(password.encode()).decode()

        self.password_dict[site] = {
            "username": username,
            "password": encrypted,
            "url": url
        }

        self.save_vault()

    def delete_password(self, site):

        if site not in self.password_dict:
            print(f"No password found for {site}")
            return

        del self.password_dict[site]
        self.save_vault()

    def update_password(self, site, new_password):

        if site not in self.password_dict:
            print(f"No password found for {site}")
            return

        encrypted = Fernet(self.key).encrypt(new_password.encode()).decode()
        self.password_dict[site]["password"] = encrypted
        self.save_vault()

    def get_password(self, site):

        if site not in self.password_dict:
            return None

        encrypted = self.password_dict[site]["password"]
        return Fernet(self.key).decrypt(encrypted.encode()).decode()

def main():

    pm = PasswordManager()

    print("""
    (1) Create a new key
    (2) Load an existing key
    (3) Create a new password file
    (4) Load existing password file
    (5) Add a new password
    (6) Delete a password
    (7) Update a password
    (8) Get a password
    (q) Quit
    """)

    done = False

    while not done:

        choice = input("Enter your choice: ")

        # Create key
        if choice == "1":

            path = input("Enter key path: ")
            pm.create_key(path)

        # Load key
        elif choice == "2":

            path = input("Enter key path: ")
            pm.load_key(path)

        # Create JSON file
        elif choice == "3":

            path = input("Enter JSON file path: ")

            pm.create_password_file(path)

        elif choice == "4":

            path = input("Enter JSON file path: ")

            pm.load_password_file(path)

        elif choice == "5":

            site = input("Enter the site: ")
            username = input("Enter the username: ")
            password = getpass("Enter the password: ")
            url = input("Enter URL: ")

            pm.add_password(
                site,
                username,
                password,
                url
            )

        elif choice == "6":
            site = input("Enter the site: ")
            pm.delete_password(site)

        elif choice == "7":

            site = input("Enter the site: ")
            new_password = getpass("Enter tne new password: ")
            pm.update_password(site, new_password)

        elif choice == "8":

            site = input("What site do you want: ")

            password = pm.get_password(site)

            if password:
                print(f"Password for {site}: {password}")

        elif choice == "q":

            done = True

        else:

            print("Invalid choice")

if __name__ == "__main__":
    main()
