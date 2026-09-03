from cryptography.fernet import Fernet
from getpass import getpass
import json
import os

class PasswordManager:

    def __init__(self):
        self.key = None
        self.password_file = None

    def create_key(self, path):
        self.key = Fernet.generate_key()

        with open(path, "wb") as f:
            f.write(self.key)

        print("Key created successfully.")

    def load_key(self, path):
        with open(path, "rb") as f:
            self.key = f.read()

        print("Key loaded successfully.")

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

        print("Password file created successfully.")

    def load_password_file(self, path):
        self.password_file = path

        if not os.path.exists(path):
            print("Password file does not exist.")
            return

        with open(path, "r") as f:
            data = json.load(f)

        print("Password file loaded successfully.")

        return data
    
    def add_password(self, site, username, password, url):

        if self.password_file is None:
            print("Create or load a password file first.")
            return

        if os.path.exists(self.password_file):
            with open(self.password_file, "r") as f:
                data = json.load(f)
        else:
            data = {}

        encrypted = Fernet(self.key).encrypt(
            password.encode()
        ).decode()

        data[site] = {
            "username": username,
            "password": encrypted,
            "url": url
        }

        with open(self.password_file, "w") as f:
            json.dump(data, f, indent=4)

        print(f"{site} added successfully")

    def get_password(self, site):

        if self.password_file is None:
            print("Create or load a password file first")
            return

        if not os.path.exists(self.password_file):
            print("Password file does not exist")
            return

        with open(self.password_file, "r") as f:
            data = json.load(f)

        if site not in data:
            print(f"No password found for {site}")
            return

        encrypted_password = data[site]["password"]

        decrypted_password = Fernet(self.key).decrypt(
            encrypted_password.encode()
        ).decode()

        return decrypted_password

def main():

    pm = PasswordManager()

    print("""
    (1) Create a new key
    (2) Load an existing key
    (3) Create a new password file
    (4) Load existing password file
    (5) Add a new password
    (6) Get a password
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
