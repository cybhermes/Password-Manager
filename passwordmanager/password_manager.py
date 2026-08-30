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
        with open(path, 'wb') as f:
            f.write(self.key)

    def load_key(self, path):
        with open(path, 'rb') as f:
            self.key = f.read()

    def create_password_file(self, path, initial_values=None):
        self.password_file = path

        if initial_values is not None:
            for site, username, password, url in initial_values.items():
                self.add_password(site, username, password, url)

    def load_password_file(self, path):
        self.password_file = path

        with open("data.json", "r") as f:
            data = json.load(f)

        for site, password in data.items():
            decrypted = Fernet(self.key).decrypt(password.encode()).decode()
            data[site][password] = decrypted

        with open("data.json", "w") as f:
            json.dump(data, f, indent=4)

    def add_password(self, site, username, password, url):
        if os.path.exists("data.json"):
            with open("data.json", "r") as f:
                data = json.load(f)
        else:
            data = {}

        encrypted = Fernet(self.key).encrypt(password.encode())
        data[site] = {
            "username": username,
            "password": encrypted,
            "url": url
        }

        with open("data.json", "w") as f:
            json.dump(data, f, indent=4)
        
    def get_password(self, site):
        pass
        
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

        if choice == "1":
            path = input("Enter path: ")
            pm.create_key(path)
        elif choice == "2":
            path = input("Enter path: ")
            pm.load_key(path)
        elif choice == "3":
            path = input("Enter path: ")
            pm.create_password_file(path, password)
        elif choice == "4":
            path = input("Enter path: ")
            pm.load_password_file(path)
        elif choice == "5":
            site = input("Enter the site: ")
            username = input("Enter the username: ")
            password = getpass("Enter the password: ")
            url = input("Unter url: ")
            pm.add_password(site, username, password, url)
        elif choice == "6":
            site = input("What site do you want: ")
            print(f"Password for {site} is {pm.get_password(site)}")
        elif choice == "q":
            done = True
        else:
            print("Invalid choice!")

if __name__ == "__main__":
    main()