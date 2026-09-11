from cryptography.fernet import Fernet, InvalidToken
from getpass import getpass
import json
import os
import secrets
import string
from argon2.low_level import hash_secret_raw, Type
import base64

class PasswordManager:

    def __init__(self):
        self.key = None
        self.password_file = None
        self.password_dict = {}
        self.salt = None

        # Argon2 parameters
        self.time_cost = 3
        self.memory_cost = 65536
        self.parallelism = 4
        self.hash_len = 32

    def derive_key(self, master_password):
        key = hash_secret_raw(secret=master_password.encode(), salt=self.salt, time_cost=self.time_cost, memory_cost=self.memory_cost, parallelism=self.parallelism, hash_len=self.hash_len, type=Type.ID)

        return base64.urlsafe_b64encode(key)

    def create_master_passwoord(self):
        master_password = getpass("Create master password: ")
        confirm_password = getpass("Confirm master password: ")

        if master_password != confirm_password:
            print("Passwords do not match")
            return False

        if not master_password:
            print("Master password cannot be empty")
            return False

        self.salt = secrets.token_bytes(16)
        self.key = self.derive_key(master_password)

        print("Master password created successfully")
        return True

    def save_vault(self):
        if self.password_file is None:
            print("No password file loaded")
            return False

        if self.key is None:
            print("Vault is locked")
            return False

        data = {
            "kdf": {
                "algorithm": "argon2id",
                "time_cost": self.time_cost,
                "memory_cost": self.memory_cost,
                "parallelism": self.parallelism,
                "hash_len": self.hash_len
            },
            "salt": base64.b64encode(self.salt).decode(),
            "verification": Fernet(self.key).encrypt(b"PASSWORD_MANAGER_VAULT").decode(),
            "entries": self.password_dict
        }

        with open(self.password_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

        return True

    def create_password_file(self, path, initial_values=None):
        if os.path.exists(path):
            print("A vault with this name already exists")
            return False

        self.password_file = path
        self.password_dict = {}

        if not self.create_master_passwoord():
            self.password_file = None
            return False

        self.save_vault()
        print("Password file created successfully")
        return True

    def load_password_file(self, path):
        if not os.path.exists(path):
            print("Vault does not exist")
            return False

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            kdf = data["kdf"]

            self.time_cost = kdf["time_cost"]
            self.memory_cost = kdf["memory_cost"]
            self.parallelism = kdf["parallelism"]
            self.hash_len = kdf["hash_len"]

            self.salt = base64.b64decode(data["salt"])

            master_password = getpass("Enter master password: ")
            self.key = self.derive_key(master_password)
            verification = data["verification"]
            Fernet(self.key).decrypt(verification.encode())

            self.password_dict = data["entries"]
            self.password_file = path
                
            print("Vault loaded")
            return True
        
        except InvalidToken:
            print("Incorrect master password")
            self.key = None
            return False
        
        except (KeyError, ValueError, json.JSONDecodeError):
            print("Invalid or corrupted vault")
            self.key = None
            return False

    def generate_password(self, length=16):
        character_sets = [string.ascii_uppercase, string.ascii_lowercase, string.digits, string.punctuation]

        if length < len(character_sets):
            raise ValueError("Password length is too short for the selected character sets")

        password = [secrets.choice(characters) for characters in character_sets]

        all_characters = ''.join(character_sets)
        password += [secrets.choice(all_characters) for _ in range(length - len(password))]

        secrets.SystemRandom().shuffle(password)

        return ''.join(password)

    def add_password(self, site, username, password, url):
        if self.key is None:
            print("Vault is locked")
            return

        encrypted = Fernet(self.key).encrypt(password.encode()).decode()

        self.password_dict[site] = {
            "username": username,
            "password": encrypted,
            "url": url
        }

        self.save_vault()
        print(f"Password for {site} added successfully")

    def delete_password(self, site):
        if self.key is None:
            print("Vault is locked")
            return

        if site not in self.password_dict:
            print(f"No password found for {site}")
            return

        del self.password_dict[site]
        self.save_vault()
        print(f"Password for {site} deleted successfully")

    def update_password(self, site, new_password):
        if self.key is None:
            print("Vault is locked")
            return

        if site not in self.password_dict:
            print(f"No password found for {site}")
            return

        encrypted = Fernet(self.key).encrypt(new_password.encode()).decode()
        self.password_dict[site]["password"] = encrypted
        self.save_vault()
        print(f"Password for {site} updated successfully")

    def get_password(self, site):
        if self.key is None:
            print("Vault is locked")
            return None

        if site not in self.password_dict:
            print(f"No password found for {site}")
            return None

        encrypted = self.password_dict[site]["password"]

        try:
            return Fernet(self.key).decrypt(encrypted.encode()).decode()
        except InvalidToken:
            print("Unable to decrypt password")
            return None
