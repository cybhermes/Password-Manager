from cryptography.fernet import Fernet, InvalidToken
from getpass import getpass
import json
import os
import secrets
import string
from argon2.low_level import hash_secret_raw, Type
import base64
import tempfile

class PasswordManager:

    def __init__(self):
        self._key = None
        self.password_file = None
        self.password_dict = {}
        self.salt = None
        self.unlocked = False

        # Argon2 parameters
        self.time_cost = 3
        self.memory_cost = 65536
        self.parallelism = 4
        self.hash_len = 32

    def derive_key(self, master_password):
        key = hash_secret_raw(secret=master_password.encode(), 
            salt=self.salt, time_cost=self.time_cost, 
            memory_cost=self.memory_cost, 
            parallelism=self.parallelism, 
            hash_len=self.hash_len, type=Type.ID)

        return base64.urlsafe_b64encode(key)

    def create_master_password(self):
        master_password = getpass("Create master password (at least 12 characters): ")

        if len(master_password) < 12:
            print("Master password must be at least 12 characters")
            return False

        confirm_password = getpass("Confirm master password: ")

        if master_password != confirm_password:
            print("Passwords do not match")
            return False

        if not master_password:
            print("Master password cannot be empty")
            return False

        self.salt = secrets.token_bytes(16)
        self._key = self.derive_key(master_password)

        print("Master password created successfully")
        return True

    def change_master_password(self):
        if not self.is_unlocked():
            print("Vault is locked")
            return False

        new_password = getpass("Enter new master password (at least 12 characters): ")

        if len(new_password) < 12:
            print("Masster password must be at least 12 characters")
            return False

        confirm_password = getpass("Confirm new master password: ")

        if new_password != confirm_password:
            print("Passwords do not match")
            return False

        new_salt = secrets.token_bytes(16)

        new_key_bytes = hash_secret_raw(secret=new_password.encode("utf-8"), salt=new_salt, time_cost=self.time_cost, memory_cost=self.memory_cost, parallelism=self.parallelism, hash_len=self.hash_len, type=Type.ID)

        new_key = base64.urlsafe_b64encode(new_key_bytes)

        vault_data = {
            "entries": self.password_dict
            }

        plain_text = json.dumps(vault_data).encode("utf-8")
        encrypted_vault = Fernet(new_key).encrypt(plain_text).decode("utf-8")

        data = {
            "version": 1,
            "kdf": {
                "algorithm": "argon2id",
                "time_cost": self.time_cost,
                "memory_cost": self.memory_cost,
                "parallelism": self.parallelism,
                "hash_len": self.hash_len
            },
            "salt": base64.b64encode(new_salt).decode("ascii"),
            "cipher": {"algorithm": "fernet"},
            "vault": encrypted_vault
        }

        try:
            self._write_vault(data)
        except OSError as exc:
            print(f"Failed to change master password: {exc}")
            return False

        self._key = new_key
        self.salt = new_salt

        print("Master password changed seccessfully")
        return True

    def _write_vault(self, data):
        directory = os.path.dirname(os.path.abspath(self.password_file))

        fd, temp_path = tempfile.mkstemp(dir=directory, prefix=".vault_", suffix=".tmp")

        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
                f.flush()
                os.fsync(f.fileno()) 
            os.replace(temp_path, self.password_file)
        except Exception:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise

    def save_vault(self):
        if self.password_file is None:
            print("No vault loaded")
            return False

        if not self.is_unlocked():
            print("Vault is locked")
            return False

        try:
            vault_data = {
                "entries": self.password_dict
            }

            plain_text = json.dumps(vault_data).encode("utf-8")
            encrypted_vault = Fernet(self._key).encrypt(plain_text).decode()

            data = {
                "version": 1,
                "kdf": {
                    "algorithm": "argon2id",
                    "time_cost": self.time_cost,
                    "memory_cost": self.memory_cost,
                    "parallelism": self.parallelism,
                    "hash_len": self.hash_len
                },
                "salt": base64.b64encode(self.salt).decode("ascii"),
                "cipher": {
                    "algorithm": "fernet"
                },
                "vault": encrypted_vault
            }

            self._write_vault(data)
            return True
        except (OSError, TypeError, ValueError) as exc:
            print(f"Failed to save vault: {exc}")
            return False

    def is_unlocked(self):
        return self.unlocked and self._key is not None

    def lock_vault(self):
        self._key = None
        self.password_dict.clear()
        self.unlocked = False

        print("Vault locked")

    def create_password_file(self, path):
        if os.path.exists(path):
            print("A vault with this name already exists")
            return False

        self.password_file = path
        self.password_dict = {}

        if not self.create_master_password():
            self.password_file = None
            return False

        self.unlocked = True

        if not self.save_vault():
            self.lock_vault()
            self.password_file = None
            self.salt = None
            print("Failed to creates vault")
            return False

        print("Password file created successfully")
        return True

    def load_password_file(self, path):
        if not os.path.exists(path):
            print("Vault does not exist")
            return False

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if data.get("version") != 1:
                print("Unsupported vault version")
                return False

            cipher = data.get("cipher")

            if not isinstance(cipher, dict):
                print("Invalid cipher configuration")
                return False

            if cipher.get("algorithm") != "fernet":
                print("Unsupported encryption algorithm")
                return False

            kdf = data["kdf"]
            if kdf["algorithm"] != "argon2id":
                print("Unsupported KDF")
                return False

            time_cost = kdf["time_cost"]
            memory_cost = kdf["memory_cost"]
            parallelism = kdf["parallelism"]
            hash_len = kdf["hash_len"]

            if not 1 <= time_cost <= 10:
                raise ValueError("Invalid time_cost")
            if not 8192 <= memory_cost <= 1048576:
                raise ValueError("Invalid memory_cost")
            if not 1 <= parallelism <= 16:
                raise ValueError("Invalid parallelism")
            if not 16 <= hash_len <= 64:
                raise ValueError("Invalid hash_len")

            self.time_cost = time_cost
            self.memory_cost = memory_cost
            self.parallelism = parallelism
            self.hash_len = hash_len

            try:
                self.salt = base64.b64decode(data["salt"], validate=True)
            except (ValueError, TypeError):
                print("Invalid salt")
                return False

            if len(self.salt) != 16:
                print("Invalid salt length")
                return False

            master_password = getpass("Enter master password: ")
            self._key = self.derive_key(master_password)

            encrypted_vault = data["vault"]
            plain_text = Fernet(self._key).decrypt(encrypted_vault.encode())

            vault_data = json.loads(plain_text.decode())
            if not isinstance(vault_data, dict):
                raise ValueError("Invalid vault data")

            if "entries" not in vault_data:
                raise ValueError("Missing vault entries")

            if not isinstance(vault_data["entries"], dict):
                raise ValueError("Invalid vault entries")
            
            self.password_dict = vault_data["entries"]
            self.password_file = path
            self.unlocked = True

            print("Vault unlocked")
            return True
        
        except InvalidToken:
            self._key = None
            self.password_dict ={}
            self.salt = None
            self.password_file = None
            self.unlocked = False

            print("Incorrect master password")
            return False
        
        except (KeyError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
            self._key = None
            self.password_dict ={}
            self.salt = None
            self.password_file = None
            self.unlocked = False

            print("Invalid or corrupted vault")
            return False

    def generate_password(self, length=16):
        if type(length) is not int:
            raise TypeError("Password length must be an integer")

        if not 8 <= length <= 128:
            raise ValueError("Password length must be between 4 and 128")

        character_sets = [
            string.ascii_uppercase,
            string.ascii_lowercase,
            string.digits,
            string.punctuation
        ]

        password = [
            secrets.choice(characters)
            for characters in character_sets
        ]

        all_characters = "".join(character_sets)

        password.extend(
            secrets.choice(all_characters)
            for _ in range(length - len(password))
        )

        secrets.SystemRandom().shuffle(password)

        return "".join(password)

    def add_password(self, site, username, password, url):
        if not self.is_unlocked():
            print("Vault is locked")
            return False

        if site in self.password_dict:
            print(f"A password for {site} already exists")
            return False

        if not isinstance(site, str) or not site.strip():
            print("Site cannot be empty")
            return False

        if not isinstance(username, str) or not username.strip():
            print("Username cannot be empty")
            return False

        if not isinstance(password, str) or not password:
            print("Password cannot be empty")
            return False

        if not isinstance(url, str):
            print("URL must be a string")
            return False

        site = site.strip()
        username = username.strip()
        url = url.strip()

        self.password_dict[site] = {
            "username": username,
            "password": password,
            "url": url
        }

        if self.save_vault():
            print(f"Password for {site} added successfully")
            return True

        return False

    def delete_password(self, site):
        if not self.is_unlocked():
            print("Vault is locked")
            return

        if site not in self.password_dict:
            print(f"No password found for {site}")
            return

        del self.password_dict[site]
        self.save_vault()
        print(f"Password for {site} deleted successfully")

    def update_password(self, site, new_password):
        if not self.is_unlocked():
            print("Vault is locked")
            return False

        if site not in self.password_dict:
            print(f"No password found for {site}")
            return False
        
        if not isinstance(new_password, str) or not new_password:
            print("Password cannot be empty")
            return False

        self.password_dict[site]["password"] = new_password

        if self.save_vault():
            print(f"Password for {site} updated successfully")
            return True

        return False

    def get_password(self, site):
        if not self.is_unlocked():
            print("Vault is locked")
            return None

        if site not in self.password_dict:
            print(f"No password found for {site}")
            return None

        return self.password_dict[site]["password"]

    def list_passwords(self):
        if not self.is_unlocked():
            print("Vault is locked")
            return False

        if not self.password_dict:
            print("Vault is empty")
            return True

        print("Stored accounts:")

        for site, data in self.password_dict.items():
            print(f"- {site} ({data['username']})")

        return True

    
