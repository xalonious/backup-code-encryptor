import base64
import os
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import InvalidToken

SALT_LENGTH = 16
ITERATIONS = 100_000
HASH_ALGORITHM = hashes.SHA256
KEY_LENGTH = 32

def generate_salt() -> bytes:
    return os.urandom(SALT_LENGTH)

def get_key(password: str, salt: bytes) -> bytes:
    password = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=HASH_ALGORITHM(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encrypt_file(filename: str, password: str):
    salt = generate_salt()
    key = get_key(password, salt)
    cipher_suite = Fernet(key)
    try:
        with open(filename, 'rb') as file:
            file_data = file.read()
        encrypted_data = cipher_suite.encrypt(file_data)
        with open(filename, 'wb') as file:
            file.write(salt + encrypted_data)
        print(f"Encrypted {filename} successfully.")
    except IOError as e:
        print(f"Error encrypting file {filename}: {e}")

def decrypt_file(filename: str, password: str) -> bool:
    try:
        with open(filename, 'rb') as file:
            salt = file.read(SALT_LENGTH)
            encrypted_data = file.read()
        key = get_key(password, salt)
        cipher_suite = Fernet(key)
        try:
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            with open(filename, 'wb') as file:
                file.write(decrypted_data)
            print(f"Decrypted {filename} successfully.")
            return True
        except InvalidToken:
            print(f"Invalid password for file {filename}.")
            return False
    except IOError as e:
        print(f"Error decrypting file {filename}: {e}")
        return False

def process_files(action: str, service: str, password: str):
    files = {
        'discord': 'discord_backup.txt',
        'roblox': 'roblox_backup.txt',
        'snapchat': 'snapchat_backup.txt',
        'epic': 'epic_backup.txt',
        'github': 'github_backup.txt',
        'namecheap': 'namecheap_backup.txt',
    }
    
    if service == 'all':
        services = files.keys()
    else:
        services = [service]
    
    for svc in services:
        filename = files.get(svc)
        if filename:
            if action == 'encrypt':
                encrypt_file(filename, password)
            elif action == 'decrypt':
                decrypt_file(filename, password)

def main():
    action = input("Do you want to encrypt or decrypt? ").strip().lower()
    service = input("Which service do you want to encrypt or decrypt? ").strip().lower()
    if action not in ['encrypt', 'decrypt']:
        print("Invalid action. Please enter 'encrypt' or 'decrypt'.")
        return
    
    password = getpass("Enter the password: ")
    process_files(action, service, password)

if __name__ == "__main__":
    main()
    input("Press Enter to exit...")
