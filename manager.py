import base64
import os
from getpass import getpass
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from colorama import init, Fore, Style

init(autoreset=True)

SALT_LENGTH = 16
ITERATIONS = 100_000
HASH_ALGORITHM = hashes.SHA256
KEY_LENGTH = 32
MAGIC = b"FENC1"  

def print_question(message: str):
    print(Fore.MAGENTA + "[?] " + message + Style.RESET_ALL)

def print_action(message: str):
    print(Fore.MAGENTA + "[✔️] " + message + Style.RESET_ALL)

def print_error(message: str):
    print(Fore.RED + "[!] " + message + Style.RESET_ALL)

def generate_salt() -> bytes:
    return os.urandom(SALT_LENGTH)

def get_key(password: str, salt: bytes) -> bytes:
    password_bytes = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=HASH_ALGORITHM(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    return key

def is_encrypted_file(filename: str) -> bool:
    try:
        with open(filename, "rb") as f:
            return f.read(len(MAGIC)) == MAGIC
    except IOError:
        return False

def encrypt_file(filename: str, password: str):
    if is_encrypted_file(filename):
        print_error(f"{filename} already appears to be encrypted. Skipping.")
        return

    salt = generate_salt()
    key = get_key(password, salt)
    cipher_suite = Fernet(key)

    try:
        with open(filename, 'rb') as file:
            file_data = file.read()

        encrypted_data = cipher_suite.encrypt(file_data)

        with open(filename, 'wb') as file:
            file.write(MAGIC + salt + encrypted_data)

        print_action(f"Encrypted {filename} successfully.")
    except IOError as e:
        print_error(f"Error encrypting file {filename}: {e}")

def decrypt_file(filename: str, password: str) -> bool:
    try:
        with open(filename, 'rb') as file:
            header = file.read(len(MAGIC))
            if header != MAGIC:
                print_error(f"{filename} does not appear to be encrypted (missing header).")
                return False

            salt = file.read(SALT_LENGTH)
            encrypted_data = file.read()

        key = get_key(password, salt)
        cipher_suite = Fernet(key)

        try:
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            with open(filename, 'wb') as file:
                file.write(decrypted_data)
            print_action(f"Decrypted {filename} successfully.")
            return True
        except InvalidToken:
            print_error(f"Invalid password for file {filename}.")
            return False
    except IOError as e:
        print_error(f"Error decrypting file {filename}: {e}")
        return False

def process_files(action: str, service: str, password: str):
    files = {
        'discord': 'discord_backup.txt',  # Adjust file names as needed
        'roblox': 'roblox_backup.txt',
        'snapchat': 'snapchat_backup.txt',
        'epic': 'epic_backup.txt',
        'github': 'github_backup.txt',
        'namecheap': 'namecheap_backup.txt',
        'steam': 'steam_backup.txt',
    }

    if service == 'all':
        services = files.keys()
    else:
        services = [service]

    for svc in services:
        filename = files.get(svc)
        if not filename:
            print_error(f"No file found for service: {svc}")
            continue

        if action == 'encrypt':
            if is_encrypted_file(filename):
                print_error(f"{filename} already appears to be encrypted. Skipping.")
            else:
                encrypt_file(filename, password)

        elif action == 'decrypt':
            if not is_encrypted_file(filename):
                print_error(f"{filename} does not appear to be encrypted. Skipping.")
            else:
                decrypt_file(filename, password)

def main():
    valid_actions = ['encrypt', 'decrypt']
    valid_services = ['discord', 'roblox', 'snapchat', 'epic', 'github', 'namecheap', 'steam', 'all']  # Add/remove services as needed

    action = input(Fore.MAGENTA + "[?] Do you want to encrypt or decrypt? " + Style.RESET_ALL).strip().lower()
    while action not in valid_actions:
        print_error("Invalid action. Please enter 'encrypt' or 'decrypt'.")
        action = input(Fore.MAGENTA + "[?] Do you want to encrypt or decrypt? " + Style.RESET_ALL).strip().lower()

    service = input(Fore.MAGENTA + "[?] Which service do you want to encrypt or decrypt? " + Style.RESET_ALL).strip().lower()
    while service not in valid_services:
        print_error("Invalid service. Please enter one of the following:")
        print_error(", ".join(valid_services))
        service = input(Fore.MAGENTA + "[?] Which service do you want to encrypt or decrypt? " + Style.RESET_ALL).strip().lower()

    password = getpass(Fore.MAGENTA + "[?] Enter the password: " + Style.RESET_ALL)
    process_files(action, service, password)

if __name__ == "__main__":
    main()
    input(Fore.MAGENTA + "[?] Press Enter to exit..." + Style.RESET_ALL)
