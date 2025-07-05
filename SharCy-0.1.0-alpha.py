# SharCy 0.1.0 Alpha (20250705 PEP)
# A simple encryption tool for text files using Fernet symmetric encryption.
# This script is designed to run on Linux and Windows, with USB support for file storage.

import os
import sys
import getpass
import secrets
import base64
import hashlib
import hmac
import logging
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def validate_password(password: str) -> bool:
    """Validate password strength (min 12 chars, mixed types)."""
    if len(password) < 12:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    return has_upper and has_lower and has_digit and has_special

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def derive_hmac_key(password: str, salt: bytes) -> bytes:
    """Derive a key for HMAC from the password and salt (separate from encryption key)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt + b"HMAC",
        iterations=600_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def compute_file_hmac(file_path: str, key: bytes) -> bytes:
    """Compute HMAC-SHA256 of a file's contents for integrity verification."""
    h = hmac.new(key, digestmod=hashlib.sha256)
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.digest()
    except Exception as e:
        logger.error(f"Failed to compute HMAC for {file_path}: {e}")
        raise

def secure_delete(file_path: str) -> None:
    """Securely delete a file by overwriting it with random data.
    Note: On SSDs and some filesystems, true secure deletion is not guaranteed."""
    if not os.path.exists(file_path):
        return
    file_size = os.path.getsize(file_path)
    try:
        with open(file_path, 'r+b') as f:
            f.write(secrets.token_bytes(file_size))
        os.remove(file_path)
    except Exception as e:
        logger.error(f"Failed to securely delete {file_path}: {e}")
        raise

def check_usb_mounted(usb_path: str) -> bool:
    """Check if USB path is valid and mounted."""
    return os.path.ismount(usb_path) or os.path.exists(usb_path)

def save_salt_with_hmac(salt: bytes, salt_file: str, hmac_key: bytes) -> None:
    """Save salt with HMAC for integrity verification."""
    with open(salt_file, 'wb') as f:
        f.write(salt)
    salt_hmac = compute_file_hmac(salt_file, hmac_key)
    with open(salt_file + '.hmac', 'wb') as f:
        f.write(salt_hmac)

def verify_salt_integrity(salt_file: str, hmac_key: bytes) -> bool:
    """Verify the integrity of the salt file using HMAC."""
    hmac_file = salt_file + '.hmac'
    if not os.path.exists(hmac_file):
        return False
    with open(hmac_file, 'rb') as f:
        stored_hmac = f.read()
    computed_hmac = compute_file_hmac(salt_file, hmac_key)
    return hmac.compare_digest(stored_hmac, computed_hmac)

def handle_permission_error(file_path: str, operation: str) -> None:
    """Handle permission errors."""
    logger.error(f"Error: Cannot {operation} {file_path}. Check USB permissions.")
    raise PermissionError(f"Cannot {operation} {file_path}")

def encrypt_text(fernet: Fernet, text: str, encrypted_file: str, created_files: set) -> None:
    """Encrypt and save text to a file."""
    try:
        encrypted = fernet.encrypt(text.encode())
        with open(encrypted_file, 'wb') as file:
            file.write(encrypted)
        logger.info(f"Encrypted text saved to {encrypted_file}")
        created_files.add(encrypted_file)
    except PermissionError:
        handle_permission_error(encrypted_file, "write to")
    except Exception as e:
        logger.error(f"Error during encryption: {e}")
        raise

def decrypt_text(fernet: Fernet, encrypted_file: str) -> None:
    """Read and decrypt text from a file."""
    try:
        with open(encrypted_file, 'rb') as file:
            encrypted = file.read()
        decrypted = fernet.decrypt(encrypted).decode()
        logger.info("Decrypted text:")
        print(decrypted)
    except PermissionError:
        handle_permission_error(encrypted_file, "read")
    except Exception as e:
        logger.error(f"Decryption failed: {e}. Wrong password or corrupted file.")
        raise

def main(created_files: set) -> bool:
    # Clear the terminal window (cross-platform)
    os.system('cls' if os.name == 'nt' else 'clear')
    print("""\n\033[1;34m                            
            ██████                               
          ███  ████████                          
          █  ░░░▒▒▒▓▓▓▓███                       
          ██  ░░░▒▒▒▓▒▓▓▓▓██                     
           █     ░░░░▒▒▒▓▓▓▓██                   
           ██     ░░░░▒▒▒▓▓▓▓██                  
            ██      ░░░░▒▒▒▓▓▓▓██                
             ██    ░░░░░▒▒▒▒▓▓▓▓██               
              ██     ░░░░▒▒▒▓▓▓▓▓█               
               █    ░░░░▒▒▒▓▓▓▓▓▓▓██             
               █    ░░░▒▒▒▒▒▒▓▓▓▓▓▓█             
              ██     ░░░░▒▒▒▓▓▓▓▓▓▓██            
              █     ░░░░▒▒▒▒▒▓▓▓▓▓▓▓█            
           ████    ░░░░░▒▒▒▒▓▓▓▓▓▓▓▓██           
       █████    ░░░░░░▒▒▒▒▒▒▒▒▓▓▓▓▓▓███████      
   ███▓▓▓▓█ ▓▓▓▓▓░░█████████████████▓▓▓▓██████                                      
\033[1;0m                                                       
\033[1;32m
              SharCy Encryption Tool
\033[0m\n""")
    try:
        # Get the directory where the binary/script is located
        base_dir = os.path.dirname(sys.executable)

        # Prompt for USB path, defaulting to binary's directory
        usb_mount_path = input(
            f"Enter USB mount path (e.g., /media/usb or D:\\) or press Enter to use {base_dir}: "
        ).strip()
        if not usb_mount_path:
            usb_mount_path = base_dir
        if not check_usb_mounted(usb_mount_path):
            logger.error(f"USB not mounted or path {usb_mount_path} does not exist.")
            return

        encrypted_file = os.path.join(usb_mount_path, 'encrypted_text.txt')
        salt_file = os.path.join(usb_mount_path, 'salt.bin')
        salt_hmac_file = salt_file + '.hmac'

        # Password input with strong validation
        while True:
            password = getpass.getpass("Enter a strong password (min 12 chars, mixed types): ")
            if not validate_password(password):
                logger.warning("Password must be at least 12 characters, with uppercase, lowercase, digits, and special characters.")
            else:
                break

        password_bytes = password.encode()
        password = None

        # Check or generate salt
        if os.path.exists(salt_file):
            # Derive HMAC key from password and salt for integrity check
            with open(salt_file, 'rb') as f:
                salt = f.read()
            hmac_key = derive_hmac_key(password_bytes.decode(), salt)
            if not verify_salt_integrity(salt_file, hmac_key):
                logger.error("Salt file tampered or corrupted.")
                return
        else:
            salt = secrets.token_bytes(16)
            hmac_key = derive_hmac_key(password_bytes.decode(), salt)
            try:
                save_salt_with_hmac(salt, salt_file, hmac_key)
                logger.info(f"Salt generated and saved to {salt_file}")
                created_files.add(salt_file)
                created_files.add(salt_hmac_file)
            except Exception as e:
                logger.error(f"Cannot write to {salt_file}. Check USB permissions. {e}")
                return

        # Derive encryption key
        key = derive_key(password_bytes.decode(), salt)
        fernet = Fernet(key)

        password_bytes = None
        key = None

        while True:
            choice = input("Choose: (1) Write encrypted text, (2) Read and decrypt text, (3) Delete encrypted file securely, (q) Quit: ").strip().lower()
            if choice == '1':
                text = input("Enter text to encrypt and save: ")
                if os.path.exists(encrypted_file):
                    overwrite = input(f"File {encrypted_file} exists. Overwrite? (y/n): ").lower()
                    if overwrite != 'y':
                        logger.info("Operation canceled.")
                        continue
                encrypt_text(fernet, text, encrypted_file, created_files)
            elif choice == '2':
                if os.path.exists(encrypted_file):
                    decrypt_text(fernet, encrypted_file)
                else:
                    logger.error(f"Encrypted file {encrypted_file} not found.")
            elif choice == '3':
                if os.path.exists(encrypted_file):
                    confirm = input(f"Securely delete {encrypted_file}? (y/n): ").lower()
                    if confirm == 'y':
                        try:
                            secure_delete(encrypted_file)
                            logger.info(f"File {encrypted_file} securely deleted.")
                            print("Warning: On SSDs and some filesystems, secure deletion may not be guaranteed.")
                            if encrypted_file in created_files:
                                created_files.remove(encrypted_file)
                        except Exception as e:
                            logger.error(f"Error during secure deletion: {e}")
                else:
                    logger.error(f"Encrypted file {encrypted_file} not found.")
            elif choice == 'q':
                return False
            else:
                logger.warning("Invalid option.")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return True  # Abnormal exit
    except KeyboardInterrupt:
        print("\nOperation cancelled by user (Ctrl+C). Exiting securely.")
        return True  # Abnormal exit    
    finally:
        # Explicitly clear sensitive variables
        if 'password_bytes' in locals() and password_bytes is not None:
            try:
                if isinstance(password_bytes, (bytes, bytearray)):
                    pb = bytearray(password_bytes)
                    for i in range(len(pb)):
                        pb[i] = 0
            except Exception:
                pass  
            password_bytes = None
        password = None
        key = None
        salt = None
        hmac_key = None
        fernet = None

if __name__ == "__main__":
    created_files = set()
    abnormal_exit = main(created_files)
    # Clear the terminal window (cross-platform)        
    os.system('cls' if os.name == 'nt' else 'clear')
    print("🦈")
    if abnormal_exit:
        # Securely delete files created in this session
        for file_path in created_files:
            try:
                secure_delete(file_path)
                print(f"Session file {file_path} securely deleted.")
            except Exception as e:
                print(f"Failed to securely delete {file_path}: {e}")