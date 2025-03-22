import pathlib
import secrets
import os
import base64
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def generate_salt(size=16):
    return secrets.token_bytes(size)

def derive_key(salt):
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(b"default_password")  # Using a fixed default password

def load_salt():
    return open("salt.salt", "rb").read()

def generate_key(salt_size=16, load_existing_salt=True):
    if load_existing_salt and os.path.exists("salt.salt"):
        salt = load_salt()
    else:
        salt = generate_salt(salt_size)
        with open("salt.salt", "wb") as salt_file:
            salt_file.write(salt)
    derived_key = derive_key(salt)
    return base64.urlsafe_b64encode(derived_key)

def encrypt(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
    
    # Store original file extension in the encrypted data
    ext = os.path.splitext(filename)[1].encode()
    encrypted_data = f.encrypt(ext + b"::" + file_data)
    
    encrypted_filename = os.path.splitext(filename)[0]  # Keep original name
    os.rename(filename, encrypted_filename)
    with open(encrypted_filename, "wb") as file:
        file.write(encrypted_data)

def decrypt(filename, key):
    filename = str(filename)
    f = Fernet(key)
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    try:
        decrypted_data = f.decrypt(encrypted_data)
    except cryptography.fernet.InvalidToken:
        print("[!] Invalid token, decryption failed")
        return
    
    # Extract original extension
    ext, file_data = decrypted_data.split(b"::", 1)
    ext = ext.decode()
    
    original_filename = filename + ext  # Restore original extension
    
    with open(original_filename, "wb") as file:
        file.write(file_data)
    os.remove(filename)

def encrypt_folder(foldername, key):
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"[*] Encrypting {child}")
            encrypt(child, key)
        elif child.is_dir():
            encrypt_folder(child, key)

def decrypt_folder(foldername, key):
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"[*] Decrypting {child}")
            decrypt(child, key)
        elif child.is_dir():
            decrypt_folder(child, key)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="File Encryptor/Decryptor without Password Prompt")
    parser.add_argument("path", help="Path to encrypt/decrypt, can be a file or a folder")
    parser.add_argument("-e", "--encrypt", action="store_true", help="Encrypt the file/folder")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt the file/folder")
    args = parser.parse_args()
    
    key = generate_key()
    
    if args.encrypt and args.decrypt:
        raise TypeError("Please specify only one operation: encrypt or decrypt.")
    elif args.encrypt:
        if os.path.isfile(args.path):
            encrypt(args.path, key)
        elif os.path.isdir(args.path):
            encrypt_folder(args.path, key)
    elif args.decrypt:
        if os.path.isfile(args.path):
            decrypt(args.path, key)
        elif os.path.isdir(args.path):
            decrypt_folder(args.path, key)
    else:
        raise TypeError("Please specify whether you want to encrypt or decrypt the file.")
