import os
import hashlib
import base64

def hash_password(password):
    """Hash a password using PBKDF2."""
    salt = os.urandom(16)  # Generate a random salt
    hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.b64encode(salt + hash).decode()  # Combine salt and hash

def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user."""
    stored_password_bytes = base64.b64decode(stored_password.encode())
    salt = stored_password_bytes[:16]
    stored_hash = stored_password_bytes[16:]
    
    new_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode(), salt, 100000)
    return new_hash == stored_hash

def main():
    password = input("Enter a password to hash: ")
    hashed_password = hash_password(password)
    print(f"Hashed Password: {hashed_password}")

    # Verify the password
    password_to_verify = input("Enter the password to verify: ")
    is_verified = verify_password(hashed_password, password_to_verify)
    print(f"Password Verified: {is_verified}")

if __name__ == "__main__":
    main()
