import base64
import logging
import os
import re

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Configure logging
logger = logging.getLogger(__name__)


# Generate salt
def generate_salt() -> bytes:
    try:
        return os.urandom(16)
    except Exception as e:
        logger.error(f"Error generating salt: {e}")
        return None


# Hash password with salt
def hash_password(password: str, salt: bytes) -> bytes:
    try:
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    except Exception as e:
        logger.error(f"Error hashing password: {e}")
        return None


# Verify password
def verify_password(
    stored_password: bytes, provided_password: str, salt: bytes
) -> bool:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    try:
        kdf.verify(
            provided_password.encode(), base64.urlsafe_b64decode(stored_password)
        )
        return True
    except Exception as e:
        logger.error(f"Error verifying password: {e}")
        return False


# Validate master password
def validate_master_password(password: str) -> bool:
    """
    Validate the master password based on security requirements:
    - Minimum 8 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 number
    - At least 1 special character
    """
    if len(password) < 8:
        logger.error("Password must be at least 8 characters long.")
        return False
    if not re.search(r"[A-Z]", password):
        logger.error("Password must contain at least one uppercase letter.")
        return False
    if not re.search(r"[a-z]", password):
        logger.error("Password must contain at least one lowercase letter.")
        return False
    if not re.search(r"[0-9]", password):
        logger.error("Password must contain at least one number.")
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        logger.error("Password must contain at least one special character.")
        return False

    return True


# Set the master password
def set_master_password(conn, master_password: str):
    # Validate the master password
    if not validate_master_password(master_password):
        logger.error("Master password validation failed.")
        raise ValueError("Master password does not meet security requirements.")

    try:
        salt = generate_salt()
        hashed_password = hash_password(master_password, salt)
        with conn:
            conn.execute(
                "INSERT INTO master_password (salt, password) VALUES (?, ?)",
                (salt, hashed_password),
            )
        logger.info("Master password set in the database.")
    except Exception as e:
        logger.error(f"Error setting master password: {e}")
        raise e


# Usage example
if __name__ == "__main__":
    # Example connection to a database (replace with actual connection)
    conn = None  # Replace with actual database connection
    master_password = "my_secure_Password1!"

    try:
        set_master_password(conn, master_password)
        print("Master password set successfully.")
    except ValueError as ve:
        print(f"Validation error: {ve}")
    except Exception as e:
        print(f"Error setting master password: {e}")
