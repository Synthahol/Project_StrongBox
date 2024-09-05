import base64
import logging
import os
import re
import sqlite3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Configure logging
logger = logging.getLogger(__name__)


def generate_salt() -> bytes:
    """Generate a cryptographically secure random salt."""
    try:
        return os.urandom(16)
    except Exception as e:
        logger.error(f"Error generating salt: {e}", exc_info=True)
        raise RuntimeError("Failed to generate salt.") from e


def hash_password(password: str, salt: bytes) -> bytes:
    """
    Hash a password with the provided salt using the Scrypt KDF.
    
    Args:
        password (str): The plaintext password.
        salt (bytes): The salt to use for hashing.
    
    Returns:
        bytes: The hashed password encoded in base64.
    """
    try:
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    except Exception as e:
        logger.error(f"Error hashing password: {e}", exc_info=True)
        raise RuntimeError("Failed to hash password.") from e


def verify_password(stored_password: bytes, provided_password: str, salt: bytes) -> bool:
    """
    Verify a provided password against the stored hashed password and salt.
    
    Args:
        stored_password (bytes): The stored hashed password.
        provided_password (str): The plaintext password to verify.
        salt (bytes): The salt used for hashing.
    
    Returns:
        bool: True if the password is correct, False otherwise.
    """
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    try:
        kdf.verify(provided_password.encode(), base64.urlsafe_b64decode(stored_password))
        return True
    except Exception as e:
        logger.error(f"Error verifying password: {e}", exc_info=True)
        return False


def validate_master_password(password: str) -> bool:
    """
    Validate the master password based on security requirements.
    
    Args:
        password (str): The password to validate.
    
    Returns:
        bool: True if the password meets the requirements, False otherwise.
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


def set_master_password(conn: sqlite3.Connection, master_password: str) -> None:
    """
    Set the master password in the database after validation.
    
    Args:
        conn (sqlite3.Connection): The database connection object.
        master_password (str): The master password to set.
    
    Raises:
        ValueError: If the master password does not meet security requirements.
    """
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
    except sqlite3.Error as e:
        logger.error(f"Database error setting master password: {e}", exc_info=True)
        raise
    except Exception as e:
        logger.error(f"Unexpected error setting master password: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    # Example connection to a database (replace with actual connection)
    conn = None  # Replace with actual database connection
    master_password = "my_secure_Password1!"

    try:
        set_master_password(conn, master_password)
        print("Master password set successfully.")
    except ValueError as ve:
        print(f"Validation error: {ve}")
    except sqlite3.Error as db_err:
        print(f"Database error: {db_err}")
    except Exception as e:
        print(f"Error setting master password: {e}")
