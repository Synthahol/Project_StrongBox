# master_password.py

import base64
import hashlib
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


def verify_password(
    stored_password: bytes, provided_password: str, salt: bytes
) -> bool:
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
        kdf.verify(
            provided_password.encode(), base64.urlsafe_b64decode(stored_password)
        )
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


def hash_identifier(identifier: str) -> str:
    """
    Hash the user identifier (email) using SHA-256.

    Args:
        identifier (str): The user identifier to hash.

    Returns:
        str: The hashed identifier.
    """
    normalized_identifier = identifier.strip().lower()
    return hashlib.sha256(normalized_identifier.encode("utf-8")).hexdigest()


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


def change_master_password(
    conn: sqlite3.Connection, current_password: str, new_password: str
) -> None:
    """
    Change the master password in the database after verifying the current password.

    Args:
        conn (sqlite3.Connection): The database connection object.
        current_password (str): The current master password.
        new_password (str): The new master password to set.

    Raises:
        ValueError: If the current password is incorrect or the new password does not meet requirements.
    """
    try:
        cursor = conn.execute("SELECT salt, password FROM master_password LIMIT 1")
        row = cursor.fetchone()
        if not row:
            logger.error("Master password not set in the database.")
            raise ValueError("Master password not set in the database.")

        salt, stored_password = row
        if not verify_password(stored_password, current_password, salt):
            logger.error("Current master password verification failed.")
            raise ValueError("Current master password is incorrect.")

        if not validate_master_password(new_password):
            logger.error("New master password validation failed.")
            raise ValueError("New master password does not meet security requirements.")

        new_salt = generate_salt()
        new_hashed_password = hash_password(new_password, new_salt)

        with conn:
            conn.execute(
                "UPDATE master_password SET salt = ?, password = ?",
                (new_salt, new_hashed_password),
            )
        logger.info("Master password updated successfully.")
    except sqlite3.Error as e:
        logger.error(f"Database error changing master password: {e}", exc_info=True)
        raise
    except Exception as e:
        logger.error(f"Unexpected error changing master password: {e}", exc_info=True)
        raise


def change_user_identifier(
    conn: sqlite3.Connection, current_password: str, new_email: str
) -> None:
    """
    Change the user's email address used for 2FA after verifying the master password.

    Args:
        conn (sqlite3.Connection): The database connection object.
        current_password (str): The current master password.
        new_email (str): The new email address to set.

    Raises:
        ValueError: If the current password is incorrect or the new email is invalid.
    """
    # Validate new email format
    if not re.match(r"[^@]+@[^@]+\.[^@]+", new_email):
        logger.error("Invalid email format provided.")
        raise ValueError("Invalid email format.")

    try:
        cursor = conn.execute("SELECT salt, password FROM master_password LIMIT 1")
        row = cursor.fetchone()
        if not row:
            logger.error("Master password not set in the database.")
            raise ValueError("Master password not set in the database.")

        salt, stored_password = row
        if not verify_password(stored_password, current_password, salt):
            logger.error("Master password verification failed.")
            raise ValueError("Master password is incorrect.")

        # Hash the new email identifier
        hashed_new_email = hash_identifier(new_email)

        # Update the user_identifier in two_factor_auth table
        current_email = get_current_email(conn)
        hashed_current_email = hash_identifier(current_email)
        with conn:
            conn.execute(
                "UPDATE two_factor_auth SET user_identifier = ? WHERE user_identifier = ?",
                (hashed_new_email, hashed_current_email),
            )
            conn.execute(
                "UPDATE user_data SET email = ? WHERE email = ?",
                (new_email, current_email),
            )
        logger.info("User email updated successfully.")
    except sqlite3.Error as e:
        logger.error(f"Database error changing user identifier: {e}", exc_info=True)
        raise
    except Exception as e:
        logger.error(f"Unexpected error changing user identifier: {e}", exc_info=True)
        raise


def get_current_email(conn: sqlite3.Connection) -> str:
    """
    Retrieve the current email address (user identifier) from the database.

    Args:
        conn (sqlite3.Connection): The database connection object.

    Returns:
        str: The current email address.

    Raises:
        ValueError: If no email is set.
    """
    try:
        cursor = conn.execute("SELECT email FROM user_data LIMIT 1")
        row = cursor.fetchone()
        if not row or not row[0]:
            logger.error("No email set in the database.")
            raise ValueError("No email set in the database.")
        return row[0]
    except sqlite3.Error as e:
        logger.error(f"Database error retrieving current email: {e}", exc_info=True)
        raise
    except Exception as e:
        logger.error(f"Unexpected error retrieving current email: {e}", exc_info=True)
        raise
