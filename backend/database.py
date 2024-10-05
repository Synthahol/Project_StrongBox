# backend/database.py

"""This module contains functions for managing the SQLite database."""

import hashlib
import logging
import os
import re
import sqlite3
from typing import List, Tuple

import bcrypt
import keyring
from cryptography.fernet import Fernet

from backend.config import DATABASE_DIR

# Configure logging
logger = logging.getLogger(__name__)

# Constants
SERVICE_ID = "my_fortalice_app"
DATABASE_NAME = "UserDatabase"
DATABASE_PATH = os.path.join(DATABASE_DIR, f"{DATABASE_NAME}.db")
_cipher_suite = None


def get_cipher_suite() -> Fernet:
    """Define the cipher suite for encrypting and decrypting data."""
    global _cipher_suite
    if _cipher_suite is None:
        key = manage_encryption_key(DATABASE_NAME)
        key_hash = hashlib.sha256(key).hexdigest()
        logger.debug(f"Encryption key used (hash): {key_hash}")
        _cipher_suite = Fernet(key)
    return _cipher_suite


def hash_identifier(identifier: str) -> str:
    """Compute a hash of the identifier for consistent lookup."""
    normalized_identifier = identifier.strip().lower()
    return hashlib.sha256(normalized_identifier.encode("utf-8")).hexdigest()


def manage_encryption_key(database_name: str) -> bytes:
    """Load or generate an encryption key stored securely using keyring."""
    key_name = f"{database_name}_KEY"
    encryption_key = keyring.get_password(SERVICE_ID, key_name)
    if encryption_key:
        logger.info(f"Encryption key for {database_name} loaded successfully.")
        return encryption_key.encode()
    else:
        encryption_key = Fernet.generate_key().decode()
        keyring.set_password(SERVICE_ID, key_name, encryption_key)
        logger.info(f"New encryption key generated and stored for {database_name}.")
        return encryption_key.encode()


def encrypt_data(data: str) -> str:
    """Encrypt data using the cipher suite."""
    try:
        cipher_suite = get_cipher_suite()
        encrypted = cipher_suite.encrypt(data.encode()).decode()
        logger.debug("Data encrypted successfully.")
        return encrypted
    except Exception as e:
        logger.error(f"Error encrypting data: {e}")
        raise Exception("Encryption failed.") from e


def decrypt_data(encrypted_data: str) -> str:
    """Decrypt data using the cipher suite."""
    try:
        cipher_suite = get_cipher_suite()
        decrypted = cipher_suite.decrypt(encrypted_data.encode()).decode()
        logger.debug("Data decrypted successfully.")
        return decrypted
    except Exception as e:
        logger.error(f"Error decrypting data: {e}")
        raise Exception("Decryption failed.") from e


def create_connection() -> sqlite3.Connection:
    """Create and return a connection to the SQLite database."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        logger.info("Created connection to database.")
        return conn
    except sqlite3.Error as e:
        logger.error(f"Error creating database connection: {e}")
        return None


def initialize_db(conn: sqlite3.Connection, key_id: str) -> None:
    """
    Initialize the database with necessary tables.

    Args:
        conn (sqlite3.Connection): The database connection object.
        key_id (str): Identifier for encryption keys (if applicable).
    """
    try:
        with conn:
            # Create master_password table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS master_password (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    salt BLOB NOT NULL,
                    password BLOB NOT NULL
                )
            """)
            # Create two_factor_auth table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS two_factor_auth (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_identifier TEXT NOT NULL,
                    secret BLOB NOT NULL
                )
            """)
            # Create user_data table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS user_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL
                )
            """)
            # Create passwords table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    UNIQUE(service, username)
                )
            """)
        logger.info("Initialized database.")
    except sqlite3.Error as e:
        logger.error(f"Error initializing database: {e}", exc_info=True)
        raise


def is_master_password_set(conn: sqlite3.Connection) -> bool:
    """Check if the master password has been set."""
    try:
        cursor = conn.execute("SELECT 1 FROM master_password WHERE id = 1")
        is_set = cursor.fetchone() is not None
        logger.info("Checked if master password is set.")
        return is_set
    except sqlite3.Error as e:
        logger.error(f"Error checking master password: {e}")
        return False


def hash_password(password: str) -> bytes:
    """Hash the password using bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def verify_password(hashed_password: bytes, password: str) -> bool:
    """Verify the password against the hashed password."""
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password)


def validate_master_password(master_password: str) -> bool:
    """Validate the master password against security criteria."""
    if len(master_password) < 8:
        logger.error("Password must be at least 8 characters long.")
        return False
    if not re.search(r"[a-z]", master_password):
        logger.error("Password must contain at least one lowercase letter.")
        return False
    if not re.search(r"[A-Z]", master_password):
        logger.error("Password must contain at least one uppercase letter.")
        return False
    if not re.search(r"\d", master_password):
        logger.error("Password must contain at least one number.")
        return False
    if not re.search(r"[^\w\s]", master_password):
        logger.error("Password must contain at least one special character.")
        return False
    return True


def set_master_password(conn: sqlite3.Connection, master_password: str) -> None:
    """Set the master password in the database."""
    if not validate_master_password(master_password):
        logger.error("Master password validation failed.")
        raise ValueError("Master password does not meet security requirements.")
    try:
        hashed_password = hash_password(master_password)
        with conn:
            conn.execute(
                "INSERT INTO master_password (id, password) VALUES (1, ?)",
                (hashed_password,),
            )
        logger.info("Master password set in the database.")
    except sqlite3.IntegrityError:
        logger.error("Master password already set.")
        raise Exception("Master password is already set.")
    except sqlite3.Error as e:
        logger.error(f"Error setting master password: {e}")
        raise Exception("Failed to set master password.") from e


def verify_master_password(conn: sqlite3.Connection, master_password: str) -> bool:
    """Verify the provided master password against the stored hash."""
    try:
        cursor = conn.execute("SELECT password FROM master_password WHERE id = 1")
        row = cursor.fetchone()
        if row:
            stored_password = row[0]
            is_verified = verify_password(stored_password, master_password)
            logger.info("Verified master password.")
            return is_verified
        logger.warning("Master password not set.")
        return False
    except sqlite3.Error as e:
        logger.error(f"Master password verification error: {e}")
        return False


def update_master_password(
    conn: sqlite3.Connection, current_password: str, new_password: str
) -> Tuple[bool, str]:
    """
    Update the master password in the database after verifying the current password.

    Args:
        conn (sqlite3.Connection): The database connection.
        current_password (str): The current master password.
        new_password (str): The new master password to set.

    Returns:
        Tuple[bool, str]: (success: bool, message: str)
    """
    if not validate_master_password(new_password):
        logger.error("New master password validation failed.")
        return False, "New master password does not meet security requirements."

    try:
        cursor = conn.execute("SELECT password FROM master_password WHERE id = 1")
        row = cursor.fetchone()
        if not row:
            logger.error("Master password not set.")
            return False, "Master password is not set."

        stored_password = row[0]
        if not verify_password(stored_password, current_password):
            logger.error("Current master password is incorrect.")
            return False, "Current master password is incorrect."

        hashed_new_password = hash_password(new_password)
        with conn:
            conn.execute(
                "UPDATE master_password SET password = ? WHERE id = 1",
                (hashed_new_password,),
            )
        logger.info("Master password updated successfully.")
        return True, "Master password updated successfully."
    except sqlite3.Error as e:
        logger.error(f"Error updating master password: {e}")
        return False, "Failed to update master password."


def get_current_email(conn: sqlite3.Connection) -> str:
    """Retrieve the current email address from user_data table."""
    try:
        cursor = conn.execute("SELECT email FROM user_data WHERE id = 1")
        row = cursor.fetchone()
        if row:
            logger.info("Retrieved current email address.")
            return row[0]
        logger.info("No email address found for user.")
        return None
    except sqlite3.Error as e:
        logger.error(f"Error retrieving current email: {e}")
        return None


def update_email(
    conn: sqlite3.Connection, current_password: str, new_email: str
) -> Tuple[bool, str]:
    """
    Update the user's email address in the user_data table after verifying the current password.

    Args:
        conn (sqlite3.Connection): The database connection.
        current_password (str): The current master password.
        new_email (str): The new email address to set.

    Returns:
        Tuple[bool, str]: (success: bool, message: str)
    """
    # Validate email format
    if not re.match(r"[^@]+@[^@]+\.[^@]+", new_email):
        logger.error("Invalid email address format.")
        return False, "Invalid email address format."

    try:
        # Verify current master password
        if not verify_master_password(conn, current_password):
            logger.error("Current master password is incorrect.")
            return False, "Current master password is incorrect."

        # Update email in user_data table
        cursor = conn.execute("SELECT 1 FROM user_data WHERE id = 1")
        if cursor.fetchone():
            conn.execute(
                "UPDATE user_data SET email = ? WHERE id = 1",
                (new_email,),
            )
        else:
            conn.execute(
                "INSERT INTO user_data (id, email) VALUES (1, ?)",
                (new_email,),
            )
        conn.commit()
        logger.info("Email address updated successfully.")
        return True, "Email address updated successfully."
    except sqlite3.Error as e:
        logger.error(f"Error updating email address: {e}")
        return False, "Failed to update email address."


def store_password(
    conn: sqlite3.Connection, service: str, username: str, password: str
) -> None:
    """Store a new password entry in the database."""
    encrypted_service = encrypt_data(service)
    encrypted_username = encrypt_data(username)
    encrypted_password = encrypt_data(password)
    try:
        with conn:
            conn.execute(
                "INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)",
                (encrypted_service, encrypted_username, encrypted_password),
            )
        logger.info("Stored password for a service.")
    except sqlite3.IntegrityError:
        logger.error("Password entry for this service and username already exists.")
        raise Exception("Password entry already exists.")
    except sqlite3.Error as e:
        logger.error(f"Error storing password: {e}")
        raise Exception("Failed to store password.") from e


def retrieve_password(conn: sqlite3.Connection, service: str, username: str) -> str:
    """Retrieve a specific password entry from the database."""
    encrypted_service = encrypt_data(service)
    encrypted_username = encrypt_data(username)
    try:
        cursor = conn.execute(
            "SELECT password FROM passwords WHERE service = ? AND username = ?",
            (encrypted_service, encrypted_username),
        )
        row = cursor.fetchone()
        if row:
            decrypted_password = decrypt_data(row[0])
            logger.info("Retrieved password for a service.")
            return decrypted_password
        else:
            logger.info("No password found for the specified service and username.")
            return None
    except Exception as e:
        logger.error(f"Error retrieving password: {e}")
        raise Exception("Failed to retrieve password.") from e


def check_existing_entry(conn: sqlite3.Connection, service: str, username: str) -> bool:
    """Check if a password entry already exists for a given service and username."""
    encrypted_service = encrypt_data(service)
    encrypted_username = encrypt_data(username)
    try:
        cursor = conn.execute(
            "SELECT 1 FROM passwords WHERE service=? AND username=?",
            (encrypted_service, encrypted_username),
        )
        exists = cursor.fetchone() is not None
        logger.info("Checked existing entry for a service.")
        return exists
    except sqlite3.Error as e:
        logger.error(f"Error checking existing entry: {e}")
        return False


def get_all_passwords(conn: sqlite3.Connection) -> List[Tuple[str, str, str]]:
    """Retrieve all password entries from the database."""
    try:
        cursor = conn.execute("SELECT service, username, password FROM passwords")
        entries = []
        for (
            encrypted_service,
            encrypted_username,
            encrypted_password,
        ) in cursor.fetchall():
            try:
                service = decrypt_data(encrypted_service)
                username = decrypt_data(encrypted_username)
                password = decrypt_data(encrypted_password)
                entries.append((service, username, password))
            except Exception as e:
                logger.error(f"Error decrypting entry: {e}")
        logger.info("Retrieved all passwords.")
        return entries
    except sqlite3.Error as e:
        logger.error(f"Error retrieving all passwords: {e}")
        return []


def update_password(
    conn: sqlite3.Connection,
    old_service: str,
    old_username: str,
    new_service: str,
    new_username: str,
    new_password: str,
) -> None:
    """Update an existing password entry in the database."""
    encrypted_old_service = encrypt_data(old_service)
    encrypted_old_username = encrypt_data(old_username)
    encrypted_new_service = encrypt_data(new_service)
    encrypted_new_username = encrypt_data(new_username)
    encrypted_password = encrypt_data(new_password)
    try:
        with conn:
            conn.execute(
                """
                UPDATE passwords 
                SET service = ?, username = ?, password = ? 
                WHERE service = ? AND username = ?
                """,
                (
                    encrypted_new_service,
                    encrypted_new_username,
                    encrypted_password,
                    encrypted_old_service,
                    encrypted_old_username,
                ),
            )
        logger.info("Updated password for a service.")
    except sqlite3.Error as e:
        logger.error(f"Failed to update password: {e}")
        raise Exception("Failed to update password.") from e


def delete_password(conn: sqlite3.Connection, service: str, username: str) -> None:
    """Delete a specific password entry from the database."""
    encrypted_service = encrypt_data(service)
    encrypted_username = encrypt_data(username)
    try:
        with conn:
            conn.execute(
                "DELETE FROM passwords WHERE service = ? AND username = ?",
                (encrypted_service, encrypted_username),
            )
        logger.info("Deleted password for a service.")
    except sqlite3.Error as e:
        logger.error(f"Failed to delete password: {e}")
        raise Exception("Failed to delete password.") from e


def execute_query(
    conn: sqlite3.Connection, query: str, params: tuple = None
) -> List[Tuple]:
    """Execute a SQL query with optional parameters."""
    try:
        cursor = conn.cursor()
        cursor.execute(query, params or ())
        conn.commit()
        results = cursor.fetchall()
        logger.debug(f"Executed query: {query} | Params: {params}")
        return results
    except sqlite3.Error as e:
        logger.error(f"Error executing query: {e} | Query: {query}")
        return []


def fetch_one(conn: sqlite3.Connection, query: str, params: tuple = None) -> Tuple:
    """Execute a SQL query and fetch a single result."""
    try:
        cursor = conn.cursor()
        cursor.execute(query, params or ())
        conn.commit()
        result = cursor.fetchone()
        logger.debug(f"Executed query: {query} | Params: {params}")
        return result if result else ()
    except sqlite3.Error as e:
        logger.error(f"Error executing query: {e} | Query: {query}")
        return ()


def fetch_all(
    conn: sqlite3.Connection, query: str, params: tuple = None
) -> List[Tuple]:
    """Execute a SQL query and fetch all results."""
    try:
        cursor = conn.cursor()
        cursor.execute(query, params or ())
        conn.commit()
        results = cursor.fetchall()
        logger.debug(f"Executed query: {query} | Params: {params}")
        return results
    except sqlite3.Error as e:
        logger.error(f"Error executing query: {e} | Query: {query}")
        return []


def store_2fa_secret(
    conn: sqlite3.Connection, user_identifier: str, secret: str
) -> None:
    """Store or replace the 2FA secret for a user."""
    try:
        hashed_user_identifier = hash_identifier(user_identifier)
        encrypted_secret = encrypt_data(secret)
        conn.execute(
            "INSERT OR REPLACE INTO two_factor_auth (user_identifier, secret) VALUES (?, ?)",
            (hashed_user_identifier, encrypted_secret),
        )
        conn.commit()
        logger.info(
            f"Stored 2FA secret for hashed_user_identifier: {hashed_user_identifier}"
        )
    except sqlite3.Error as e:
        logger.error(f"Failed to store 2FA secret: {e}")
        raise Exception("Failed to store 2FA secret.") from e


def get_2fa_secret(conn: sqlite3.Connection, user_identifier: str) -> str:
    """Retrieve the decrypted 2FA secret for a user."""
    hashed_user_identifier = hash_identifier(user_identifier)
    logger.debug(
        f"Retrieving 2FA secret for hashed_user_identifier: {hashed_user_identifier}"
    )
    try:
        cursor = conn.execute(
            "SELECT secret FROM two_factor_auth WHERE user_identifier = ?",
            (hashed_user_identifier,),
        )
        row = cursor.fetchone()
        if row:
            encrypted_secret = row[0]
            try:
                secret = decrypt_data(encrypted_secret)
                logger.info("Retrieved 2FA secret for user.")
                return secret
            except Exception as e:
                logger.error(f"Decryption failed: {e}")
                raise
        else:
            logger.info("No 2FA secret found for the specified user.")
            return None
    except Exception as e:
        logger.error(f"Error retrieving 2FA secret: {e}")
        raise Exception("Failed to retrieve 2FA secret.") from e


def delete_2fa_secret(conn: sqlite3.Connection, user_identifier: str) -> None:
    """Delete the 2FA secret for a user."""
    try:
        hashed_user_identifier = hash_identifier(user_identifier)
        with conn:
            conn.execute(
                "DELETE FROM two_factor_auth WHERE user_identifier = ?",
                (hashed_user_identifier,),
            )
        logger.info("Deleted 2FA secret for user.")
    except sqlite3.Error as e:
        logger.error(f"Failed to delete 2FA secret: {e}")
        raise Exception("Failed to delete 2FA secret.") from e
