# backend.database.py

"""This module contains functions for managing the SQLite database."""

import hashlib
import logging
import os
import sqlite3

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


def get__cipher_suite():
    """Define the cipher suite for encrypting and decrypting data."""
    global _cipher_suite
    if _cipher_suite is None:
        key = manage_encryption_key(DATABASE_NAME)
        _cipher_suite = Fernet(key)
    return _cipher_suite


def hash_identifier(identifier: str) -> str:
    """Compute a hash of the identifier for consistent lookup."""
    return hashlib.sha256(identifier.encode("utf-8")).hexdigest()


def manage_encryption_key(database_name):
    """Load or generate an encryption key stored securely using keyring."""
    key_name = f"{database_name}_KEY"
    encryption_key = keyring.get_password(SERVICE_ID, key_name)
    if encryption_key:
        logger.info(f"Encryption key for {database_name} loaded successfully.")
        return encryption_key.encode()
    encryption_key = Fernet.generate_key().decode()
    keyring.set_password(SERVICE_ID, key_name, encryption_key)
    logger.info(f"New encryption key generated and stored for {database_name}.")
    return encryption_key.encode()


def encrypt_data(data: str) -> str:
    """Encrypt data using the cipher suite."""
    try:
        _cipher_suite = get__cipher_suite()
        return _cipher_suite.encrypt(data.encode()).decode()
    except Exception:
        logger.error("Error encrypting data.")
        raise Exception("Encryption failed.")


def decrypt_data(encrypted_data: str) -> str:
    """Decrypt data using the cipher suite."""
    try:
        _cipher_suite = get__cipher_suite()
        return _cipher_suite.decrypt(encrypted_data.encode()).decode()
    except Exception:
        logger.error("Error decrypting data.")
        raise Exception("Decryption failed.")


def create_connection() -> sqlite3.Connection:
    """Create and return a connection to the SQLite database."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        logger.info("Created connection to database.")
        return conn
    except sqlite3.Error as e:
        logger.error(f"Error creating database connection: {e}")
        return None


def initialize_db(conn: sqlite3.Connection, key_id: str):
    """Initialize the database with necessary tables."""
    try:
        with conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY,
                    service TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL
                );"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS master_password (
                    id INTEGER PRIMARY KEY,
                    password BLOB NOT NULL
                );"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS metadata (
                    key_id TEXT NOT NULL
                );"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS secure_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL
                );"""
            )
            conn.execute(
                "INSERT OR IGNORE INTO metadata (key_id) VALUES (?)", (key_id,)
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS two_factor_auth (
                user_identifier TEXT PRIMARY KEY,
                secret TEXT NOT NULL
            );"""
            )
        logger.info("Initialized database.")
    except sqlite3.Error as e:
        logger.error(f"Error initializing database: {e}")


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
    import re

    if len(master_password) < 8:
        return False
    if not re.search(r"[a-z]", master_password):
        return False
    if not re.search(r"[A-Z]", master_password):
        return False
    if not re.search(r"\d", master_password):
        return False
    if not re.search(r"[^\w\s]", master_password):
        return False
    return True


def set_master_password(conn: sqlite3.Connection, master_password: str):
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
        raise Exception("Failed to set master password.")


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
        return False
    except sqlite3.Error as e:
        logger.error(f"Master password verification error: {e}")
        return False


def store_password(
    conn: sqlite3.Connection, service: str, username: str, password: str
):
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
    except sqlite3.Error as e:
        logger.error(f"Error storing password: {e}")
        raise Exception("Failed to store password.")


def retrieve_password(conn: sqlite3.Connection, service: str, username: str):
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
        raise Exception("Failed to retrieve password.")


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


def get_all_passwords(conn: sqlite3.Connection) -> list:
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
    conn,
    old_service,
    old_username,
    new_service,
    new_username,
    new_password,
):
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
        raise Exception("Failed to update password.")


def delete_password(conn, service, username):
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
        raise Exception("Failed to delete password.")


def execute_query(conn: sqlite3.Connection, query: str, params: tuple = None) -> list:
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


def fetch_one(conn: sqlite3.Connection, query: str, params: tuple = None) -> tuple:
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


def fetch_all(conn: sqlite3.Connection, query: str, params: tuple = None) -> list:
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


def store_2fa_secret(conn: sqlite3.Connection, user_identifier: str, secret: str):
    """Store the 2FA secret for a user in the database."""
    try:
        hashed_user_identifier = hash_identifier(user_identifier)
        encrypted_secret = encrypt_data(secret)
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO two_factor_auth (user_identifier, secret) VALUES (?, ?)",
                (hashed_user_identifier, encrypted_secret),
            )
        logger.info("Stored 2FA secret for user.")
    except sqlite3.Error as e:
        logger.error(f"Failed to store 2FA secret: {e}")
        raise Exception("Failed to store 2FA secret.")


def get_2fa_secret(conn: sqlite3.Connection, user_identifier: str) -> str:
    """Retrieve the decrypted 2FA secret for a user."""
    hashed_user_identifier = hash_identifier(user_identifier)
    try:
        cursor = conn.execute(
            "SELECT secret FROM two_factor_auth WHERE user_identifier = ?",
            (hashed_user_identifier,),
        )
        row = cursor.fetchone()
        if row:
            encrypted_secret = row[0]
            secret = decrypt_data(encrypted_secret)
            logger.info("Retrieved 2FA secret for user.")
            return secret
        else:
            logger.info("No 2FA secret found for the specified user.")
            return None
    except Exception as e:
        logger.error(f"Error retrieving 2FA secret: {e}")
        raise Exception("Failed to retrieve 2FA secret.")


def delete_2fa_secret(conn: sqlite3.Connection, user_identifier: str):
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
        raise Exception("Failed to delete 2FA secret.")
