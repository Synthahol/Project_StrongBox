# database.py

import logging
import os
import sqlite3

import keyring
from cryptography.fernet import Fernet
from dotenv import load_dotenv

from backend.config import DATABASE_DIR
from backend.master_password import (
    generate_salt,
    hash_password,
    validate_master_password,
    verify_password,
)

# Configure logging
logger = logging.getLogger(__name__)

# Load environment variables from the .env file
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
env_path = os.path.join(project_root, ".env")
load_dotenv(dotenv_path=env_path)

# Constants
SERVICE_ID = "my_fortalice_app"
DATABASE_NAME = "DefaultFortalice"
DATABASE_PATH = os.path.join(DATABASE_DIR, f"{DATABASE_NAME}.db")
cipher_suite = None


def get_cipher_suite():
    global cipher_suite
    if cipher_suite is None:
        key = manage_encryption_key(DATABASE_NAME)
        cipher_suite = Fernet(key)
    return cipher_suite


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
        cipher_suite = get_cipher_suite()
        return cipher_suite.encrypt(data.encode()).decode()
    except Exception:
        logger.error("Error encrypting data.")
        raise Exception("Encryption failed.")


def decrypt_data(encrypted_data: str) -> str:
    """Decrypt data using the cipher suite."""
    try:
        cipher_suite = get_cipher_suite()
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
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
                    salt BLOB NOT NULL,
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


def set_master_password(conn: sqlite3.Connection, master_password: str):
    """Set the master password in the database."""
    if not validate_master_password(master_password):
        logger.error("Master password validation failed.")
        raise ValueError("Master password does not meet security requirements.")
    try:
        salt = generate_salt()
        hashed_password = hash_password(master_password, salt)
        with conn:
            conn.execute(
                "INSERT INTO master_password (id, salt, password) VALUES (1, ?, ?)",
                (salt, hashed_password),
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
        cursor = conn.execute("SELECT salt, password FROM master_password WHERE id = 1")
        row = cursor.fetchone()
        if row:
            salt, stored_password = row
            is_verified = verify_password(stored_password, master_password, salt)
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
    encrypted_password = encrypt_data(password)
    try:
        with conn:
            conn.execute(
                "INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)",
                (service, username, encrypted_password),
            )
        logger.info(f"Stored password for service: {service}")
    except sqlite3.Error as e:
        logger.error(f"Error storing password: {e}")
        raise Exception("Failed to store password.")


def retrieve_password(conn: sqlite3.Connection, service: str, username: str):
    """Retrieve a specific password entry from the database."""
    try:
        cursor = conn.execute(
            "SELECT password FROM passwords WHERE service = ? AND username = ?",
            (service, username),
        )
        row = cursor.fetchone()
        if row:
            decrypted_password = decrypt_data(row[0])
            logger.info(f"Retrieved password for service: {service}")
            return decrypted_password
        else:
            logger.info("No password found for the specified service and username.")
            return None
    except Exception as e:
        logger.error(f"Error retrieving password: {e}")
        raise Exception("Failed to retrieve password.")


def check_existing_entry(conn: sqlite3.Connection, service: str, username: str) -> bool:
    """Check if a password entry already exists for a given service and username."""
    try:
        cursor = conn.execute(
            "SELECT 1 FROM passwords WHERE service=? AND username=?",
            (service, username),
        )
        exists = cursor.fetchone() is not None
        logger.info(f"Checked existing entry for service: {service}")
        return exists
    except sqlite3.Error as e:
        logger.error(f"Error checking existing entry: {e}")
        return False


def get_all_passwords(conn: sqlite3.Connection) -> list:
    """Retrieve all password entries from the database."""
    try:
        cursor = conn.execute("SELECT service, username, password FROM passwords")
        entries = []
        for service, username, encrypted_password in cursor.fetchall():
            try:
                password = decrypt_data(encrypted_password)
                entries.append((service, username, password))
            except Exception as e:
                logger.error(f"Error decrypting password for {service}: {e}")
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
                    new_service,
                    new_username,
                    encrypted_password,
                    old_service,
                    old_username,
                ),
            )
        logger.info(
            f"Updated password for service: {old_service} to {new_service}, username: {old_username} to {new_username}"
        )
    except sqlite3.Error as e:
        logger.error(f"Failed to update password: {e}")
        raise Exception("Failed to update password.")


def delete_password(conn, service, username):
    """Delete a specific password entry from the database."""
    try:
        with conn:
            conn.execute(
                "DELETE FROM passwords WHERE service = ? AND username = ?",
                (service, username),
            )
        logger.info(f"Deleted password for service: {service}, username: {username}")
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
        logger.debug(f"Executed query: {query} | Params: {params} | Results: {results}")
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
        logger.debug(f"Executed query: {query} | Params: {params} | Result: {result}")
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
        logger.debug(f"Executed query: {query} | Params: {params} | Results: {results}")
        return results
    except sqlite3.Error as e:
        logger.error(f"Error executing query: {e} | Query: {query}")
        return []
