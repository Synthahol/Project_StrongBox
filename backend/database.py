import logging
import os
import re
import sqlite3

import keyring
from cryptography.fernet import Fernet
from dotenv import load_dotenv

from backend.master_password import (
    generate_salt,
    hash_password,
    validate_master_password,
    verify_password,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Define the path to the .env file
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
env_path = os.path.join(project_root, ".env")
load_dotenv(dotenv_path=env_path)

SERVICE_ID = "my_fortalice_app"


def sanitize_env_var_name(database_name: str) -> str:
    """Sanitize the database name to create a valid environment variable name."""
    sanitized_name = re.sub(r"\W+", "_", database_name.upper()).strip("_")
    if sanitized_name and sanitized_name[0].isdigit():
        sanitized_name = "_" + sanitized_name
    return sanitized_name


def load_encryption_key(database_name: str) -> bytes:
    """Retrieve the encryption key from the Windows Credential Locker using keyring."""
    key_name = f"{database_name}_KEY"
    encryption_key = keyring.get_password(SERVICE_ID, key_name)
    if not encryption_key:
        raise ValueError(
            "Encryption key not found in the Credential Locker. Please set it up first."
        )
    return encryption_key.encode()


def manage_encryption_key(database_name: str) -> bytes:
    """
    Load an encryption key from the Windows Credential Locker or generate a new one if not present.
    Save the new key securely using keyring.
    """
    logger.debug("Starting manage_encryption_key()")
    key_name = f"{database_name}_KEY"
    encryption_key = keyring.get_password(SERVICE_ID, key_name)

    if encryption_key:
        logger.info(f"Encryption key for {database_name} loaded successfully.")
        return encryption_key.encode()

    encryption_key = Fernet.generate_key().decode()
    keyring.set_password(SERVICE_ID, key_name, encryption_key)
    logger.info(
        f"New encryption key generated and securely stored for {database_name}."
    )

    return encryption_key.encode()


def get_cipher_suite(database_name: str) -> Fernet:
    """Get a Fernet cipher suite using the encryption key for the specified database."""
    key = manage_encryption_key(database_name)
    return Fernet(key)


def encrypt_data(data: str, cipher_suite: Fernet) -> str:
    """Encrypt data using the provided cipher suite."""
    try:
        encrypted_data = cipher_suite.encrypt(data.encode())
        return encrypted_data.decode()
    except Exception:
        logger.error("Error encrypting data", exc_info=True)
        raise


def decrypt_data(encrypted_data: str, cipher_suite: Fernet) -> str:
    """Decrypt data using the provided cipher suite."""
    try:
        decrypted_data = cipher_suite.decrypt(encrypted_data.encode())
        return decrypted_data.decode()
    except Exception:
        logger.error("Error decrypting data", exc_info=True)
        raise


def create_connection(db_file: str) -> sqlite3.Connection:
    """Create a database connection to the specified SQLite database."""
    try:
        conn = sqlite3.connect(db_file)
        logger.info("Created connection to database.")
        return conn
    except sqlite3.Error:
        logger.error("Error creating connection to database", exc_info=True)
        return None


def initialize_db(conn: sqlite3.Connection, key_id: str) -> None:
    """Initialize the database schema if it does not exist."""
    try:
        with conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS passwords (
                                id INTEGER PRIMARY KEY,
                                service TEXT NOT NULL,
                                username TEXT NOT NULL,
                                password TEXT NOT NULL
                            );""")
            conn.execute("""CREATE TABLE IF NOT EXISTS master_password (
                                id INTEGER PRIMARY KEY,
                                salt BLOB NOT NULL,
                                password BLOB NOT NULL
                            );""")
            conn.execute("""CREATE TABLE IF NOT EXISTS metadata (
                                key_id TEXT NOT NULL
                            );""")
            if not conn.execute(
                "SELECT key_id FROM metadata WHERE key_id = ?", (key_id,)
            ).fetchone():
                conn.execute("INSERT INTO metadata (key_id) VALUES (?)", (key_id,))
        logger.info("Database initialized.")
    except sqlite3.Error:
        logger.error("Error initializing database", exc_info=True)


def is_master_password_set(conn: sqlite3.Connection) -> bool:
    """Check if the master password is set in the database."""
    try:
        cursor = conn.execute("SELECT 1 FROM master_password WHERE id = 1")
        is_set = cursor.fetchone() is not None
        logger.info("Checked if master password is set.")
        return is_set
    except sqlite3.Error:
        logger.error("Error checking if master password is set", exc_info=True)
        return False


def set_master_password(conn: sqlite3.Connection, master_password: str) -> None:
    """Set the master password in the database."""
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
    except sqlite3.Error:
        logger.error("Error setting master password", exc_info=True)


def verify_master_password(conn: sqlite3.Connection, master_password: str) -> bool:
    """Verify the master password against the stored hash."""
    try:
        cursor = conn.execute("SELECT salt, password FROM master_password WHERE id = 1")
        row = cursor.fetchone()
        if row:
            salt, stored_password = row
            is_verified = verify_password(stored_password, master_password, salt)
            logger.info("Verified master password.")
            return is_verified
        return False
    except sqlite3.Error:
        logger.error("Master password verification error", exc_info=True)
        return False


def store_password(
    conn: sqlite3.Connection,
    service: str,
    username: str,
    password: str,
    cipher_suite: Fernet,
) -> None:
    """Store an encrypted password in the database."""
    encrypted_password = encrypt_data(password, cipher_suite)
    if encrypted_password:
        try:
            with conn:
                conn.execute(
                    "INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)",
                    (service, username, encrypted_password),
                )
            logger.info("Stored password for service.")
        except sqlite3.Error:
            logger.error("Error storing password", exc_info=True)


def retrieve_password(
    conn: sqlite3.Connection, service: str, username: str, cipher_suite: Fernet
) -> tuple[str, str]:
    """Retrieve and decrypt a password from the database."""
    try:
        cursor = conn.execute(
            "SELECT username, password FROM passwords WHERE service = ? AND username = ?",
            (service, username),
        )
        row = cursor.fetchone()
        if row and len(row) == 2:
            username, encrypted_password = row
            decrypted_password = decrypt_data(encrypted_password, cipher_suite)
            logger.info("Retrieved password for service.")
            return username, decrypted_password
        else:
            logger.info("No password found for the specified service and username.")
            return None, None
    except sqlite3.Error:
        logger.error("Error retrieving password", exc_info=True)
        return None, None


def check_existing_entry(conn: sqlite3.Connection, service: str, username: str) -> bool:
    """Check if an entry exists in the database for the given service and username."""
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT 1 FROM passwords WHERE service = ? AND username = ?",
            (service, username),
        )
        is_existing = cur.fetchone() is not None
        logger.info("Checked existing entry for service.")
        return is_existing
    except sqlite3.Error:
        logger.error("Error checking existing entry", exc_info=True)
        return False


def get_all_passwords(conn: sqlite3.Connection) -> list[tuple[str, str, str]]:
    """Retrieve all stored passwords from the database."""
    try:
        cursor = conn.execute("SELECT service, username, password FROM passwords")
        passwords = cursor.fetchall()
        logger.info("Retrieved all passwords.")
        return passwords
    except sqlite3.Error:
        logger.error("Error retrieving all passwords", exc_info=True)
        return []


def update_password(
    conn: sqlite3.Connection,
    old_service: str,
    old_username: str,
    new_service: str,
    new_username: str,
    new_password: str,
    cipher_suite: Fernet,
) -> None:
    """Update an existing password entry in the database."""
    encrypted_new_password = encrypt_data(new_password, cipher_suite)
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
                    encrypted_new_password,
                    old_service,
                    old_username,
                ),
            )
        logger.info("Updated password for the specified service and username.")
    except sqlite3.Error:
        logger.error("Failed to update password", exc_info=True)
        raise


def delete_password(conn: sqlite3.Connection, service: str, username: str) -> None:
    """Delete a password entry from the database."""
    try:
        with conn:
            conn.execute(
                "DELETE FROM passwords WHERE service = ? AND username = ?",
                (service, username),
            )
        logger.info("Deleted password for the specified service and username.")
    except sqlite3.Error:
        logger.error("Failed to delete password", exc_info=True)


def login_user(conn: sqlite3.Connection, username: str, master_password: str) -> bool:
    """Login user by verifying the master password."""
    if verify_master_password(conn, master_password):
        logger.info("Login successful.")
        return True
    else:
        logger.warning("Master password verification failed.")
        return False
