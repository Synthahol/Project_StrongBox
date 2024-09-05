import base64
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
logger = logging.getLogger(__name__)

# Explicitly define the path to the .env file
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
env_path = os.path.join(project_root, ".env")

# Load environment variables from the correct .env file
load_dotenv(dotenv_path=env_path)

# Service name to be used in keyring
SERVICE_ID = "my_fortalice_app"


def sanitize_env_var_name(database_name):
    """Sanitize the database name to create a valid environment variable name."""
    sanitized_name = database_name.upper()
    sanitized_name = re.sub(r"\W+", "_", sanitized_name)
    sanitized_name = re.sub(r"_+$", "", sanitized_name)
    if sanitized_name and sanitized_name[0].isdigit():
        sanitized_name = "_" + sanitized_name
    return sanitized_name


def load_encryption_key(database_name):
    """Retrieve the encryption key from the Windows Credential Locker using keyring."""
    key_name = f"{database_name}_KEY"
    encryption_key = keyring.get_password(SERVICE_ID, key_name)

    if not encryption_key:
        raise ValueError(
            "Encryption key not found in the Credential Locker. Please set it up first."
        )

    return encryption_key.encode()


def encrypt_key(key, encryption_key):
    fernet = Fernet(encryption_key)
    encrypted_key = fernet.encrypt(key.encode())
    return base64.urlsafe_b64encode(encrypted_key).decode()


def decrypt_key(encrypted_key, encryption_key):
    fernet = Fernet(encryption_key)
    encrypted_key_bytes = base64.urlsafe_b64decode(encrypted_key.encode())
    decrypted_key = fernet.decrypt(encrypted_key_bytes).decode()
    return decrypted_key


def manage_encryption_key(database_name):
    """
    Load an encryption key from the Windows Credential Locker or generate a new one if not present.
    Save the new key securely using keyring.
    """
    logger.debug("Starting manage_encryption_key()")
    key_name = f"{database_name}_KEY"

    # Check if the key already exists in the Credential Locker
    encryption_key = keyring.get_password(SERVICE_ID, key_name)

    if encryption_key:
        logger.info(
            f"Encryption key for {database_name} loaded successfully from Credential Locker."
        )
        return encryption_key.encode()

    # If not found, generate a new key
    encryption_key = Fernet.generate_key().decode()

    # Store the key securely using keyring
    keyring.set_password(SERVICE_ID, key_name, encryption_key)
    logger.info(
        f"New encryption key generated and stored securely in Credential Locker for {database_name}."
    )

    return encryption_key.encode()


def get_cipher_suite(database_name):
    key = manage_encryption_key(database_name)
    return Fernet(key)


def encrypt_data(data: str, cipher_suite: Fernet) -> str:
    """Encrypt data using the provided cipher suite."""
    try:
        encrypted_data = cipher_suite.encrypt(data.encode())
        return encrypted_data.decode()
    except Exception as e:
        logger.error("Error encrypting data: %s", e)
        raise


def decrypt_data(encrypted_data: str, cipher_suite: Fernet) -> str:
    """Decrypt data using the provided cipher suite."""
    try:
        decrypted_data = cipher_suite.decrypt(encrypted_data.encode())
        return decrypted_data.decode()
    except Exception as e:
        logger.error("Error decrypting data: %s", e)
        raise


def create_connection(db_file: str) -> sqlite3.Connection:
    try:
        conn = sqlite3.connect(db_file)
        logger.info("Created connection to database.")
        return conn
    except sqlite3.Error as e:
        logger.error("Error creating connection to database: %s", e)
        return None


def initialize_db(conn: sqlite3.Connection, key_id: str):
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
            conn.execute("INSERT INTO metadata (key_id) VALUES (?)", (key_id,))
        logger.info("Initialized database.")
    except sqlite3.Error as e:
        logger.error("Error initializing database: %s", e)


def is_master_password_set(conn: sqlite3.Connection) -> bool:
    try:
        cursor = conn.execute("SELECT 1 FROM master_password WHERE id = 1")
        is_set = cursor.fetchone() is not None
        logger.info("Checked if master password is set.")
        return is_set
    except sqlite3.Error as e:
        logger.error("Error checking if master password is set: %s", e)
        return False


def set_master_password(conn: sqlite3.Connection, master_password: str):
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
        logger.error("Error setting master password: %s", e)


def verify_master_password(conn: sqlite3.Connection, master_password: str) -> bool:
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
        logger.error("Master password verification error: %s", e)
        return False


def store_password(
    conn: sqlite3.Connection,
    service: str,
    username: str,
    password: str,
    cipher_suite: Fernet,
):
    encrypted_password = encrypt_data(password, cipher_suite)
    if encrypted_password:
        try:
            with conn:
                conn.execute(
                    "INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)",
                    (service, username, encrypted_password),
                )
            logger.info("Stored password for service.")
        except sqlite3.Error as e:
            logger.error("Error storing password: %s", e)


def retrieve_password(
    conn: sqlite3.Connection, service: str, username: str, cipher_suite: Fernet
):
    try:
        cursor = conn.execute(
            "SELECT username, password FROM passwords WHERE service = ? AND username = ?",
            (service, username),
        )
        row = cursor.fetchone()

        if row and len(row) == 2:
            username, encrypted_password = row
            logger.info("Retrieved encrypted password for service.")
            return username, encrypted_password
        else:
            logger.info("No password found for the specified service and username.")
            return None, None
    except sqlite3.Error as e:
        logger.error("Error retrieving password: %s", e)
        return None, None


def check_existing_entry(conn: sqlite3.Connection, service: str, username: str) -> bool:
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM passwords WHERE service=? AND username=?",
            (service, username),
        )
        is_existing = cur.fetchone() is not None
        logger.info("Checked existing entry for service.")
        return is_existing
    except sqlite3.Error as e:
        logger.error("Error checking existing entry: %s", e)
        return False


def get_all_passwords(conn: sqlite3.Connection) -> list[tuple[str, str, str]]:
    try:
        cursor = conn.execute("SELECT service, username, password FROM passwords")
        passwords = cursor.fetchall()
        logger.info("Retrieved all passwords.")
        return passwords
    except sqlite3.Error as e:
        logger.error("Error retrieving all passwords: %s", e)
        return []


def update_password(
    conn,
    old_service,
    old_username,
    old_password,
    new_service,
    new_username,
    new_password,
    cipher_suite,
):
    cursor = conn.cursor()
    encrypted_new_password = cipher_suite.encrypt(new_password.encode()).decode()

    try:
        cursor.execute(
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
        conn.commit()
        logger.info("Updated password for the specified service and username.")
    except sqlite3.Error as e:
        logger.error("Failed to update password: %s", e)
        raise


def delete_password(conn, service, username, cipher_suite):
    cursor = conn.cursor()
    try:
        cursor.execute(
            "DELETE FROM passwords WHERE service = ? AND username = ?",
            (service, username),
        )
        conn.commit()
        logger.info("Deleted password for the specified service and username.")
    except sqlite3.Error as e:
        logger.error("Failed to delete password: %s", e)


def login_user(conn: sqlite3.Connection, username: str, master_password: str):
    if verify_master_password(conn, master_password):
        logger.info("Login successful.")
    else:
        logger.warning("Master password verification failed.")
