import logging
import os
import re
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

# Explicitly define the path to the .env file
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
env_path = os.path.join(project_root, ".env")

# Load environment variables from the correct .env file
load_dotenv(dotenv_path=env_path)

# Service name to be used in keyring
SERVICE_ID = "my_fortalice_app"

# Define the database name and path
DATABASE_NAME = "DefaultFortalice"
DATABASE_PATH = os.path.join(DATABASE_DIR, f"{DATABASE_NAME}.db")

# Global cipher suite
cipher_suite = None


def get_cipher_suite():
    global cipher_suite
    if cipher_suite is None:
        key = manage_encryption_key(DATABASE_NAME)
        cipher_suite = Fernet(key)
    return cipher_suite


def sanitize_env_var_name(database_name):
    """Sanitize the database name to create a valid environment variable name."""
    sanitized_name = database_name.upper()
    sanitized_name = re.sub(r"\W+", "_", sanitized_name)
    sanitized_name = re.sub(r"_+$", "", sanitized_name)
    if sanitized_name and sanitized_name[0].isdigit():
        sanitized_name = "_" + sanitized_name
    return sanitized_name


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


def encrypt_data(data: str) -> str:
    """Encrypt data using the cipher suite."""
    try:
        cipher_suite = get_cipher_suite()
        encrypted_data = cipher_suite.encrypt(data.encode())
        return encrypted_data.decode()
    except Exception:
        logger.error("Error encrypting data.")
        raise Exception("Encryption failed.")


def decrypt_data(encrypted_data: str) -> str:
    """Decrypt data using the cipher suite."""
    try:
        cipher_suite = get_cipher_suite()
        decrypted_data = cipher_suite.decrypt(encrypted_data.encode())
        return decrypted_data.decode()
    except Exception:
        logger.error("Error decrypting data.")
        raise Exception("Decryption failed.")


def create_connection() -> sqlite3.Connection:
    try:
        conn = sqlite3.connect(DATABASE_PATH)
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
            conn.execute(
                "INSERT OR IGNORE INTO metadata (key_id) VALUES (?)", (key_id,)
            )
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
                "INSERT INTO master_password (id, salt, password) VALUES (1, ?, ?)",
                (salt, hashed_password),
            )
        logger.info("Master password set in the database.")
    except sqlite3.IntegrityError:
        logger.error("Master password already set.")
        raise Exception("Master password is already set.")
    except sqlite3.Error as e:
        logger.error("Error setting master password: %s", e)
        raise Exception("Failed to set master password.")


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
):
    encrypted_password = encrypt_data(password)
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
            raise Exception("Failed to store password.")


def retrieve_password(conn: sqlite3.Connection, service: str, username: str):
    try:
        cursor = conn.execute(
            "SELECT username, password FROM passwords WHERE service = ? AND username = ?",
            (service, username),
        )
        row = cursor.fetchone()

        if row and len(row) == 2:
            username, encrypted_password = row
            decrypted_password = decrypt_data(encrypted_password)
            logger.info("Retrieved password for service.")
            return username, decrypted_password
        else:
            logger.info("No password found for the specified service and username.")
            return None, None
    except sqlite3.Error as e:
        logger.error("Error retrieving password: %s", e)
        raise Exception("Failed to retrieve password.")
    except Exception as e:
        logger.error("Decryption error: %s", e)
        raise Exception("Failed to decrypt password.")


def check_existing_entry(conn: sqlite3.Connection, service: str, username: str) -> bool:
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT 1 FROM passwords WHERE service=? AND username=?",
            (service, username),
        )
        is_existing = cur.fetchone() is not None
        logger.info("Checked existing entry for service.")
        return is_existing
    except sqlite3.Error as e:
        logger.error("Error checking existing entry: %s", e)
        return False


def get_all_passwords(conn: sqlite3.Connection) -> list:
    try:
        cursor = conn.execute("SELECT service, username, password FROM passwords")
        encrypted_passwords = cursor.fetchall()
        decrypted_passwords = []
        for service, username, encrypted_password in encrypted_passwords:
            try:
                password = decrypt_data(encrypted_password)
                decrypted_passwords.append((service, username, password))
            except Exception as e:
                logger.error("Error decrypting password for service %s: %s", service, e)
                # Optionally, skip this entry or include it with an error flag
        logger.info("Retrieved all passwords.")
        return decrypted_passwords
    except sqlite3.Error as e:
        logger.error("Error retrieving all passwords: %s", e)
        return []


def update_password(
    conn,
    old_service,
    old_username,
    new_service,
    new_username,
    new_password,
):
    encrypted_new_password = encrypt_data(new_password)

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
    except sqlite3.Error as e:
        logger.error("Failed to update password: %s", e)
        raise Exception("Failed to update password.")


def delete_password(conn, service, username):
    try:
        with conn:
            conn.execute(
                "DELETE FROM passwords WHERE service = ? AND username = ?",
                (service, username),
            )
        logger.info("Deleted password for the specified service and username.")
    except sqlite3.Error as e:
        logger.error("Failed to delete password: %s", e)
        raise Exception("Failed to delete password.")


def login_user(conn: sqlite3.Connection, username: str, master_password: str):
    if verify_master_password(conn, master_password):
        logger.info("Login successful.")
    else:
        logger.warning("Master password verification failed.")
        raise Exception("Invalid master password.")
