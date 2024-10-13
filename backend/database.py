# backend/database.py

"""This module contains functions for managing the SQLite database."""

import hashlib
import logging
import os
import re
import sqlite3
from typing import List, Optional, Tuple

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


def create_connection() -> Optional[sqlite3.Connection]:
    """Create and return a connection to the SQLite database."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.execute("PRAGMA foreign_keys = ON;")  # Enable foreign key constraints
        logger.info("Created connection to database with foreign keys enabled.")
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
            # Drop existing tables if they exist
            conn.execute("DROP TABLE IF EXISTS master_password")
            conn.execute("DROP TABLE IF EXISTS two_factor_auth")
            conn.execute("DROP TABLE IF EXISTS users")
            conn.execute("DROP TABLE IF EXISTS passwords")
            conn.execute("DROP TABLE IF EXISTS secure_notes")

            # Create users table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE
                )
            """)

            # Create master_password table with user_id foreign key
            conn.execute("""
                CREATE TABLE IF NOT EXISTS master_password (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    password BLOB NOT NULL,
                    user_id INTEGER NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    UNIQUE(user_id)
                )
            """)

            # Create two_factor_auth table with user_id foreign key
            conn.execute("""
                CREATE TABLE IF NOT EXISTS two_factor_auth (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL UNIQUE,
                    secret BLOB NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)

            # Create passwords table with user_id foreign key
            conn.execute("""
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    UNIQUE(service, username, user_id)
                )
            """)

            # Create secure_notes table with title and content
            conn.execute("""
                CREATE TABLE IF NOT EXISTS secure_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
        logger.info("Initialized database with multi-user support.")
    except sqlite3.Error as e:
        logger.error(f"Error initializing database: {e}", exc_info=True)
        raise


def get_user_id(conn: sqlite3.Connection, email: str) -> Optional[int]:
    """
    Retrieve the user ID for the given email address.

    Args:
        conn (sqlite3.Connection): The database connection.
        email (str): The user's email address.

    Returns:
        Optional[int]: The user's ID if found, else None.
    """
    try:
        cursor = conn.execute("SELECT id FROM users WHERE email = ?", (email.lower(),))
        row = cursor.fetchone()
        if row:
            logger.info(f"Retrieved user ID {row[0]} for email: {email}")
            return row[0]
        else:
            logger.warning(f"No user found with email: {email}")
            return None
    except sqlite3.Error as e:
        logger.error(f"Error retrieving user ID for email {email}: {e}")
        return None


def is_master_password_set(conn: sqlite3.Connection, email: str) -> bool:
    """
    Check if the master password has been set for a specific user.

    Args:
        conn (sqlite3.Connection): The database connection.
        email (str): The user's email address.

    Returns:
        bool: True if set, False otherwise.
    """
    try:
        user_id = get_user_id(conn, email)
        if user_id is None:
            return False
        cursor = conn.execute(
            "SELECT 1 FROM master_password WHERE user_id = ?", (user_id,)
        )
        is_set = cursor.fetchone() is not None
        logger.info(f"Master password set for user {email}: {is_set}")
        return is_set
    except sqlite3.Error as e:
        logger.error(f"Error checking master password for {email}: {e}")
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


def set_master_password(
    conn: sqlite3.Connection, email: str, master_password: str
) -> None:
    """
    Set the master password for a specific user.

    Args:
        conn (sqlite3.Connection): The database connection.
        email (str): The user's email address.
        master_password (str): The master password to set.
    """
    logger.debug("Attempting to set master password.")
    if not validate_master_password(master_password):
        logger.error("Master password validation failed.")
        raise ValueError("Master password does not meet security requirements.")
    try:
        user_id = get_user_id(conn, email)
        if user_id is None:
            # Insert the user into users table
            with conn:
                conn.execute("INSERT INTO users (email) VALUES (?)", (email.lower(),))
            user_id = get_user_id(conn, email)
            logger.info(f"Created new user with ID {user_id} for email: {email}")
        hashed_password = hash_password(master_password)
        logger.debug(f"Hashed password: {hashed_password}")
        with conn:
            conn.execute(
                """
                INSERT INTO master_password (password, user_id) 
                VALUES (?, ?)
                ON CONFLICT(user_id) DO UPDATE SET password = excluded.password
                """,
                (hashed_password, user_id),
            )
        logger.info(f"Master password set for user: {email}")
    except sqlite3.IntegrityError:
        logger.error("Master password already set for this user.")
        raise Exception("Master password is already set for this user.")
    except sqlite3.Error as e:
        logger.error(f"Error setting master password for {email}: {e}")
        raise Exception("Failed to set master password.") from e


def verify_master_password(
    conn: sqlite3.Connection, email: str, master_password: str
) -> bool:
    """
    Verify the provided master password against the stored hash for a specific user.

    Args:
        conn (sqlite3.Connection): The database connection.
        email (str): The user's email address.
        master_password (str): The password to verify.

    Returns:
        bool: True if correct, False otherwise.
    """
    try:
        user_id = get_user_id(conn, email)
        if user_id is None:
            logger.warning(f"No user found with email: {email}")
            return False
        cursor = conn.execute(
            "SELECT password FROM master_password WHERE user_id = ?", (user_id,)
        )
        row = cursor.fetchone()
        if row:
            stored_password = row[0]
            if isinstance(stored_password, str):
                stored_password = stored_password.encode("utf-8")
            is_verified = verify_password(stored_password, master_password)
            logger.info(f"Master password verification for {email}: {is_verified}")
            return is_verified
        else:
            logger.warning(f"Master password not set for user: {email}")
            return False
    except sqlite3.Error as e:
        logger.error(f"Error verifying master password for {email}: {e}")
        return False


def update_master_password(
    conn: sqlite3.Connection, email: str, current_password: str, new_password: str
) -> Tuple[bool, str]:
    """
    Update the master password in the database after verifying the current password.

    Args:
        conn (sqlite3.Connection): The database connection.
        email (str): The user's email address.
        current_password (str): The current master password.
        new_password (str): The new master password to set.

    Returns:
        Tuple[bool, str]: (success: bool, message: str)
    """
    if not validate_master_password(new_password):
        logger.error("New master password validation failed.")
        return False, "New master password does not meet security requirements."

    try:
        user_id = get_user_id(conn, email)
        if user_id is None:
            logger.error(f"No user found with email: {email}")
            return False, "User does not exist."

        # Verify current master password
        cursor = conn.execute(
            "SELECT password FROM master_password WHERE user_id = ?", (user_id,)
        )
        row = cursor.fetchone()
        if not row:
            logger.error("Master password not set.")
            return False, "Master password is not set."

        stored_password = row[0]
        if isinstance(stored_password, str):
            stored_password = stored_password.encode("utf-8")
        if not verify_password(stored_password, current_password):
            logger.error("Current master password is incorrect.")
            return False, "Current master password is incorrect."

        # Hash new password and update
        hashed_new_password = hash_password(new_password)
        with conn:
            conn.execute(
                "UPDATE master_password SET password = ? WHERE user_id = ?",
                (hashed_new_password, user_id),
            )
        logger.info("Master password updated successfully.")
        return True, "Master password updated successfully."
    except sqlite3.Error as e:
        logger.error(f"Error updating master password: {e}")
        return False, "Failed to update master password."


def get_current_email(conn: sqlite3.Connection) -> Optional[str]:
    """Retrieve the current email address from users table."""
    try:
        cursor = conn.execute("SELECT email FROM users WHERE id = 1")
        row = cursor.fetchone()
        if row:
            logger.info("Retrieved current email address.")
            return row[0]
        logger.info("No email address found for user with ID 1.")
        return None
    except sqlite3.Error as e:
        logger.error(f"Error retrieving current email: {e}")
        return None


def update_email(
    conn: sqlite3.Connection, email: str, current_password: str, new_email: str
) -> Tuple[bool, str]:
    """
    Update the user's email address in the users table after verifying the current password.

    Args:
        conn (sqlite3.Connection): The database connection.
        email (str): The user's current email address.
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
        user_id = get_user_id(conn, email)
        if user_id is None:
            logger.error(f"No user found with email: {email}")
            return False, "User does not exist."

        # Verify current master password
        cursor = conn.execute(
            "SELECT password FROM master_password WHERE user_id = ?", (user_id,)
        )
        row = cursor.fetchone()
        if not row:
            logger.error("Master password not set.")
            return False, "Master password is not set."

        stored_password = row[0]
        if isinstance(stored_password, str):
            stored_password = stored_password.encode("utf-8")
        if not verify_password(stored_password, current_password):
            logger.error("Current master password is incorrect.")
            return False, "Current master password is incorrect."

        # Update email in users table
        with conn:
            conn.execute(
                "UPDATE users SET email = ? WHERE id = ?", (new_email.lower(), user_id)
            )
        logger.info("Email address updated successfully.")
        return True, "Email address updated successfully."
    except sqlite3.IntegrityError:
        logger.error("The new email address is already in use.")
        return False, "The new email address is already in use."
    except sqlite3.Error as e:
        logger.error(f"Error updating email address: {e}")
        return False, "Failed to update email address."


def store_password(
    conn: sqlite3.Connection, service: str, username: str, password: str, email: str
) -> None:
    """Store a new password entry in the database."""
    encrypted_service = encrypt_data(service)
    encrypted_username = encrypt_data(username)
    encrypted_password = encrypt_data(password)
    try:
        user_id = get_user_id(conn, email)
        if user_id is None:
            logger.error(f"No user found with email: {email}")
            raise Exception("User does not exist.")
        with conn:
            conn.execute(
                "INSERT INTO passwords (service, username, password, user_id) VALUES (?, ?, ?, ?)",
                (encrypted_service, encrypted_username, encrypted_password, user_id),
            )
        logger.info("Stored password for a service.")
    except sqlite3.IntegrityError:
        logger.error("Password entry for this service and username already exists.")
        raise Exception("Password entry already exists.")
    except sqlite3.Error as e:
        logger.error(f"Error storing password: {e}")
        raise Exception("Failed to store password.") from e


def retrieve_password(
    conn: sqlite3.Connection, service: str, username: str, email: str
) -> Optional[str]:
    """Retrieve a specific password entry from the database."""
    encrypted_service = encrypt_data(service)
    encrypted_username = encrypt_data(username)
    try:
        user_id = get_user_id(conn, email)
        if user_id is None:
            logger.error(f"No user found with email: {email}")
            return None
        cursor = conn.execute(
            "SELECT password FROM passwords WHERE service = ? AND username = ? AND user_id = ?",
            (encrypted_service, encrypted_username, user_id),
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


def check_existing_entry(
    conn: sqlite3.Connection, service: str, username: str, email: str
) -> bool:
    """Check if a password entry already exists for a given service and username."""
    encrypted_service = encrypt_data(service)
    encrypted_username = encrypt_data(username)
    try:
        user_id = get_user_id(conn, email)
        if user_id is None:
            logger.error(f"No user found with email: {email}")
            return False
        cursor = conn.execute(
            "SELECT 1 FROM passwords WHERE service=? AND username=? AND user_id=?",
            (encrypted_service, encrypted_username, user_id),
        )
        exists = cursor.fetchone() is not None
        logger.info("Checked existing entry for a service.")
        return exists
    except sqlite3.Error as e:
        logger.error(f"Error checking existing entry: {e}")
        return False


def get_all_passwords(
    conn: sqlite3.Connection, email: str
) -> List[Tuple[str, str, str]]:
    """Retrieve all password entries for a specific user from the database."""
    try:
        user_id = get_user_id(conn, email)
        if user_id is None:
            logger.error(f"No user found with email: {email}")
            return []
        cursor = conn.execute(
            "SELECT service, username, password FROM passwords WHERE user_id = ?",
            (user_id,),
        )
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
        logger.info("Retrieved all passwords for user.")
        return entries
    except sqlite3.Error as e:
        logger.error(f"Error retrieving all passwords: {e}")
        return []


def update_password(
    conn: sqlite3.Connection,
    email: str,
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
        user_id = get_user_id(conn, email)
        if user_id is None:
            logger.error(f"No user found with email: {email}")
            raise Exception("User does not exist.")
        with conn:
            conn.execute(
                """
                UPDATE passwords 
                SET service = ?, username = ?, password = ? 
                WHERE service = ? AND username = ? AND user_id = ?
                """,
                (
                    encrypted_new_service,
                    encrypted_new_username,
                    encrypted_password,
                    encrypted_old_service,
                    encrypted_old_username,
                    user_id,
                ),
            )
        logger.info("Updated password for a service.")
    except sqlite3.Error as e:
        logger.error(f"Failed to update password: {e}")
        raise Exception("Failed to update password.") from e


def delete_password(
    conn: sqlite3.Connection, email: str, service: str, username: str
) -> None:
    """Delete a specific password entry from the database."""
    encrypted_service = encrypt_data(service)
    encrypted_username = encrypt_data(username)
    try:
        user_id = get_user_id(conn, email)
        if user_id is None:
            logger.error(f"No user found with email: {email}")
            raise Exception("User does not exist.")
        with conn:
            conn.execute(
                "DELETE FROM passwords WHERE service = ? AND username = ? AND user_id = ?",
                (encrypted_service, encrypted_username, user_id),
            )
        logger.info("Deleted password for a service.")
    except sqlite3.Error as e:
        logger.error(f"Failed to delete password: {e}")
        raise Exception("Failed to delete password.") from e


def store_2fa_secret(conn: sqlite3.Connection, email: str, secret: str) -> None:
    """
    Store or replace the 2FA secret for a user.

    Args:
        conn (sqlite3.Connection): The database connection.
        email (str): The user's email address.
        secret (str): The 2FA secret to store.
    """
    try:
        user_id = get_user_id(conn, email)
        if user_id is None:
            logger.error(f"No user found with email: {email}")
            raise Exception("User does not exist.")
        encrypted_secret = encrypt_data(secret)
        with conn:
            conn.execute(
                """
                INSERT INTO two_factor_auth (user_id, secret) 
                VALUES (?, ?)
                ON CONFLICT(user_id) DO UPDATE SET secret = excluded.secret
                """,
                (user_id, encrypted_secret),
            )
        logger.info(f"Stored 2FA secret for user: {email}")
    except sqlite3.Error as e:
        logger.error(f"Failed to store 2FA secret: {e}")
        raise Exception("Failed to store 2FA secret.") from e


def get_2fa_secret(conn: sqlite3.Connection, email: str) -> Optional[str]:
    """
    Retrieve the decrypted 2FA secret for a user.

    Args:
        conn (sqlite3.Connection): The database connection.
        email (str): The user's email address.

    Returns:
        Optional[str]: The decrypted 2FA secret if found, else None.
    """
    try:
        user_id = get_user_id(conn, email)
        if user_id is None:
            logger.error(f"No user found with email: {email}")
            return None
        cursor = conn.execute(
            "SELECT secret FROM two_factor_auth WHERE user_id = ?",
            (user_id,),
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


def delete_2fa_secret(conn: sqlite3.Connection, email: str) -> None:
    """
    Delete the 2FA secret for a user.

    Args:
        conn (sqlite3.Connection): The database connection.
        email (str): The user's email address.
    """
    try:
        user_id = get_user_id(conn, email)
        if user_id is None:
            logger.error(f"No user found with email: {email}")
            raise Exception("User does not exist.")
        with conn:
            conn.execute(
                "DELETE FROM two_factor_auth WHERE user_id = ?",
                (user_id,),
            )
        logger.info("Deleted 2FA secret for user.")
    except sqlite3.Error as e:
        logger.error(f"Failed to delete 2FA secret: {e}")
        raise Exception("Failed to delete 2FA secret.") from e


def store_secure_note(
    conn: sqlite3.Connection, email: str, title: str, content: str
) -> None:
    """
    Store a secure note with title and content for a user.

    Args:
        conn (sqlite3.Connection): The database connection.
        email (str): The user's email address.
        title (str): The title of the secure note.
        content (str): The content of the secure note.
    """
    encrypted_title = encrypt_data(title)
    encrypted_content = encrypt_data(content)
    try:
        user_id = get_user_id(conn, email)
        if user_id is None:
            logger.error(f"No user found with email: {email}")
            raise Exception("User does not exist.")
        with conn:
            conn.execute(
                "INSERT INTO secure_notes (title, content, user_id) VALUES (?, ?, ?)",
                (encrypted_title, encrypted_content, user_id),
            )
        logger.info("Stored secure note for user.")
    except sqlite3.Error as e:
        logger.error(f"Error storing secure note: {e}")
        raise Exception("Failed to store secure note.") from e


def retrieve_secure_notes(
    conn: sqlite3.Connection, email: str
) -> List[Tuple[int, str, str]]:
    """
    Retrieve all secure notes with titles and content for a user.

    Args:
        conn (sqlite3.Connection): The database connection.
        email (str): The user's email address.

    Returns:
        List[Tuple[int, str, str]]: A list of tuples containing (id, title, content).
    """
    try:
        user_id = get_user_id(conn, email)
        if user_id is None:
            logger.error(f"No user found with email: {email}")
            return []
        cursor = conn.execute(
            "SELECT id, title, content FROM secure_notes WHERE user_id = ?",
            (user_id,),
        )
        notes = []
        for note_id, encrypted_title, encrypted_content in cursor.fetchall():
            try:
                title = decrypt_data(encrypted_title)
                content = decrypt_data(encrypted_content)
                notes.append((note_id, title, content))
            except Exception as e:
                logger.error(f"Error decrypting secure note: {e}")
        logger.info("Retrieved all secure notes for user.")
        return notes
    except sqlite3.Error as e:
        logger.error(f"Error retrieving secure notes: {e}")
        return []


def update_secure_note(
    conn: sqlite3.Connection, email: str, note_id: int, title: str, content: str
) -> None:
    """
    Update an existing secure note in the database.

    Args:
        conn (sqlite3.Connection): The database connection.
        email (str): The user's email address.
        note_id (int): The ID of the note to update.
        title (str): The new title of the secure note.
        content (str): The new content of the secure note.
    """
    encrypted_title = encrypt_data(title)
    encrypted_content = encrypt_data(content)
    try:
        user_id = get_user_id(conn, email)
        if user_id is None:
            logger.error(f"No user found with email: {email}")
            raise Exception("User does not exist.")
        with conn:
            conn.execute(
                """
                UPDATE secure_notes 
                SET title = ?, content = ? 
                WHERE id = ? AND user_id = ?
                """,
                (encrypted_title, encrypted_content, note_id, user_id),
            )
        logger.info(f"Updated secure note ID: {note_id}")
    except sqlite3.Error as e:
        logger.error(f"Failed to update secure note ID {note_id}: {e}")
        raise Exception("Failed to update secure note.") from e


def delete_secure_note(conn: sqlite3.Connection, email: str, note_id: int) -> None:
    """
    Delete a secure note from the database.

    Args:
        conn (sqlite3.Connection): The database connection.
        email (str): The user's email address.
        note_id (int): The ID of the note to delete.
    """
    try:
        user_id = get_user_id(conn, email)
        if user_id is None:
            logger.error(f"No user found with email: {email}")
            raise Exception("User does not exist.")
        with conn:
            conn.execute(
                "DELETE FROM secure_notes WHERE id = ? AND user_id = ?",
                (note_id, user_id),
            )
        logger.info(f"Deleted secure note ID: {note_id}")
    except sqlite3.Error as e:
        logger.error(f"Failed to delete secure note ID {note_id}: {e}")
        raise Exception("Failed to delete secure note.") from e


def wipe_user_data(conn: sqlite3.Connection, email: str) -> None:
    """
    Wipe all user data for a specific user.

    Args:
        conn (sqlite3.Connection): The database connection.
        email (str): The user's email address.
    """
    try:
        user_id = get_user_id(conn, email)
        if user_id is None:
            logger.warning(f"No user found with email: {email}")
            return
        with conn:
            conn.execute("DELETE FROM passwords WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM secure_notes WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM two_factor_auth WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM master_password WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        logger.info(f"User data wiped for user: {email}")
    except sqlite3.Error as e:
        logger.error(f"Error wiping user data for {email}: {e}")
        raise Exception("Failed to wipe user data.") from e


# Additional utility functions can be added here as needed.
