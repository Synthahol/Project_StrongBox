# backend/secure_notes.py

import logging
from dataclasses import dataclass
from typing import List, Optional

from backend.database import execute_query, fetch_all, fetch_one
from session_manager import SessionManager

logger = logging.getLogger(__name__)


@dataclass
class SecureNote:
    id: int
    title: str
    content: str  # Encrypted content


def create_secure_notes_table():
    """Create the secure_notes table if it doesn't exist."""
    create_table_query = """
    CREATE TABLE IF NOT EXISTS secure_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL
    );
    """
    execute_query(create_table_query)
    logger.debug("secure_notes table ensured in database.")


def add_secure_note(title: str, content: str):
    """Add a new secure note to the database."""
    insert_query = """
    INSERT INTO secure_notes (title, content) VALUES (?, ?);
    """
    execute_query(insert_query, (title, content))
    logger.info(f"Added new secure note with title: {title}")


def get_all_secure_notes() -> List[SecureNote]:
    """Retrieve all secure notes from the database."""
    select_query = "SELECT id, title, content FROM secure_notes;"
    rows = fetch_all(select_query)
    notes = [SecureNote(id=row[0], title=row[1], content=row[2]) for row in rows]
    logger.debug(f"Retrieved {len(notes)} secure notes from the database.")
    return notes


def get_secure_note_by_id(note_id: int) -> Optional[SecureNote]:
    """Retrieve a single secure note by its ID."""
    select_query = "SELECT id, title, content FROM secure_notes WHERE id = ?;"
    row = fetch_one(select_query, (note_id,))
    if row:
        logger.debug(f"Retrieved secure note with ID: {note_id}")
        return SecureNote(id=row[0], title=row[1], content=row[2])
    logger.warning(f"No secure note found with ID: {note_id}")
    return None


def update_secure_note(note_id: int, title: str, content: str):
    """Update an existing secure note."""
    update_query = """
    UPDATE secure_notes
    SET title = ?, content = ?
    WHERE id = ?;
    """
    execute_query(update_query, (title, content, note_id))
    logger.info(f"Updated secure note with ID: {note_id}")


def delete_secure_note(note_id: int):
    """Delete a secure note from the database."""
    delete_query = "DELETE FROM secure_notes WHERE id = ?;"
    execute_query(delete_query, (note_id,))
    logger.info(f"Deleted secure note with ID: {note_id}")


def encrypt_content(plaintext: str) -> str:
    """Encrypt the plaintext using the cipher_suite from the session."""
    session = SessionManager.get_instance()
    cipher_suite = session.get_cipher_suite()
    if not cipher_suite:
        logger.error("Cipher suite not initialized. Cannot encrypt content.")
        raise ValueError("Cipher suite not initialized.")
    encrypted = cipher_suite.encrypt(plaintext.encode()).decode()
    logger.debug("Content encrypted successfully.")
    return encrypted


def decrypt_content(encrypted_text: str) -> str:
    """Decrypt the encrypted text using the cipher_suite from the session."""
    session = SessionManager.get_instance()
    cipher_suite = session.get_cipher_suite()
    if not cipher_suite:
        logger.error("Cipher suite not initialized. Cannot decrypt content.")
        raise ValueError("Cipher suite not initialized.")
    decrypted = cipher_suite.decrypt(encrypted_text.encode()).decode()
    logger.debug("Content decrypted successfully.")
    return decrypted
