# backend/secure_notes.py

import logging
from dataclasses import dataclass
from typing import List, Optional

from backend.database import (
    decrypt_data,
    encrypt_data,
    execute_query,
    fetch_all,
    fetch_one,
)

logger = logging.getLogger(__name__)


@dataclass
class SecureNote:
    id: int
    title: str
    content: str  # Decrypted content


def create_secure_notes_table(conn):
    """Create the secure_notes table if it doesn't exist."""
    execute_query(
        conn,
        """
        CREATE TABLE IF NOT EXISTS secure_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL
        );
        """,
    )
    logger.debug("Ensured secure_notes table exists.")


def add_secure_note(conn, title: str, content: str):
    """Add a new secure note to the database."""
    encrypted_content = encrypt_data(content)
    execute_query(
        conn,
        "INSERT INTO secure_notes (title, content) VALUES (?, ?);",
        (title, encrypted_content),
    )
    logger.info(f"Added secure note with title: {title}")


def get_all_secure_notes(conn) -> List[SecureNote]:
    """Retrieve all secure notes from the database."""
    notes = []
    for row in fetch_all(conn, "SELECT id, title, content FROM secure_notes;"):
        try:
            decrypted_content = decrypt_data(row[2])
            notes.append(SecureNote(id=row[0], title=row[1], content=decrypted_content))
        except Exception as e:
            logger.error(f"Error decrypting note ID {row[0]}: {e}")
    logger.debug(f"Retrieved {len(notes)} secure notes.")
    return notes


def get_secure_note_by_id(conn, note_id: int) -> Optional[SecureNote]:
    """Retrieve a single secure note by its ID."""
    row = fetch_one(
        conn, "SELECT id, title, content FROM secure_notes WHERE id = ?;", (note_id,)
    )
    if row:
        try:
            decrypted_content = decrypt_data(row[2])
            logger.debug(f"Retrieved secure note ID: {note_id}")
            return SecureNote(id=row[0], title=row[1], content=decrypted_content)
        except Exception as e:
            logger.error(f"Error decrypting note ID {note_id}: {e}")
    else:
        logger.warning(f"No secure note found with ID: {note_id}")
    return None


def update_secure_note(conn, note_id: int, new_title: str, new_content: str):
    """Update an existing secure note."""
    encrypted_content = encrypt_data(new_content)
    execute_query(
        conn,
        "UPDATE secure_notes SET title = ?, content = ? WHERE id = ?;",
        (new_title, encrypted_content, note_id),
    )
    logger.info(f"Updated secure note ID: {note_id}")


def delete_secure_note(conn, note_id: int):
    """Delete a secure note by its ID."""
    execute_query(conn, "DELETE FROM secure_notes WHERE id = ?;", (note_id,))
    logger.info(f"Deleted secure note ID: {note_id}")
