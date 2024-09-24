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
    try:
        encrypted_title = encrypt_data(title)
        encrypted_content = encrypt_data(content)
        execute_query(
            conn,
            "INSERT INTO secure_notes (title, content) VALUES (?, ?);",
            (encrypted_title, encrypted_content),
        )
        logger.info("Added a secure note.")
    except Exception as e:
        logger.error(f"Error adding secure note: {e}")
        raise Exception("Failed to add secure note.")


def get_all_secure_notes(conn) -> List[SecureNote]:
    """Retrieve all secure notes from the database."""
    notes = []
    try:
        rows = fetch_all(conn, "SELECT id, title, content FROM secure_notes;")
        for row in rows:
            try:
                decrypted_title = decrypt_data(row[1])
                decrypted_content = decrypt_data(row[2])
                notes.append(
                    SecureNote(
                        id=row[0], title=decrypted_title, content=decrypted_content
                    )
                )
            except Exception as e:
                logger.error(f"Error decrypting note ID {row[0]}: {e}")
        logger.debug(f"Retrieved {len(notes)} secure notes.")
    except Exception as e:
        logger.error(f"Error retrieving secure notes: {e}")
        raise Exception("Failed to retrieve secure notes.")
    return notes


def get_secure_note_by_id(conn, note_id: int) -> Optional[SecureNote]:
    """Retrieve a single secure note by its ID."""
    try:
        row = fetch_one(
            conn,
            "SELECT id, title, content FROM secure_notes WHERE id = ?;",
            (note_id,),
        )
        if row:
            try:
                decrypted_title = decrypt_data(row[1])
                decrypted_content = decrypt_data(row[2])
                logger.debug(f"Retrieved secure note ID: {note_id}")
                return SecureNote(
                    id=row[0], title=decrypted_title, content=decrypted_content
                )
            except Exception as e:
                logger.error(f"Error decrypting note ID {note_id}: {e}")
                raise Exception("Failed to decrypt secure note.")
        else:
            logger.warning(f"No secure note found with ID: {note_id}")
            return None
    except Exception as e:
        logger.error(f"Error retrieving secure note by ID {note_id}: {e}")
        raise Exception("Failed to retrieve secure note by ID.")


def update_secure_note(
    conn,
    note_id: int,
    new_title: str,
    new_content: str,
):
    """Update an existing secure note."""
    try:
        encrypted_new_title = encrypt_data(new_title)
        encrypted_new_content = encrypt_data(new_content)
        execute_query(
            conn,
            """
            UPDATE secure_notes 
            SET title = ?, content = ? 
            WHERE id = ?;
            """,
            (encrypted_new_title, encrypted_new_content, note_id),
        )
        logger.info(f"Updated secure note ID: {note_id}")
    except Exception as e:
        logger.error(f"Error updating secure note ID {note_id}: {e}")
        raise Exception("Failed to update secure note.")


def delete_secure_note(conn, note_id: int):
    """Delete a secure note by its ID."""
    try:
        execute_query(conn, "DELETE FROM secure_notes WHERE id = ?;", (note_id,))
        logger.info(f"Deleted secure note ID: {note_id}")
    except Exception as e:
        logger.error(f"Error deleting secure note ID {note_id}: {e}")
        raise Exception("Failed to delete secure note.")
