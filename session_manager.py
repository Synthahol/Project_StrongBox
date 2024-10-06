# session_manager.py

import logging
import sqlite3
import threading
from typing import Optional

import bcrypt

logger = logging.getLogger(__name__)


class SessionManager:
    """
    A thread-safe singleton class responsible for managing session data, including the master password.
    """

    _instance = None
    _lock = threading.Lock()
    _initialized = False  # Flag to prevent re-initialization

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(SessionManager, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not self.__class__._initialized:
            self.__master_password = None
            self.__session_active = False  # Track session status
            self.__class__._initialized = True

    def set_master_password(self, master_password: str):
        """
        Sets the master password for the session.

        Args:
            master_password (str): The master password entered by the user.
        """
        self.__master_password = master_password
        self.__session_active = True  # Activate session upon setting password

    def clear_master_password(self):
        """
        Clears the master password from the session and deactivates the session.
        """
        self.__master_password = None
        self.__session_active = False

    def verify_master_password(
        self, input_password: Optional[str], conn: sqlite3.Connection
    ) -> bool:
        """
        Verifies the input password against the hashed master password stored in the database.

        Args:
            input_password (Optional[str]): The password to verify.
            conn (sqlite3.Connection): The database connection.

        Returns:
            bool: True if the password is correct, False otherwise.
        """
        if input_password is None:
            logger.error("No input password provided for verification.")
            return False

        try:
            cursor = conn.execute("SELECT password FROM master_password WHERE id = 1")
            row = cursor.fetchone()
            if row:
                stored_hashed_password = row[0]
                # Ensure stored_hashed_password is bytes
                if isinstance(stored_hashed_password, str):
                    stored_hashed_password = stored_hashed_password.encode("utf-8")
                is_verified = bcrypt.checkpw(
                    input_password.encode("utf-8"), stored_hashed_password
                )
                if is_verified:
                    self.set_master_password(input_password)  # Store in session
                    logger.info("Master password verified and stored in session.")
                    return True
                else:
                    logger.warning("Master password verification failed.")
                    return False
            else:
                logger.warning("Master password not set in the database.")
                return False
        except sqlite3.Error as e:
            logger.error(f"Error verifying master password: {e}")
            return False

    def is_session_active(self) -> bool:
        """
        Checks if the session is currently active.

        Returns:
            bool: True if the session is active, False otherwise.
        """
        return self.__session_active

    def get_master_password(self) -> Optional[str]:
        """
        Retrieves the master password stored in the session.

        Returns:
            Optional[str]: The master password if set, else None.
        """
        return self.__master_password
