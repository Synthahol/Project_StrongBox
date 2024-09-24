# session_manager.py

import threading


class SessionManager:
    """
    A singleton class responsible for managing the session data, including the master password.
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(SessionManager, cls).__new__(cls)
            return cls._instance

    def __init__(self):
        self.__master_password = None

    def set_master_password(self, master_password: str):
        """
        Sets the master password for the session.

        Args:
            master_password (str): The master password entered by the user.
        """
        self.__master_password = master_password

    def get_master_password(self) -> str:
        """
        Retrieves the master password stored in the session.

        Returns:
            str: The master password.
        """
        return self.__master_password

    def clear_master_password(self):
        """
        Clears the master password from the session.
        """
        self.__master_password = None
