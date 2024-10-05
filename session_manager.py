# session_manager.py

import threading


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

    def verify_master_password(self, input_password: str) -> bool:
        """
        Verifies the input password against the stored master password.

        Args:
            input_password (str): The password to verify.

        Returns:
            bool: True if the passwords match, False otherwise.
        """
        is_verified = self.__master_password == input_password
        if is_verified:
            self.__session_active = (
                True  # Reactivate session upon successful verification
            )
        return is_verified

    def is_session_active(self) -> bool:
        """
        Checks if the session is currently active.

        Returns:
            bool: True if the session is active, False otherwise.
        """
        return self.__session_active

    # Optional: Remove the getter to enhance security
    # def get_master_password(self) -> str:
    #     """
    #     Retrieves the master password stored in the session.

    #     Returns:
    #         str: The master password.
    #     """
    #     return self.__master_password
