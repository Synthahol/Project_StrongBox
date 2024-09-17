# session_manager.py


class SessionManager:
    _instance = None

    def __init__(self):
        self._master_password = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = SessionManager()
        return cls._instance

    def set_master_password(self, password):
        self._master_password = password

    def get_master_password(self):
        return self._master_password

    def clear_master_password(self):
        self._master_password = None  # Clear the password when not needed
