import logging
import os
import sys
import uuid

from password_generation import PasswordGenerationTab
from password_management import PasswordManagementTab
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
)

# Add the root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from config import DATABASE_DIR, LOG_FILE
except ModuleNotFoundError as e:
    print(f"Error importing config: {e}")
    sys.exit(1)

# Ensure the database directory exists
os.makedirs(DATABASE_DIR, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


class WelcomeDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Welcome to StrongBox!")
        layout = QVBoxLayout()
        label = QLabel("Welcome to StrongBox! Click OK to proceed.")
        layout.addWidget(label)
        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        layout.addWidget(ok_button)
        self.setLayout(layout)


class PasswordManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("StrongBox - Password Manager")
        self.setGeometry(300, 300, 600, 400)  # Increased size for table view

        self.central_widget = QTabWidget()
        self.setCentralWidget(self.central_widget)

        self.conn = None
        self.is_master_password_verified = False  # Flag to track verification state
        self.cipher_suite = None
        self.initialize_app()

    def initialize_app(self):
        from cryptography.fernet import Fernet

        from backend.database import (
            create_connection,
            initialize_db,
            is_master_password_set,
            load_or_generate_key,
        )

        # Use a default database name
        database_name = "DefaultStrongBox"

        # Use the database name to load or generate the encryption key
        key = load_or_generate_key(database_name)

        # Create the cipher suite using the retrieved or generated key
        self.cipher_suite = Fernet(key)

        # Define the database path
        db_path = os.path.join(DATABASE_DIR, f"{database_name}.db")

        # Establish connection to the database
        self.conn = create_connection(db_path)
        if self.conn:
            key_id = str(uuid.uuid4())
            initialize_db(self.conn, key_id)
            logger.info(f"Connected to database: {db_path} with key_id: {key_id}")

            # Check if the master password is set
            if not is_master_password_set(self.conn):
                self.set_master_password()
            else:
                self.verify_master_password()

            self.create_tabs()
        else:
            self.show_error("Failed to connect to the database.")
            logger.error("Failed to connect to the database.")
            return

    def create_tabs(self):
        self.password_management_tab = PasswordManagementTab(
            self.conn, self.cipher_suite
        )
        self.password_generation_tab = PasswordGenerationTab()
        self.central_widget.addTab(self.password_generation_tab, "Password Generator")
        self.central_widget.addTab(self.password_management_tab, "Manage Passwords")

    def set_master_password(self):
        while True:
            password, ok = self.prompt_user_input(
                "Set Master Password", "Enter a master password:", QLineEdit.Password
            )
            if ok and password:
                confirm_password, ok = self.prompt_user_input(
                    "Confirm Master Password",
                    "Confirm master password:",
                    QLineEdit.Password,
                )
                if ok and password == confirm_password:
                    self.store_master_password(password)
                    break
                else:
                    self.show_warning("Passwords do not match. Please try again.")
            else:
                self.show_warning("Master password is required to proceed.")

    def verify_master_password(self):
        from backend.database import verify_master_password

        while True:
            password, ok = QInputDialog.getText(
                self,
                "Verify Master Password",
                "Enter master password:",
                QLineEdit.Password,
            )
            if ok and password:
                if verify_master_password(self.conn, password):
                    logger.info("Master password verified successfully.")
                    return True
                else:
                    logger.warning("Incorrect master password.")
                    QMessageBox.warning(
                        self, "Error", "Incorrect master password. Please try again."
                    )
            else:
                logger.warning("Master password is required to proceed.")
                QMessageBox.warning(
                    self, "Error", "Master password is required to proceed."
                )
                return False  # Add this line to return False if the user cancels

    def prompt_user_input(self, title, label, echo_mode=QLineEdit.Normal):
        return QInputDialog.getText(self, title, label, echo_mode)

    def store_master_password(self, password):
        from backend.database import set_master_password

        try:
            set_master_password(self.conn, password)
            self.show_info("Master password set successfully!")
            logger.info("Master password set successfully.")
        except ValueError as ve:
            self.show_warning(f"Password validation failed: {ve}")

    def show_info(self, message):
        QMessageBox.information(self, "Info", message)

    def show_warning(self, message):
        QMessageBox.warning(self, "Warning", message)

    def show_error(self, message):
        QMessageBox.critical(self, "Error", message)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    welcome_dialog = WelcomeDialog()
    welcome_dialog.exec()

    window = PasswordManager()
    window.show()
    logger.info("StrongBox application started.")
    sys.exit(app.exec())
