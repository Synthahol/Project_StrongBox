import logging
import os
import sys
import uuid

from password_generation import PasswordGenerationTab
from password_management import PasswordManagementTab
from PySide6.QtWidgets import (
    QApplication,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

# Add the root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Print sys.path to verify the paths
print("sys.path:", sys.path)

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


class PasswordManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("StrongBox - Password Manager")
        self.setGeometry(300, 300, 600, 400)  # Increased size for table view

        self.central_widget = QTabWidget()
        self.setCentralWidget(self.central_widget)

        self.conn = None
        self.cipher_suite = None  # Add cipher_suite attribute
        self.initialize_app()

    def initialize_app(self):
        from cryptography.fernet import Fernet

        from backend.database import (
            create_connection,
            initialize_db,
            is_master_password_set,
            load_or_generate_key,  # Import the key management function
        )

        db_file, ok = QInputDialog.getText(
            self,
            "Database File",
            "Enter the name of the StrongBox you want to access or create: (e.g., My Internet Passwords):",
        )
        if ok and db_file:
            # Strip any leading/trailing whitespace from the input
            database_name = db_file.strip()

            # Use the database name to load or generate the encryption key
            key = load_or_generate_key(database_name)

            # Create the cipher suite using the retrieved or generated key
            self.cipher_suite = Fernet(key)  # Store cipher_suite in self

            # Define the database path
            db_path = os.path.join(DATABASE_DIR, f"{database_name}.db")

            # Establish connection to the database
            self.conn = create_connection(db_path)
            if self.conn:
                key_id = str(uuid.uuid4())  # Generate a unique key_id using UUID
                initialize_db(self.conn, key_id)
                logger.info(f"Connected to database: {db_path} with key_id: {key_id}")

                # Check if the master password is set
                if not is_master_password_set(self.conn):
                    self.prompt_set_master_password()
                else:
                    self.prompt_verify_master_password()

                self.create_tabs()
            else:
                logger.error("Failed to connect to the database.")
                QMessageBox.critical(
                    self, "Error", "Failed to connect to the database."
                )
        else:
            logger.warning("No database name provided or operation was canceled.")
            QMessageBox.warning(
                self,
                "Operation Canceled",
                "No database name provided or operation was canceled.",
            )

    def prompt_set_master_password(self):
        while True:
            password, ok = QInputDialog.getText(
                self,
                "Set Master Password",
                "Enter master password:",
                QLineEdit.Password,
            )
            if ok and password:
                confirm_password, ok = QInputDialog.getText(
                    self,
                    "Confirm Master Password",
                    "Confirm master password:",
                    QLineEdit.Password,
                )
                if ok and password == confirm_password:
                    from backend.database import set_master_password

                    set_master_password(self.conn, password)
                    logger.info("Master password set successfully.")
                    QMessageBox.information(
                        self, "Success", "Master password set successfully!"
                    )
                    break
                else:
                    logger.warning("Passwords do not match.")
                    QMessageBox.warning(
                        self, "Error", "Passwords do not match. Please try again."
                    )
            else:
                logger.warning("Master password is required to proceed.")
                QMessageBox.warning(
                    self, "Error", "Master password is required to proceed."
                )

    def prompt_verify_master_password(self):
        while True:
            password, ok = QInputDialog.getText(
                self,
                "Verify Master Password",
                "Enter master password:",
                QLineEdit.Password,
            )
            if ok and password:
                from backend.database import verify_master_password

                if verify_master_password(self.conn, password):
                    logger.info("Master password verified successfully.")
                    QMessageBox.information(
                        self, "Success", "Master password verified successfully!"
                    )
                    break
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
                sys.exit()

    def create_tabs(self):
        # Tab for entering service/username/password information
        self.password_management_tab = PasswordManagementTab(
            self.conn, self.cipher_suite
        )

        # Tab for password generation
        self.password_generation_tab = PasswordGenerationTab()

        # Tab for showing stored passwords
        self.stored_passwords_tab = QWidget()
        self.stored_passwords_layout = QVBoxLayout(self.stored_passwords_tab)
        self.stored_passwords_label = QLabel("Stored Passwords")
        self.stored_passwords_layout.addWidget(self.stored_passwords_label)

        # Passwords table
        self.password_table = QTableWidget()
        self.password_table.setColumnCount(4)
        self.password_table.setHorizontalHeaderLabels(
            ["Service", "Username", "Password", "Action"]
        )
        self.stored_passwords_layout.addWidget(self.password_table)

        # Load stored passwords
        self.load_passwords()

        # Add the tabs to the central widget
        self.central_widget.addTab(self.password_management_tab, "Passwords")
        self.central_widget.addTab(self.password_generation_tab, "Password Generator")
        self.central_widget.addTab(self.stored_passwords_tab, "Stored Passwords")

    def load_passwords(self):
        self.password_table.setRowCount(0)
        from backend.database import get_all_passwords

        passwords = get_all_passwords(self.conn)
        for row_num, (service, username, encrypted_password) in enumerate(passwords):
            self.password_table.insertRow(row_num)
            self.password_table.setItem(row_num, 0, QTableWidgetItem(service))
            self.password_table.setItem(row_num, 1, QTableWidgetItem(username))

            # Decrypt the password using cipher_suite
            try:
                password = self.cipher_suite.decrypt(
                    encrypted_password.encode()
                ).decode()
                self.password_table.setItem(row_num, 2, QTableWidgetItem(password))
            except Exception as e:
                logger.error(f"Failed to decrypt password for {service}: {e}")
                self.password_table.setItem(
                    row_num, 2, QTableWidgetItem("Decryption Error")
                )

            show_btn = QPushButton("Show")
            show_btn.clicked.connect(lambda ch, r=row_num: self.show_password(r))
            self.password_table.setCellWidget(row_num, 3, show_btn)

    def show_password(self, row):
        service = self.password_table.item(row, 0).text()
        from backend.database import retrieve_password

        username, password = retrieve_password(self.conn, service, self.cipher_suite)
        if username and password:
            QMessageBox.information(
                self,
                "Password Details",
                f"Service: {service}\nUsername: {username}\nPassword: {password}",
            )
        else:
            QMessageBox.warning(self, "Error", "Failed to retrieve password details.")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PasswordManager()
    window.show()
    logger.info("StrongBox application started.")
    sys.exit(app.exec())
