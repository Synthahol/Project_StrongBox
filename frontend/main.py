import logging
import os
import sys
import uuid

from blueprints import ButtonFactory, CustomMessageBox
from password_generation import PasswordGenerationTab
from password_management import PasswordManagementTab
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from backend.settings import SettingsTab

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


class CustomInputDialog(QDialog):
    def __init__(self, title, label, echo_mode=QLineEdit.Normal, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)

        layout = QVBoxLayout(self)

        self.label = QLabel(label)
        layout.addWidget(self.label)

        self.input_field = QLineEdit()
        self.input_field.setEchoMode(echo_mode)
        layout.addWidget(self.input_field)

        # Use ButtonFactory for creating the OK and Cancel buttons
        button_factory = ButtonFactory(self)
        button_layout = button_factory.create_button_with_layout(
            "", "OK", 100, self.accept
        )
        layout.addLayout(button_layout)

        cancel_button = QPushButton("Cancel")
        cancel_button.setMinimumWidth(100)
        cancel_button.clicked.connect(self.reject)
        layout.addWidget(cancel_button)

        self.setLayout(layout)

    def get_input(self):
        return self.input_field.text()


class WelcomeDialog(QDialog):
    def __init__(self):
        super().__init__()

        # Set the custom icon for the dialog title bar
        self.setWindowIcon(QIcon(r"frontend/icons/muscles.png"))

        self.setWindowTitle("Welcome to StrongBox!")

        layout = QVBoxLayout()

        label = QLabel("Welcome to StrongBox! Click OK to proceed.")
        layout.addWidget(label)

        # Use ButtonFactory for the OK button
        button_factory = ButtonFactory(self)
        button_layout = button_factory.create_button_with_layout(
            "", "OK", 100, self.accept
        )
        layout.addLayout(button_layout)

        self.setLayout(layout)


class VerifyMasterPasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle("Verify Master Password")
        self.setMinimumSize(400, 100)

        layout = QVBoxLayout(self)

        self.label = QLabel("Enter master password:")
        layout.addWidget(self.label)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        # Create an instance of ButtonFactory
        button_factory = ButtonFactory(self)

        # Use ButtonFactory to create both OK and Cancel buttons
        buttons = [("OK", 100, self.accept), ("Cancel", 100, self.reject)]
        button_layout = button_factory.create_buttons_with_spacing(buttons)

        layout.addLayout(button_layout)
        self.setLayout(layout)

    def get_password(self):
        return self.password_input.text()


class PasswordManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.conn = None  # Initialize conn
        self.cipher_suite = None  # Initialize cipher_suite

        self.setWindowTitle("StrongBox")
        self.setGeometry(300, 300, 800, 600)  # Adjusted size

        # Set the custom icon for the title bar
        self.setWindowIcon(QIcon(r"frontend/icons/muscles.png"))

        # Create the main widget and set it as the central widget
        self.main_widget = QWidget(self)
        self.setCentralWidget(self.main_widget)

        # Main layout for the window
        main_layout = QHBoxLayout(self.main_widget)

        # Left side - column with buttons
        left_column = QVBoxLayout()
        left_column.setContentsMargins(10, 10, 10, 10)

        # Password Generator button with custom icon
        self.generator_button = QPushButton("Password Generator")
        self.generator_button.setIcon(
            QIcon(r"frontend/icons/magic-wand.png")
        )  # Set your custom icon path
        self.generator_button.clicked.connect(self.show_password_generator)
        left_column.addWidget(self.generator_button)

        # Manage Passwords button with custom icon
        self.manage_button = QPushButton("Manage Passwords")
        self.manage_button.setIcon(
            QIcon(r"frontend/icons/safe-box_64x64.png")
        )  # Set your custom icon path
        self.manage_button.clicked.connect(self.show_manage_passwords)
        left_column.addWidget(self.manage_button)

        # Settings button with custom icon
        self.settings_button = QPushButton("Visual Settings")
        self.settings_button.setIcon(QIcon(r"frontend/icons/settings.png"))
        self.settings_button.setStyleSheet("text-align: left; padding-left: 0px;")
        self.settings_button.clicked.connect(self.show_settings)
        left_column.addWidget(self.settings_button)

        # Adding a spacer to push the buttons to the top
        left_column.addStretch()

        # Right side - stacked widget
        self.stacked_widget = QStackedWidget()

        # Adding left column and stacked widget to the main layout
        main_layout.addLayout(left_column)
        main_layout.addWidget(self.stacked_widget)

        # Initialize the application
        self.initialize_app()

        # Maximize the window instead of going full screen
        self.showMaximized()

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
                if not self.verify_master_password():
                    CustomMessageBox(
                        "Error",
                        "Master password verification failed.",
                        QMessageBox.Critical,
                    ).show_message()
                    return

            # Create the Password Generation page, Manage Passwords page, and Settings page after connection is established
            self.password_generation_tab = PasswordGenerationTab()
            self.password_management_tab = PasswordManagementTab(
                self.conn, self.cipher_suite
            )
            self.settings_tab = SettingsTab(
                main_window=self
            )  # Initialize the SettingsTab

            # Add all tabs to the stacked widget
            self.stacked_widget.addWidget(self.password_generation_tab)
            self.stacked_widget.addWidget(self.password_management_tab)
            self.stacked_widget.addWidget(self.settings_tab)

            self.show_password_generator()  # Show the Password Generator by default
        else:
            CustomMessageBox(
                "Error", "Failed to connect to the database.", QMessageBox.Critical
            ).show_message()
            logger.error("Failed to connect to the database.")
            return

    def show_password_generator(self):
        self.stacked_widget.setCurrentWidget(self.password_generation_tab)

    def show_manage_passwords(self):
        self.stacked_widget.setCurrentWidget(self.password_management_tab)

    def show_settings(self):
        """Switches the view to the Settings tab."""
        self.stacked_widget.setCurrentWidget(self.settings_tab)

    def set_master_password(self):
        while True:
            # Use the custom input dialog for entering the master password
            dialog = CustomInputDialog(
                "Set Master Password",
                "Enter a master password:",
                QLineEdit.Password,
                self,
            )
            if dialog.exec() == QDialog.Accepted:
                password = dialog.get_input()
                if password:
                    # Use the custom input dialog for confirming the master password
                    confirm_dialog = CustomInputDialog(
                        "Confirm Master Password",
                        "Confirm master password:",
                        QLineEdit.Password,
                        self,
                    )
                    if confirm_dialog.exec() == QDialog.Accepted:
                        confirm_password = confirm_dialog.get_input()
                        if password == confirm_password:
                            self.store_master_password(password)
                            break
                        else:
                            CustomMessageBox(
                                "Warning",
                                "Passwords do not match. Please try again.",
                                QMessageBox.Warning,
                            ).show_message()
                    else:
                        CustomMessageBox(
                            "Warning",
                            "Confirmation of master password is required.",
                            QMessageBox.Warning,
                        ).show_message()
                else:
                    CustomMessageBox(
                        "Warning",
                        "Master password is required to proceed.",
                        QMessageBox.Warning,
                    ).show_message()
            else:
                CustomMessageBox(
                    "Warning",
                    "Master password is required to proceed.",
                    QMessageBox.Warning,
                ).show_message()

    def verify_master_password(self):
        from backend.database import verify_master_password

        while True:
            dialog = VerifyMasterPasswordDialog(self)

            if dialog.exec() == QDialog.Accepted:
                password = dialog.get_password()
                if password and verify_master_password(self.conn, password):
                    logger.info("Master password verified successfully.")
                    return True
                else:
                    CustomMessageBox(
                        "Warning",
                        "Incorrect master password. Please try again.",
                        QMessageBox.Warning,
                    ).show_message()
            else:
                CustomMessageBox(
                    "Warning",
                    "Master password is required to proceed.",
                    QMessageBox.Warning,
                ).show_message()
                return False  # Return False if the user cancels

    def prompt_user_input(self, title, label, echo_mode=QLineEdit.Normal):
        dialog = CustomInputDialog(title, label, echo_mode, self)
        if dialog.exec() == QDialog.Accepted:
            return dialog.get_input(), True
        else:
            return "", False

    def store_master_password(self, password):
        from backend.database import set_master_password

        try:
            set_master_password(self.conn, password)
            CustomMessageBox(
                "Info", "Master password set successfully!", QMessageBox.Information
            ).show_message()
            logger.info("Master password set successfully.")
        except ValueError as ve:
            CustomMessageBox(
                "Warning", f"Password validation failed: {ve}", QMessageBox.Warning
            ).show_message()

    def show_info(self, message):
        CustomMessageBox("Info", message, QMessageBox.Information).show_message()

    def show_warning(self, message):
        CustomMessageBox("Warning", message, QMessageBox.Warning).show_message()

    def show_copied_message(self, message="Text copied to clipboard!"):
        CustomMessageBox("Copied", message, QMessageBox.Information).show_message()

    def show_success_message(self, message="Operation completed successfully!"):
        CustomMessageBox("Success", message, QMessageBox.Information).show_message()


def main():
    app = QApplication(sys.argv)

    # Load stylesheet from style.qss
    stylesheet_path = os.path.join(os.path.dirname(__file__), "styles", "style.qss")
    with open(stylesheet_path, "r") as file:
        app.setStyleSheet(file.read())

    welcome_dialog = WelcomeDialog()
    welcome_dialog.exec()

    window = PasswordManager()
    window.show()
    logger.info("StrongBox application started.")
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
