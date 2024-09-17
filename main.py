# main.py

import logging
import os
import sys
import uuid

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
from frontend.blueprints import ButtonFactory, CustomMessageBox
from frontend.passkey_manager_tab import PasskeyManagerTab
from frontend.password_generation import PasswordGenerationTab
from frontend.password_management import PasswordManagementTab
from session_manager import SessionManager

# Add the root directory to sys.path
sys.path.extend(
    [
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
    ]
)

try:
    from backend.config import DATABASE_DIR, LOG_FILE
except ModuleNotFoundError as error:
    print(f"Error importing config: {error}")
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
    """Custom input dialog for user input with customizable title and label."""

    def __init__(self, title, label, echo_mode=QLineEdit.Normal, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        layout = QVBoxLayout(self)

        # Add the label and input field
        self.label = QLabel(label)
        layout.addWidget(self.label)

        self.input_field = QLineEdit()
        self.input_field.setEchoMode(echo_mode)
        layout.addWidget(self.input_field)

        # Use ButtonFactory to create consistent button layout
        button_factory = ButtonFactory(self)
        buttons = [("OK", 100, self.accept), ("Cancel", 100, self.reject)]
        button_layout = button_factory.create_buttons_with_spacing(buttons)

        # Ensure the button layout is horizontal
        layout.addLayout(button_layout)

    def get_input(self):
        """Return the input from the line edit."""
        return self.input_field.text()


class WelcomeDialog(QDialog):
    """Welcome dialog displayed when the application starts."""

    def __init__(self):
        super().__init__()
        self.setWindowIcon(QIcon(r"frontend/icons/encryption.png"))
        self.setWindowTitle("Welcome to Fortalice!")

        layout = QVBoxLayout()
        label = QLabel("Welcome to Fortalice! Click OK to proceed.")
        layout.addWidget(label)

        button_factory = ButtonFactory(self)
        button_layout = button_factory.create_button_with_layout(
            "", "OK", 100, self.accept
        )
        layout.addLayout(button_layout)

        self.setLayout(layout)


class VerifyMasterPasswordDialog(QDialog):
    """Dialog for verifying the master password input by the user."""

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

        button_factory = ButtonFactory(self)
        buttons = [("OK", 100, self.accept), ("Cancel", 100, self.reject)]
        button_layout = button_factory.create_buttons_with_spacing(buttons)

        layout.addLayout(button_layout)
        self.setLayout(layout)

    def get_password(self):
        """Return the entered master password."""
        return self.password_input.text()


class PasswordManager(QMainWindow):
    """Main application window for Fortalice, managing the main functionalities."""

    def __init__(self):
        super().__init__()
        self.conn = None
        self.cipher_suite = None
        self.password_generation_tab = None
        self.password_management_tab = None
        self.passkey_manager_tab = None
        self.settings_tab = None

        self.setWindowTitle("Fortalice")
        self.setGeometry(300, 300, 800, 600)
        self.setWindowIcon(QIcon(r"frontend/icons/encryption.png"))

        self.main_widget = QWidget(self)
        self.setCentralWidget(self.main_widget)

        main_layout = QHBoxLayout(self.main_widget)

        left_column = QVBoxLayout()
        left_column.setContentsMargins(10, 10, 10, 10)

        self._setup_buttons(left_column)

        left_column.addStretch()
        self.stacked_widget = QStackedWidget()

        main_layout.addLayout(left_column)
        main_layout.addWidget(self.stacked_widget)

        self.initialize_app()
        self.showMaximized()

    def _setup_buttons(self, layout):
        """Set up the buttons for navigating different tabs."""
        self.generator_button = self._create_button(
            "Password Generator",
            r"frontend/icons/magic-wand.png",
            self.show_password_generator,
        )
        layout.addWidget(self.generator_button)

        self.manage_button = self._create_button(
            "Manage Passwords",
            r"frontend/icons/safe-box.png",
            self.show_manage_passwords,
        )
        layout.addWidget(self.manage_button)

        # Add the new passkey manager button
        self.passkey_button = self._create_button(
            "Manage Passkeys",
            r"frontend/icons/passkey.png",  # Make sure this icon exists
            self.show_passkey_manager,
        )
        layout.addWidget(self.passkey_button)

        self.settings_button = self._create_button(
            "Visual Settings", r"frontend/icons/settings.png", self.show_settings
        )
        self.settings_button.setStyleSheet("text-align: left; padding-left: 0px;")
        layout.addWidget(self.settings_button)

    def _create_button(self, text, icon_path, callback):
        """Create a button with text, icon, and a callback function."""
        button = QPushButton(text)
        button.setIcon(QIcon(icon_path))
        button.clicked.connect(callback)
        return button

    def initialize_app(self):
        """Initialize the application by setting up the database connection and cipher suite."""
        from backend.database import (
            create_connection,
            initialize_db,
            is_master_password_set,
        )

        # Remove references to db_path since create_connection no longer requires it
        self.conn = create_connection()

        if self.conn:
            key_id = str(uuid.uuid4())
            initialize_db(self.conn, key_id)
            logger.info("Database connection successful.")

            if not is_master_password_set(self.conn):
                self.set_master_password()
            elif not self.verify_master_password():
                CustomMessageBox(
                    "Error",
                    "Master password verification failed.",
                    QMessageBox.Critical,
                ).show_message()
                return

            self._setup_tabs()
        else:
            CustomMessageBox(
                "Error", "Failed to connect to the database.", QMessageBox.Critical
            ).show_message()
            logger.error("Failed to connect to the database.")

    def _setup_tabs(self):
        """Set up the main tabs of the application."""
        self.password_generation_tab = PasswordGenerationTab()
        self.password_management_tab = PasswordManagementTab()
        self.passkey_manager_tab = PasskeyManagerTab()
        self.settings_tab = SettingsTab(main_window=self)

        self.stacked_widget.addWidget(self.password_generation_tab)
        self.stacked_widget.addWidget(self.password_management_tab)
        self.stacked_widget.addWidget(self.passkey_manager_tab)
        self.stacked_widget.addWidget(self.settings_tab)

        self.show_password_generator()

    def show_password_generator(self):
        """Show the password generation tab."""
        self.stacked_widget.setCurrentWidget(self.password_generation_tab)

    def show_manage_passwords(self):
        """Show the manage passwords tab."""
        self.stacked_widget.setCurrentWidget(self.password_management_tab)

    def show_passkey_manager(self):
        """Show the passkey manager tab."""
        self.stacked_widget.setCurrentWidget(self.passkey_manager_tab)

    def show_settings(self):
        """Show the settings tab."""
        self.stacked_widget.setCurrentWidget(self.settings_tab)

    def set_master_password(self):
        """Prompt the user to set the master password using a custom input dialog."""
        while True:
            # Format the dialog text using HTML to separate each sentence into its own paragraph
            dialog_text = (
                "<p>Enter a master password. It must contain lowercase, uppercase, number, "
                "special character and be at least 8 characters long.</p>"
                "<p>Hint: use a unique passphrase like ILoveMyDog!2024.</p>"
                "<p>Or make it whatever you want. You do you booboo. Just make sure it is unique to this program and very easy for you to remember because it cannot be recovered if forgotten or lost.</p>"
            )

            # Prompt the user to enter a master password
            dialog = CustomInputDialog(
                "Set Master Password",
                dialog_text,
                QLineEdit.Password,
                self,
            )
            if dialog.exec() == QDialog.Accepted:
                password = dialog.get_input()
                if password:
                    # Prompt the user to confirm the master password
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
                        "Master password is required to proceed.",
                        QMessageBox.Warning,
                    ).show_message()
            else:
                CustomMessageBox(
                    "Warning",
                    "Master password is required to proceed.",
                    QMessageBox.Warning,
                ).show_message()
                break

    def _prompt_password_input(self, title, label):
        """Prompt the user for a password input."""
        dialog = CustomInputDialog(title, label, QLineEdit.Password, self)
        if dialog.exec() == QDialog.Accepted:
            return dialog.get_input()
        return ""

    def verify_master_password(self):
        """Verify the entered master password using a custom input dialog."""
        from backend.database import verify_master_password

        while True:
            # Prompt the user to enter the master password for verification
            dialog = VerifyMasterPasswordDialog(self)
            if dialog.exec() == QDialog.Accepted:
                password = dialog.get_password()
                if password and verify_master_password(self.conn, password):
                    logger.info("Master password verified successfully.")
                    # Store the master password in the session manager
                    session = SessionManager.get_instance()
                    session.set_master_password(password)
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
                return False

    def store_master_password(self, password):
        """Store the master password in the database."""
        from backend.database import set_master_password

        try:
            set_master_password(self.conn, password)
            # Store the master password in the session manager
            session = SessionManager.get_instance()
            session.set_master_password(password)
            CustomMessageBox(
                "Info", "Master password set successfully!", QMessageBox.Information
            ).show_message()
            logger.info("Master password set successfully.")
        except ValueError as ve:
            CustomMessageBox(
                "Warning", f"Password validation failed: {ve}", QMessageBox.Warning
            ).show_message()

    def closeEvent(self, event):
        """Handle the application close event to clear sensitive data."""
        session = SessionManager.get_instance()
        session.clear_master_password()
        logger.info("Application closed. Master password cleared from memory.")
        event.accept()  # Proceed with the close event

    def show_info(self, message):
        """Show an informational message."""
        CustomMessageBox("Info", message, QMessageBox.Information).show_message()

    def show_warning(self, message):
        """Show a warning message."""
        CustomMessageBox("Warning", message, QMessageBox.Warning).show_message()

    def show_copied_message(self, message="Text copied to clipboard!"):
        """Show a message indicating that text was copied to the clipboard."""
        CustomMessageBox("Copied", message, QMessageBox.Information).show_message()

    def show_success_message(self, message="Operation completed successfully!"):
        """Show a success message."""
        CustomMessageBox("Success", message, QMessageBox.Information).show_message()


def main():
    """Main entry point of the Fortalice application."""
    app = QApplication(sys.argv)

    # Load stylesheet from style.qss
    stylesheet_path = os.path.join(
        os.path.dirname(__file__), "frontend", "styles", "style.qss"
    )

    with open(stylesheet_path, "r", encoding="utf-8") as file:
        app.setStyleSheet(file.read())

    welcome_dialog = WelcomeDialog()
    welcome_dialog.exec()

    window = PasswordManager()
    window.show()
    logger.info("Fortalice application started.")
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
