# main.py

import logging
import os
import re
import sys
import uuid
from typing import Callable, Optional

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, QSize, Qt
from PySide6.QtGui import QFont, QFontDatabase, QGuiApplication, QIcon
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

from backend.database import (
    create_connection,
    initialize_db,
    is_master_password_set,
    set_master_password,
    verify_master_password,
)
from frontend.blueprints import (
    ButtonFactory,
    CustomMessageBox,
)
from frontend.passkey_manager_tab import PasskeyManagerTab
from frontend.password_generation import PasswordGenerationTab
from frontend.password_health_check_tab import PasswordHealthTab
from frontend.password_management import PasswordManagementTab
from frontend.secure_notes_tab import SecureNotesTab
from frontend.visual_settings import SettingsTab
from session_manager import SessionManager

# Add the root directory to sys.path using a safer approach
# Assuming this script is part of a package, adjust accordingly
PACKAGE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PACKAGE_DIR not in sys.path:
    sys.path.insert(0, PACKAGE_DIR)


try:
    from backend.config import DATABASE_DIR, LOG_FILE
except ModuleNotFoundError as error:
    print(f"Error importing config: {error}")
    sys.exit(1)

# Ensure the database directory exists
os.makedirs(DATABASE_DIR, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,  # Changed to INFO to avoid verbose DEBUG logs in production
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)


class CustomInputDialog(QDialog):
    """Custom input dialog for user input with customizable title and label."""

    def __init__(
        self,
        title: str,
        label: str,
        echo_mode: QLineEdit.EchoMode = QLineEdit.Normal,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setWindowIcon(QIcon(r"frontend/icons/encryption.png"))
        layout = QVBoxLayout(self)

        # Add the label and input field
        self.label = QLabel(label)
        self.label.setWordWrap(True)
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

        # Set fixed size to prevent resizing issues
        self.setFixedSize(self.sizeHint())

        # Center the dialog
        self.center()

    def get_input(self) -> str:
        """Return the input from the line edit."""
        return self.input_field.text()

    def center(self):
        """Center the dialog on the screen."""
        screen = QGuiApplication.primaryScreen()
        screen_geometry = screen.availableGeometry()
        x = (screen_geometry.width() - self.width()) // 2
        y = (screen_geometry.height() - self.height()) // 2
        self.move(x, y)


class WelcomeDialog(QDialog):
    """Welcome dialog displayed when the application starts."""

    def __init__(self):
        super().__init__()
        self.setWindowIcon(QIcon(r"frontend/icons/encryption.png"))
        self.setWindowTitle("Welcome to Fortalice!")

        layout = QVBoxLayout()
        label = QLabel("Welcome to Fortalice! Click OK to proceed.")
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)

        button_factory = ButtonFactory(self)
        button_layout = button_factory.create_button_with_layout(
            "", "OK", 100, self.accept
        )
        layout.addLayout(button_layout)

        self.setLayout(layout)

        # Set fixed size to prevent resizing issues
        self.setFixedSize(self.sizeHint())

        # Center the dialog
        self.center()

        # Setup fade-in animation
        self.setWindowOpacity(0)
        self.animation = QPropertyAnimation(self, b"windowOpacity")
        self.animation.setDuration(1000)  # 1 second
        self.animation.setStartValue(0)
        self.animation.setEndValue(1)
        self.animation.setEasingCurve(QEasingCurve.InOutQuad)
        self.animation.start()

    def center(self):
        """Center the dialog on the screen."""
        screen = QGuiApplication.primaryScreen()
        screen_geometry = screen.availableGeometry()
        x = (screen_geometry.width() - self.width()) // 2
        y = (screen_geometry.height() - self.height()) // 2
        self.move(x, y)


class VerifyMasterPasswordDialog(QDialog):
    """Dialog for verifying the master password input by the user."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("Verify Master Password")
        self.setWindowIcon(QIcon(r"frontend/icons/encryption.png"))
        self.setMinimumSize(400, 150)

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

        # Set fixed size to prevent resizing issues
        self.setFixedSize(self.sizeHint())

        # Center the dialog
        self.center()

    def get_password(self) -> str:
        """Return the password entered by the user."""
        return self.password_input.text()

    def center(self):
        """Center the dialog on the screen."""
        screen = QGuiApplication.primaryScreen()
        screen_geometry = screen.availableGeometry()
        x = (screen_geometry.width() - self.width()) // 2
        y = (screen_geometry.height() - self.height()) // 2
        self.move(x, y)


class PasswordManager(QMainWindow):
    """Main application window for Fortalice, managing the main functionalities."""

    def __init__(self):
        super().__init__()
        self.conn: Optional[object] = None
        self.cipher_suite: Optional[object] = None  # Clarify type if possible
        self.password_generation_tab: Optional[PasswordGenerationTab] = None
        self.password_management_tab: Optional[PasswordManagementTab] = None
        self.passkey_manager_tab: Optional[PasskeyManagerTab] = None
        self.secure_notes_tab: Optional[SecureNotesTab] = None
        self.settings_tab: Optional[SettingsTab] = None
        self.password_health_tab: Optional[QWidget] = None

        self.setWindowTitle("Fortalice")
        self.setGeometry(
            300, 300, 1200, 800
        )  # Increased default size for better visibility
        self.setWindowIcon(QIcon(r"frontend/icons/encryption.png"))

        self.main_widget = QWidget(self)
        self.setCentralWidget(self.main_widget)

        self.main_layout = QHBoxLayout(self.main_widget)
        self.main_layout.setContentsMargins(20, 20, 20, 20)
        self.main_layout.setSpacing(20)

        # Left Column for Navigation Buttons
        left_column = QVBoxLayout()
        left_column.setObjectName("leftColumn")  # Assign object name for styling
        left_column.setContentsMargins(10, 10, 10, 10)
        left_column.setSpacing(20)

        self._setup_buttons(left_column)

        left_column.addStretch()  # Push buttons to the top

        # Right Column for Content
        self.stacked_widget = QStackedWidget()

        self.main_layout.addLayout(left_column, 1)  # Left column takes less space
        self.main_layout.addWidget(
            self.stacked_widget, 4
        )  # Right column takes more space

        self.initialize_app()
        self.showMaximized()

    def _setup_buttons(self, layout: QVBoxLayout):
        """Set up the buttons for navigating different tabs."""
        # Password generator button
        self.generator_button = self._create_navigation_button(
            "Password Generator",
            r"frontend/icons/magic-wand.png",
            self.show_password_generator,
        )
        layout.addWidget(self.generator_button)

        # Password manager button
        self.manage_button = self._create_navigation_button(
            "Manage Passwords",
            r"frontend/icons/safe-box.png",
            self.show_manage_passwords,
        )
        layout.addWidget(self.manage_button)

        # Passkey manager button
        self.passkey_button = self._create_navigation_button(
            "Manage Passkeys",
            r"frontend/icons/passkey.png",
            self.show_passkey_manager,
        )
        layout.addWidget(self.passkey_button)

        # Secure Notes button
        self.secure_notes_button = self._create_navigation_button(
            "Secure Notes",
            r"frontend/icons/notepad.png",
            self.show_secure_notes,
        )
        layout.addWidget(self.secure_notes_button)

        # Password Health button
        self.health_button = self._create_navigation_button(
            "Password Health",
            r"frontend/icons/health.png",  # Ensure the icon exists
            self.show_password_health,
        )
        layout.addWidget(self.health_button)

        # Visual Settings Button
        self.settings_button = self._create_navigation_button(
            "Visual Settings", r"frontend/icons/settings.png", self.show_settings
        )
        layout.addWidget(self.settings_button)

    def _create_navigation_button(
        self, text: str, icon_path: str, callback: Callable
    ) -> QPushButton:
        """Create a navigation button with text, icon, and a callback function."""
        button = QPushButton(text)
        if os.path.exists(icon_path):
            button.setIcon(QIcon(icon_path))
            button.setIconSize(QSize(24, 24))
        else:
            logger.warning(
                f"Icon not found at {icon_path}. Button will be created without an icon."
            )
        button.setCursor(Qt.PointingHandCursor)  # Change cursor on hover
        button.setStyleSheet(
            "text-align: left; padding-left: 10px;"
        )  # Adjust padding for alignment
        button.clicked.connect(callback)
        return button

    def initialize_app(self):
        """Initialize the application by setting up the database connection and cipher suite."""
        self.conn = create_connection()

        if self.conn:
            key_id = str(uuid.uuid4())
            initialize_db(self.conn, key_id)
            logger.info("Database connection successful.")

            # Ensure the secure_notes table is created
            # Assuming `SecureNotesTab` handles its own table creation
            # Else, uncomment the following line if necessary:
            # create_secure_notes_table(self.conn)

            if not is_master_password_set(self.conn):
                self.set_master_password()
            elif not self.verify_master_password():
                CustomMessageBox(
                    "Error",
                    "Master password verification failed.",
                    QMessageBox.Critical,
                ).show_message()
                sys.exit(1)  # Exit if verification fails

            self._setup_tabs()
        else:
            CustomMessageBox(
                "Error", "Failed to connect to the database.", QMessageBox.Critical
            ).show_message()
            logger.error("Failed to connect to the database.")
            sys.exit(1)

    def _setup_tabs(self):
        """Set up the main tabs of the application."""
        self.password_generation_tab = PasswordGenerationTab()
        self.password_management_tab = PasswordManagementTab()
        self.passkey_manager_tab = PasskeyManagerTab()
        self.secure_notes_tab = SecureNotesTab(self.conn)
        self.password_health_tab = PasswordHealthTab(
            self.conn, self.stacked_widget
        )  # Pass stacked_widget here
        self.settings_tab = SettingsTab(main_window=self)

        # Add the tabs to the stacked widget
        self.stacked_widget.addWidget(self.password_generation_tab)
        self.stacked_widget.addWidget(self.password_management_tab)
        self.stacked_widget.addWidget(self.passkey_manager_tab)
        self.stacked_widget.addWidget(self.secure_notes_tab)
        self.stacked_widget.addWidget(self.settings_tab)
        self.stacked_widget.addWidget(self.password_health_tab)

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

    def show_secure_notes(self):
        """Show the secure notes tab."""
        self.stacked_widget.setCurrentWidget(self.secure_notes_tab)

    def show_password_health(self):
        """Show the password health tab."""
        self.stacked_widget.setCurrentWidget(self.password_health_tab)

    def show_settings(self):
        """Show the settings tab."""
        self.stacked_widget.setCurrentWidget(self.settings_tab)

    def set_master_password(self):
        """Prompt the user to set the master password using a custom input dialog."""
        while True:
            dialog_text = (
                "<p>Enter a master password. It must contain lowercase, uppercase, number, "
                "special character and be at least 8 characters long.</p>"
                "<p>Hint: Use a unique passphrase like <strong>ILoveMyDog!2024</strong>.</p>"
                "<p>Make sure it is unique to this program and easy for you to remember because it cannot be recovered if forgotten or lost.</p>"
            )

            dialog = CustomInputDialog(
                "Set Master Password",
                dialog_text,
                QLineEdit.Password,
                self,
            )
            if dialog.exec() == QDialog.Accepted:
                password = dialog.get_input()
                if self.validate_master_password(password):
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
                            "Confirmation cancelled. Please try again.",
                            QMessageBox.Warning,
                        ).show_message()
                else:
                    CustomMessageBox(
                        "Warning",
                        "Password does not meet the required criteria. Please try again.",
                        QMessageBox.Warning,
                    ).show_message()
            else:
                CustomMessageBox(
                    "Warning",
                    "Master password is required to proceed.",
                    QMessageBox.Warning,
                ).show_message()
                sys.exit(1)  # Exit if master password setup is cancelled
        logger.info("Master password set successfully.")

    def validate_master_password(self, password: str) -> bool:
        """Validate the master password against security criteria."""
        if len(password) < 8:
            return False
        if not re.search(r"[a-z]", password):
            return False
        if not re.search(r"[A-Z]", password):
            return False
        if not re.search(r"\d", password):
            return False
        if not re.search(r"[^\w\s]", password):
            return False
        return True

    def verify_master_password(self) -> bool:
        """Verify the entered master password using a custom input dialog."""
        while True:
            dialog = VerifyMasterPasswordDialog(self)
            if dialog.exec() == QDialog.Accepted:
                password = dialog.get_password()
                if password and verify_master_password(self.conn, password):
                    logger.info("Master password verified successfully.")
                    # Store the master password in the session manager
                    session = SessionManager()
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

    def store_master_password(self, password: str):
        """Store the master password in the database."""
        try:
            set_master_password(self.conn, password)
            # Store the master password in the session manager
            session = SessionManager()
            session.set_master_password(password)
            CustomMessageBox(
                "Info", "Master password set successfully!", QMessageBox.Information
            ).show_message()
            logger.info("Master password set successfully.")
        except ValueError as ve:
            CustomMessageBox(
                "Warning", f"Password validation failed: {ve}", QMessageBox.Warning
            ).show_message()
            logger.error(f"Password validation failed: {ve}")

    def closeEvent(self, event):
        """Handle the application close event to clear sensitive data."""
        session = SessionManager()
        session.clear_master_password()
        logger.info("Application closed. Master password cleared from memory.")
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed.")
        event.accept()

    def show_info(self, message: str):
        """Show an informational message."""
        CustomMessageBox("Info", message, QMessageBox.Information).show_message()

    def show_warning(self, message: str):
        """Show a warning message."""
        CustomMessageBox("Warning", message, QMessageBox.Warning).show_message()

    def show_copied_message(self, message: str = "Text copied to clipboard!"):
        """Show a message indicating that text was copied to the clipboard."""
        CustomMessageBox("Copied", message, QMessageBox.Information).show_message()

    def show_success_message(self, message: str = "Operation completed successfully!"):
        """Show a success message."""
        CustomMessageBox("Success", message, QMessageBox.Information).show_message()


def main():
    """Main entry point of the Fortalice application."""
    app = QApplication(sys.argv)

    # Load stylesheet from style.qss first
    stylesheet_path = os.path.join(
        os.path.dirname(__file__), "frontend", "styles", "style.qss"
    )

    if os.path.exists(stylesheet_path):
        with open(stylesheet_path, "r", encoding="utf-8") as file:
            app.setStyleSheet(file.read())
            logger.info("Stylesheet loaded successfully.")
    else:
        logger.error(
            f"Stylesheet not found at {stylesheet_path}. Proceeding without styling."
        )

    # Load custom fonts after applying stylesheet to ensure QFont isn't overridden
    font_path = os.path.join(
        os.path.dirname(__file__), "frontend", "fonts", "Roboto-Regular.ttf"
    )
    if os.path.exists(font_path):
        font_id = QFontDatabase.addApplicationFont(font_path)
        if font_id != -1:
            font_families = QFontDatabase.applicationFontFamilies(font_id)
            if font_families:
                font_family = font_families[0]
                app_font = QFont(font_family, 10)  # Set a reasonable default font size
                app.setFont(app_font)
                logger.info(
                    f"Custom font '{font_family}' loaded successfully with size {app_font.pointSize()}."
                )
            else:
                logger.warning(
                    "No font families found in the custom font. Using default font."
                )
        else:
            logger.warning("Failed to load custom font. Using default font.")
    else:
        logger.warning(f"Font file not found at {font_path}. Using default font.")

    # Display the welcome dialog
    welcome_dialog = WelcomeDialog()
    welcome_dialog.exec()

    # Initialize and display the main application window
    window = PasswordManager()
    window.show()
    logger.info("Fortalice application started.")
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
