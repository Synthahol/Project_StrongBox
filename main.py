# main.py

import json
import logging
import os
import re
import sqlite3
import sys
import uuid
from typing import Callable, Optional

from PySide6.QtCore import QEasingCurve, QEvent, QPropertyAnimation, QSize, Qt, QTimer
from PySide6.QtGui import QFont, QFontDatabase, QGuiApplication, QIcon, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QInputDialog,
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
    decrypt_data,
    encrypt_data,
    initialize_db,
    is_master_password_set,
    set_master_password,
    verify_master_password,
)
from backend.exceptions import SecretAlreadyExistsError
from backend.two_factor_auth import TwoFactorAuthentication
from frontend.blueprints import ButtonFactory, CustomMessageBox
from frontend.login_dialog import LoginDialog  # Import the new LoginDialog
from frontend.passkey_manager_tab import PasskeyManagerTab
from frontend.password_generation_tab import PasswordGenerationTab
from frontend.password_health_check_tab import PasswordHealthTab
from frontend.password_management import PasswordManagementTab
from frontend.secure_notes_tab import SecureNotesTab
from frontend.settings import SettingsTab
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
        self.setMinimumSize(400, 150)

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


class PasswordManager(QMainWindow):
    """Main application window for Fortalice, managing the main functionalities."""

    def __init__(self):
        super().__init__()
        self.conn: Optional[sqlite3.Connection] = None
        self.password_generation_tab: Optional[PasswordGenerationTab] = None
        self.password_management_tab: Optional[PasswordManagementTab] = None
        self.passkey_manager_tab: Optional[PasskeyManagerTab] = None
        self.secure_notes_tab: Optional[SecureNotesTab] = None
        self.settings_tab: Optional[SettingsTab] = None
        self.password_health_tab: Optional[PasswordHealthTab] = None
        self.user_identifier: Optional[str] = None

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

        # Setup session timeout
        self.setup_session_timeout()

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

        # Settings Button
        self.settings_button = self._create_navigation_button(
            "Settings", r"frontend/icons/settings.png", self.show_settings
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

            # Show the consolidated login dialog
            if not self.show_login_dialog():
                CustomMessageBox(
                    "Error",
                    "Authentication failed. Exiting application.",
                    QMessageBox.Critical,
                ).show_message()
                sys.exit(1)

            self._setup_tabs()
        else:
            CustomMessageBox(
                "Error", "Failed to connect to the database.", QMessageBox.Critical
            ).show_message()
            logger.error("Failed to connect to the database.")
            sys.exit(1)

    def show_login_dialog(self) -> bool:
        """Display the consolidated login dialog and handle authentication."""
        # Instantiate the SessionManager
        session = SessionManager()

        # Show the login dialog
        login_dialog = LoginDialog(self)
        if login_dialog.exec() == QDialog.Accepted:
            credentials = login_dialog.get_credentials()
            email = credentials["email"]
            password = credentials["password"]
            two_fa_token = credentials["two_fa_token"]
            remember_device = credentials["remember_device"]

            # Set the user identifier
            self.user_identifier = email
            logger.info(f"User identifier set: {self.user_identifier}")

            # Check if master password is set
            if not is_master_password_set(self.conn):
                self.set_master_password_from_dialog(password, session)
            else:
                if not verify_master_password(self.conn, password):
                    self.show_warning("Incorrect master password.")
                    return False
                else:
                    # Store the master password in the session manager
                    session.set_master_password(password)
                    logger.info("Master password verified successfully.")

            # Handle 2FA verification
            two_fa = TwoFactorAuthentication(self.user_identifier, self.conn)
            if not two_fa.get_secret():
                # 2FA not set up; prompt to set it up
                self.setup_two_factor_authentication()
            else:
                # Check if device is trusted
                if not self.is_device_trusted():
                    # Verify the provided 2FA token
                    if not two_fa.verify_token(two_fa_token):
                        self.show_warning("Invalid 2FA token.")
                        return False
                    else:
                        logger.info("2FA verification successful.")
                else:
                    logger.info("Device is trusted. Skipping 2FA verification.")

            # Handle "Remember this device" feature
            if remember_device:
                self.mark_device_as_trusted()

            # Reset session timer on successful login
            self.reset_session_timer()

            return True
        else:
            return False

    def set_master_password_from_dialog(self, password: str, session: SessionManager):
        """Set the master password using the provided password from the dialog."""
        if self.validate_master_password(password):
            confirm_password, ok = QInputDialog.getText(
                self,
                "Confirm Master Password",
                "Confirm your master password:",
                QLineEdit.Password,
            )
            if ok and password == confirm_password:
                set_master_password(self.conn, password)
                # Store the master password in the session manager
                session.set_master_password(password)
                CustomMessageBox(
                    "Info",
                    "Master password set successfully!",
                    QMessageBox.Information,
                ).show_message()
                logger.info("Master password set successfully.")
            else:
                self.show_warning("Passwords do not match. Please try again.")
                self.set_master_password_from_dialog(password, session)  # Retry
        else:
            self.show_warning(
                "Password does not meet the required criteria. Please try again."
            )
            self.set_master_password_from_dialog(password, session)  # Retry

    def is_two_factor_setup(self) -> bool:
        """Check if 2FA is already set up for the user."""
        two_fa = TwoFactorAuthentication(self.user_identifier, self.conn)
        secret = two_fa.get_secret()
        return secret is not None

    def setup_two_factor_authentication(self):
        """Prompt the user to set up Two-Factor Authentication."""
        two_fa = TwoFactorAuthentication(self.user_identifier, self.conn)
        try:
            two_fa.generate_secret()
            logger.info("2FA secret generated successfully.")
            qr_code_image = two_fa.generate_qr_code()
            self.show_qr_code(qr_code_image)
            # Verify the 2FA code entered by the user
            for _ in range(3):  # Allow up to 3 attempts
                token, ok = QInputDialog.getText(
                    self,
                    "Two-Factor Authentication",
                    "Enter the 2FA token from your authenticator app:",
                    QLineEdit.Normal,
                )
                if ok:
                    if two_fa.verify_token(token):
                        logger.info("2FA setup verification successful.")
                        CustomMessageBox(
                            "Info",
                            "Two-Factor Authentication set up successfully!",
                            QMessageBox.Information,
                        ).show_message()
                        return
                    else:
                        self.show_warning("Invalid 2FA token. Please try again.")
                else:
                    self.show_warning("2FA setup is required to proceed.")
                    sys.exit(1)
            self.show_warning("Maximum attempts reached. Exiting application.")
            sys.exit(1)
        except SecretAlreadyExistsError:
            logger.info("2FA is already set up for this user.")
            pass
        except Exception as e:
            logger.error(f"Failed to set up 2FA: {e}")
            self.show_warning(f"Failed to set up 2FA: {e}")
            sys.exit(1)

    def show_qr_code(self, qr_code_image_data: bytes):
        """Display the QR code for 2FA setup."""
        qr_dialog = QDialog(self)
        qr_dialog.setWindowTitle("Scan QR Code with Authenticator App")
        layout = QVBoxLayout()
        instructions = QLabel("Scan this QR code with your authenticator app.")
        instructions.setAlignment(Qt.AlignCenter)
        layout.addWidget(instructions)
        qr_label = QLabel()
        qr_pixmap = QPixmap()
        qr_pixmap.loadFromData(qr_code_image_data)
        qr_label.setPixmap(qr_pixmap)
        qr_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(qr_label)
        qr_dialog.setLayout(layout)
        qr_dialog.exec()

    def prompt_user_identifier(self):
        """Prompt the user to enter a unique identifier for 2FA."""
        # This method is no longer needed as the LoginDialog handles email input
        pass

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

    def verify_two_factor_authentication(self) -> bool:
        """Verify the user's 2FA token."""
        two_fa = TwoFactorAuthentication(self.user_identifier, self.conn)
        # Check if 2FA is enabled for the user
        secret = two_fa.get_secret()
        if not secret:
            # 2FA is not set up; proceed without verification
            return True

        # Prompt user to enter 2FA token
        for _ in range(3):  # Allow up to 3 attempts
            token, ok = QInputDialog.getText(
                self,
                "Two-Factor Authentication",
                "Enter your 2FA token:",
                QLineEdit.Normal,
            )
            if ok:
                if two_fa.verify_token(token):
                    logger.info("2FA verification successful.")
                    return True
                else:
                    self.show_warning("Invalid 2FA token. Please try again.")
            else:
                # User canceled the input dialog
                reply = QMessageBox.question(
                    self,
                    "Cancel Verification",
                    "Are you sure you want to cancel 2FA verification?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No,
                )
                if reply == QMessageBox.Yes:
                    return False
        self.show_warning("Maximum attempts reached. Exiting application.")
        return False

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

    def store_master_password(self, password: str):
        """Store the master password in the database."""
        # This method is no longer needed as master password is handled in the login dialog
        pass

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

    def mark_device_as_trusted(self):
        """Mark the current device as trusted by storing a unique identifier."""
        device_id = str(uuid.uuid4())
        trusted_devices_path = os.path.join(
            DATABASE_DIR, "trusted_devices.json.enc"
        )  # Encrypted file

        trusted_devices = {}
        if os.path.exists(trusted_devices_path):
            try:
                with open(trusted_devices_path, "rb") as file:
                    encrypted_data = file.read()
                    decrypted_data = decrypt_data(encrypted_data.decode())
                    trusted_devices = json.loads(decrypted_data)
            except Exception as e:
                logger.warning(f"Failed to decrypt trusted devices file: {e}")
                trusted_devices = {}

        # Add or update the trusted device
        trusted_devices[self.user_identifier] = device_id

        try:
            encrypted_data = encrypt_data(json.dumps(trusted_devices))
            with open(trusted_devices_path, "w") as file:
                file.write(encrypted_data)
            logger.info(f"Device marked as trusted for user: {self.user_identifier}")
        except Exception as e:
            logger.error(f"Failed to encrypt and store trusted devices: {e}")
            self.show_warning("Failed to mark device as trusted.")

    def is_device_trusted(self) -> bool:
        """Check if the current device is marked as trusted for the user."""
        trusted_devices_path = os.path.join(
            DATABASE_DIR, "trusted_devices.json.enc"
        )  # Encrypted file
        if os.path.exists(trusted_devices_path):
            try:
                with open(trusted_devices_path, "rb") as file:
                    encrypted_data = file.read()
                    decrypted_data = decrypt_data(encrypted_data.decode())
                    trusted_devices = json.loads(decrypted_data)
                    return self.user_identifier in trusted_devices
            except Exception as e:
                logger.warning(f"Failed to decrypt trusted devices file: {e}")
        return False

    def setup_session_timeout(self):
        """Set up a session timeout mechanism to log out users after inactivity."""
        self.inactivity_timer = QTimer(self)
        self.inactivity_timer.setInterval(15 * 60 * 1000)  # 15 minutes
        self.inactivity_timer.timeout.connect(self.handle_session_timeout)
        self.inactivity_timer.start()

        # Install an event filter to detect user interactions
        self.installEventFilter(self)

    def reset_session_timer(self):
        """Reset the inactivity timer."""
        if hasattr(self, "inactivity_timer") and self.inactivity_timer.isActive():
            self.inactivity_timer.stop()
            self.inactivity_timer.start()

    def handle_session_timeout(self):
        """Handle the session timeout by logging out the user."""
        self.show_info("Session timed out due to inactivity. Please log in again.")
        self.logout()

    def logout(self):
        """Log out the user by clearing the session and showing the login dialog again."""
        session = SessionManager()
        session.clear_master_password()
        logger.info("User logged out due to session timeout.")

        # Optionally, clear other sensitive data here

        # Show the login dialog again
        if not self.show_login_dialog():
            # If login fails, exit the application
            sys.exit(1)

        # Reset the session timer
        self.reset_session_timer()

    def eventFilter(self, obj, event):
        """Filter events to detect user activity and reset the session timer."""
        if event.type() in (
            QEvent.MouseMove,
            QEvent.KeyPress,
            QEvent.MouseButtonPress,
            QEvent.MouseButtonRelease,
        ):
            self.reset_session_timer()
        return super().eventFilter(obj, event)


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
