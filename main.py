# main.py

import datetime
import json
import logging
import os
import re
import sqlite3
import sys
import uuid
from typing import Callable, Optional

from PySide6.QtCore import QEasingCurve, QEvent, QPropertyAnimation, QSize, Qt, QTimer
from PySide6.QtGui import QGuiApplication, QIcon, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QInputDialog,  # Ensure QInputDialog is imported
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
from frontend.login_dialog import LoginDialog
from frontend.passkey_manager_tab import PasskeyManagerTab
from frontend.password_generation_tab import PasswordGenerationTab
from frontend.password_health_check_tab import PasswordHealthTab
from frontend.password_management import PasswordManagementTab
from frontend.secure_notes_tab import SecureNotesTab
from frontend.settings import SettingsTab
from session_manager import SessionManager

# Add the root directory to sys.path using a safer approach
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
        # Initialize SessionManager first
        self.session = SessionManager()

        self.conn: Optional[sqlite3.Connection] = None
        self.password_generation_tab: Optional[PasswordGenerationTab] = None
        self.password_management_tab: Optional[PasswordManagementTab] = None
        self.passkey_manager_tab: Optional[PasskeyManagerTab] = None
        self.secure_notes_tab: Optional[SecureNotesTab] = None
        self.settings_tab: Optional[SettingsTab] = None
        self.password_health_tab: Optional[PasswordHealthTab] = None
        self.user_identifier: Optional[str] = None
        self.device_id: Optional[str] = None

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

    def get_current_timestamp(self, format: str = "%Y-%m-%d %H:%M:%S") -> str:
        """
        Returns the current timestamp as a formatted string.

        :param format: The format string for the timestamp.
        :return: Formatted timestamp string.
        """
        return datetime.datetime.now().strftime(format)

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

            # Generate or retrieve device ID
            self.device_id = self.get_or_create_device_id()

            # Check if device is trusted and retrieve user identifier
            trusted_user = self.get_trusted_user_identifier()
            if trusted_user:
                self.user_identifier = trusted_user
                logger.info(f"Device is trusted for user: {self.user_identifier}")

                # Retrieve master password from session
                master_password = self.session.get_master_password()
                if master_password:
                    # Verify master password using session manager
                    master_password_verified = self.session.verify_master_password(
                        master_password, self.conn
                    )
                    if master_password_verified:
                        logger.info("Master password verified successfully.")
                    else:
                        logger.warning(
                            "Failed to verify master password for trusted device."
                        )
                        # Prompt the user to enter the master password
                        if not self.prompt_master_password():
                            CustomMessageBox(
                                "Error",
                                "Authentication failed. Exiting application.",
                                QMessageBox.Critical,
                            ).show_message()
                            sys.exit(1)
                else:
                    # No master password in session, prompt the user
                    if not self.prompt_master_password():
                        CustomMessageBox(
                            "Error",
                            "Authentication failed. Exiting application.",
                            QMessageBox.Critical,
                        ).show_message()
                        sys.exit(1)
            else:
                # Show the login dialog
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

    def prompt_master_password(self) -> bool:
        """Prompt the user to enter the master password and verify it."""
        password, ok = QInputDialog.getText(
            self,
            "Master Password Required",
            "Enter your master password to continue:",
            QLineEdit.Password,
        )
        if ok and password:
            if self.session.verify_master_password(password, self.conn):
                logger.info("Master password verified and stored securely.")
                return True
            else:
                self.show_warning("Incorrect master password.")
                return False
        else:
            self.show_warning("Master password is required to proceed.")
            return False

    def get_or_create_device_id(self) -> str:
        """Retrieve the existing device ID or create a new one if it doesn't exist."""
        device_id_path = os.path.join(DATABASE_DIR, "device_id.txt")

        if os.path.exists(device_id_path):
            try:
                with open(device_id_path, "r") as file:
                    device_id = file.read().strip()
                    if self.validate_uuid(device_id):
                        logger.info(f"Existing device ID found: {device_id}")
                        return device_id
                    else:
                        logger.warning(
                            "Invalid device ID format. Generating a new one."
                        )
            except Exception as e:
                logger.error(f"Failed to read device ID: {e}")

        # Generate a new device ID
        device_id = str(uuid.uuid4())
        try:
            with open(device_id_path, "w") as file:
                file.write(device_id)
            logger.info(f"New device ID generated and stored: {device_id}")
        except Exception as e:
            logger.error(f"Failed to store device ID: {e}")
            # Handle as per your security requirements

        return device_id

    @staticmethod
    def validate_uuid(uuid_to_test: str, version: int = 4) -> bool:
        """Validate that a UUID string is in fact a valid UUID."""
        try:
            uuid_obj = uuid.UUID(uuid_to_test, version=version)
        except ValueError:
            return False
        return str(uuid_obj) == uuid_to_test

    def retrieve_master_password(self) -> Optional[str]:
        """Retrieve the master password from the session manager."""
        master_password = self.session.get_master_password()
        if master_password:
            logger.info("Master password retrieved from session manager.")
        else:
            logger.warning("No master password found in session manager.")
        return master_password

    def get_trusted_user_identifier(self) -> Optional[str]:
        """
        Retrieve the user identifier associated with the current device ID.

        :return: User identifier if the device is trusted, else None.
        """
        trusted_devices_path = os.path.join(DATABASE_DIR, "trusted_devices.json.enc")

        if not os.path.exists(trusted_devices_path):
            logger.info("No trusted devices file found.")
            return None

        try:
            with open(trusted_devices_path, "rb") as file:
                encrypted_data = file.read()
                decrypted_data = decrypt_data(encrypted_data.decode())
                trusted_devices = json.loads(decrypted_data)

                for user, devices in trusted_devices.items():
                    for device in devices:
                        if device.get("device_id") == self.device_id:
                            logger.info(
                                f"Device {self.device_id} is trusted for user: {user}"
                            )
                            return user
        except Exception as e:
            logger.error(f"Error retrieving trusted user identifier: {e}")

        logger.info(f"Device {self.device_id} is not trusted.")
        return None

    def show_login_dialog(self) -> bool:
        """Display the consolidated login dialog and handle authentication."""
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
            logger.info("User identifier set.")

            # Check if master password is set
            if not is_master_password_set(self.conn):
                self.set_master_password_from_dialog(password)
            else:
                if not verify_master_password(self.conn, password):
                    self.show_warning("Incorrect master password.")
                    return False
                else:
                    # Store the master password in the session manager
                    self.session.set_master_password(password)
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

    def set_master_password_from_dialog(self, password: str):
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
                self.session.set_master_password(password)
                CustomMessageBox(
                    "Info",
                    "Master password set successfully!",
                    QMessageBox.Information,
                ).show_message()
                logger.info("Master password set successfully.")
            else:
                self.show_warning("Passwords do not match. Please try again.")
                self.set_master_password_from_dialog(password)  # Retry
        else:
            self.show_warning(
                "Password does not meet the required criteria. Please try again."
            )
            self.set_master_password_from_dialog(password)  # Retry

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
        """Show the settings tab after verifying 2FA if necessary."""
        # Check if device is trusted; if not, prompt for 2FA
        if not self.is_device_trusted():
            two_fa = TwoFactorAuthentication(self.user_identifier, self.conn)
            for _ in range(3):  # Allow up to 3 attempts
                token, ok = QInputDialog.getText(
                    self,
                    "Two-Factor Authentication",
                    "Enter your 2FA token to access Settings:",
                    QLineEdit.Normal,
                )
                if ok:
                    if two_fa.verify_token(token):
                        logger.info("2FA verification successful.")
                        self.stacked_widget.setCurrentWidget(self.settings_tab)
                        return  # Exit the method after successful verification
                    else:
                        self.show_warning("Invalid 2FA token. Please try again.")
                else:
                    # User canceled the input dialog
                    reply = QMessageBox.question(
                        self,
                        "Cancel Verification",
                        "Are you sure you want to cancel accessing Settings?",
                        QMessageBox.Yes | QMessageBox.No,
                        QMessageBox.No,
                    )
                    if reply == QMessageBox.Yes:
                        return  # Exit the method if the user chooses to cancel
            self.show_warning("Maximum attempts reached. Returning to previous screen.")
        else:
            # Device is trusted; directly show Settings tab
            self.stacked_widget.setCurrentWidget(self.settings_tab)
            logger.info("Accessing Settings without 2FA as the device is trusted.")

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

    def mark_device_as_trusted(self):
        """Mark the current device as trusted by storing its device_id and timestamp."""
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

        # Initialize the list for the user if not present
        if self.user_identifier not in trusted_devices:
            trusted_devices[self.user_identifier] = []

        # Add the device_id with timestamp if not already trusted
        if not any(
            device["device_id"] == self.device_id
            for device in trusted_devices[self.user_identifier]
        ):
            trusted_devices[self.user_identifier].append(
                {
                    "device_id": self.device_id,
                    "added_on": self.get_current_timestamp(),  # Adds timestamp
                }
            )
            logger.info(
                f"Device {self.device_id} marked as trusted for user: {self.user_identifier}"
            )
        else:
            logger.info(
                f"Device {self.device_id} is already trusted for user: {self.user_identifier}"
            )

        try:
            encrypted_data = encrypt_data(json.dumps(trusted_devices))
            with open(trusted_devices_path, "w") as file:
                file.write(encrypted_data)
            logger.info(f"Trusted devices updated for user: {self.user_identifier}")
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
                    return any(
                        device["device_id"] == self.device_id
                        for device in trusted_devices.get(self.user_identifier, [])
                    )
            except Exception as e:
                logger.warning(f"Failed to decrypt trusted devices file: {e}")
        return False

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

    def get_trusted_devices(self) -> list:
        """Retrieve the list of trusted devices for the current user."""
        trusted_devices_path = os.path.join(
            DATABASE_DIR, "trusted_devices.json.enc"
        )  # Encrypted file
        trusted_devices = []
        if os.path.exists(trusted_devices_path):
            try:
                with open(trusted_devices_path, "rb") as file:
                    encrypted_data = file.read()
                    decrypted_data = decrypt_data(encrypted_data.decode())
                    trusted_devices_data = json.loads(decrypted_data)  # Parse JSON
                    trusted_devices = trusted_devices_data.get(self.user_identifier, [])
            except Exception as e:
                logger.warning(f"Failed to decrypt or parse trusted devices file: {e}")
        return trusted_devices

    def remove_trusted_device(self, device_id: str):
        """Remove a device from the trusted devices list."""
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
                return

        if self.user_identifier in trusted_devices:
            # Find the device dict to remove
            device_to_remove = None
            for device in trusted_devices[self.user_identifier]:
                if device.get("device_id") == device_id:
                    device_to_remove = device
                    break

            if device_to_remove:
                trusted_devices[self.user_identifier].remove(device_to_remove)
                logger.info(
                    f"Device {device_id} removed from trusted devices for user: {self.user_identifier}"
                )

                try:
                    encrypted_data = encrypt_data(json.dumps(trusted_devices))
                    with open(trusted_devices_path, "w") as file:
                        file.write(encrypted_data)
                    logger.info(
                        f"Trusted devices updated for user: {self.user_identifier}"
                    )
                    self.show_info("Trusted device revoked successfully.")
                except Exception as e:
                    logger.error(f"Failed to encrypt and store trusted devices: {e}")
                    self.show_warning("Failed to revoke trusted device.")
            else:
                logger.info(
                    f"Device {device_id} not found in trusted devices for user: {self.user_identifier}"
                )
                self.show_warning("Selected device not found among trusted devices.")
        else:
            logger.info(f"No trusted devices found for user: {self.user_identifier}")

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

    def closeEvent(self, event):
        """Handle the application close event to clear sensitive data."""
        self.session.clear_master_password()
        logger.info("Application closed. Master password cleared from session.")
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
        self.session.clear_master_password()
        logger.info("User logged out and master password cleared from session.")

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
