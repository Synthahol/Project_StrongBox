# frontend/login_dialog.py

import json
import logging
import os
import re
from typing import Optional

from PySide6.QtCore import QEvent
from PySide6.QtGui import QGuiApplication, QIcon
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from backend.config import DATABASE_DIR
from backend.database import (
    decrypt_data,
    is_master_password_set,
    set_master_password,
    verify_master_password,
)
from backend.two_factor_auth import TwoFactorAuthentication
from frontend.blueprints import ButtonFactory, CustomMessageBox

# Configure the logger for this module
logger = logging.getLogger(__name__)


class LoginDialog(QDialog):
    """Consolidated login dialog with email, master password, and 2FA options."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.main_window = parent  # Reference to PasswordManager
        self.conn = self.main_window.conn if self.main_window else None
        self.device_id = self.main_window.device_id if self.main_window else None

        self.setWindowTitle("Fortalice - Login")
        self.setWindowIcon(QIcon(r"frontend/icons/encryption.png"))
        self.setFixedSize(400, 300)  # Adjusted height to accommodate all elements

        # Initialize ButtonFactory
        self.button_factory = ButtonFactory(self)

        # Main layout
        self.layout = QVBoxLayout()
        self.layout.setContentsMargins(
            20, 20, 20, 20
        )  # Reduced margins for tighter layout
        self.layout.setSpacing(15)  # Adjusted spacing between widgets

        # Form layout for labels and input fields
        self.form_layout = QVBoxLayout()
        self.form_layout.setSpacing(10)  # Reduced spacing between form rows

        # Email Input
        self.email_label = QLabel("Email Address:")
        self.email_label.setStyleSheet("font-weight: bold;")
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Enter your email")
        self.email_input.setFixedHeight(30)
        self.form_layout.addWidget(self.email_label)
        self.form_layout.addWidget(self.email_input)

        # Master Password Input with Toggle Button
        self.password_label = QLabel("Master Password:")
        self.password_label.setStyleSheet("font-weight: bold;")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your master password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setFixedHeight(30)

        # Show/Hide Button
        self.toggle_password_button = QPushButton("Show")
        self.toggle_password_button.setFixedSize(60, 30)
        self.toggle_password_button.setStyleSheet("padding: 0px;")
        self.toggle_password_button.clicked.connect(self.toggle_password_visibility)

        # Layout for password input and toggle button
        self.password_layout = QHBoxLayout()
        self.password_layout.addWidget(self.password_input)
        self.password_layout.addWidget(self.toggle_password_button)

        self.form_layout.addWidget(self.password_label)
        self.form_layout.addLayout(self.password_layout)

        # Remember Device Checkbox
        self.remember_checkbox = QCheckBox("Remember this device for future logins")
        self.form_layout.addWidget(self.remember_checkbox)

        # 2FA Token Input (Initially hidden; shown only if device is not trusted)
        self.two_fa_label = QLabel("2FA Token:")
        self.two_fa_input = QLineEdit()
        self.two_fa_input.setPlaceholderText("Enter your 2FA token")
        self.two_fa_input.setMaxLength(6)  # Assuming a 6-digit token
        self.two_fa_input.setFixedHeight(30)

        # Encapsulate 2FA fields within a QWidget
        self.two_fa_widget = QWidget()
        self.two_fa_layout = QHBoxLayout(self.two_fa_widget)
        self.two_fa_layout.setContentsMargins(
            0, 0, 0, 0
        )  # Remove margins for better alignment
        self.two_fa_layout.addWidget(self.two_fa_label)
        self.two_fa_layout.addWidget(self.two_fa_input)
        self.two_fa_layout.addStretch()
        self.form_layout.addWidget(self.two_fa_widget)

        # Initially hide the entire 2FA widget
        self.two_fa_widget.hide()

        self.layout.addLayout(self.form_layout)

        # Spacer to push buttons to the bottom
        self.layout.addStretch()

        # Buttons layout
        self.button_layout = QHBoxLayout()
        self.button_layout.addStretch()  # Left spacer

        # Create Login and Cancel buttons using ButtonFactory
        self.login_button = self.button_factory.create_button(
            "Login",
            100,
            self.handle_login,
            icon_path="frontend/icons/login_icon.png",  # Replace with your icon path
            tooltip="Click to login",
            object_name="loginButton",
        )
        self.cancel_button = self.button_factory.create_button(
            "Cancel",
            100,
            self.reject,  # Connect to dialog's reject method
            icon_path="frontend/icons/cancel_icon.png",  # Replace with your icon path
            tooltip="Click to cancel",
            object_name="cancelButton",
        )

        self.button_layout.addWidget(self.login_button)
        self.button_layout.addWidget(self.cancel_button)
        self.button_layout.addStretch()  # Right spacer

        self.layout.addLayout(self.button_layout)

        self.setLayout(self.layout)

        # Center the dialog (will be overridden by showEvent)
        # self.center()

    def showEvent(self, event: QEvent):
        """Override the showEvent to center the dialog when it's shown."""
        super().showEvent(event)
        self.center()

    def handle_login(self):
        """Handle the login logic when the Login button is clicked."""
        email = self.email_input.text().strip().lower()
        password = self.password_input.text()
        two_fa_token = self.two_fa_input.text().strip()
        remember_device = self.remember_checkbox.isChecked()

        # Basic validation
        if not self.validate_email(email):
            self.show_warning("Please enter a valid email address.")
            return

        if not password:
            self.show_warning("Please enter your master password.")
            return

        self.user_email = email
        self.user_password = password
        self.remember_device = remember_device

        # Check if master password is set
        if not is_master_password_set(self.conn):
            self.set_master_password()
            return

        # Verify master password
        if not verify_master_password(self.conn, password):
            self.show_warning("Incorrect master password.")
            return

        # Check if device is trusted
        if not self.is_device_trusted():
            # Show 2FA widget
            self.two_fa_widget.show()

            # Prompt for 2FA token if not already entered
            if not two_fa_token:
                self.show_warning("Please enter your 2FA token.")
                return

            two_fa = TwoFactorAuthentication(self.user_email, self.conn)
            if not two_fa.verify_token(two_fa_token):
                self.show_warning("Invalid 2FA token.")
                return

            logger.info("2FA verification successful.")
        else:
            logger.info("Device is trusted. Skipping 2FA verification.")

        # If all validations pass, accept the dialog and pass the data
        self.user_two_fa_token = two_fa_token
        self.accept()

        # Handle "Remember this device" feature via main_window
        if remember_device and self.main_window:
            self.main_window.mark_device_as_trusted()

    def set_master_password(self):
        """Set the master password if it's not already set."""
        confirm_password, ok = QInputDialog.getText(
            self,
            "Confirm Master Password",
            "Confirm your master password:",
            QLineEdit.Password,
        )
        if ok and self.user_password == confirm_password:
            set_master_password(self.conn, self.user_password)
            # Store the master password in the session manager
            if self.main_window:
                self.main_window.session.set_master_password(self.user_password)
            CustomMessageBox(
                "Info",
                "Master password set successfully!",
                QMessageBox.Information,
            ).show_message()
            logger.info("Master password set successfully.")
            self.accept()
        else:
            self.show_warning("Passwords do not match. Please try again.")

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
                        for device in trusted_devices.get(self.user_email, [])
                    )
            except Exception as e:
                logger.warning(f"Failed to decrypt trusted devices file: {e}")
        return False

    def validate_email(self, email: str) -> bool:
        """Validate the email format."""
        return re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None

    def get_credentials(self):
        """Return the entered credentials."""
        return {
            "email": self.user_email,
            "password": self.user_password,
            "two_fa_token": getattr(self, "user_two_fa_token", ""),
            "remember_device": self.remember_device,
        }

    def show_warning(self, message: str):
        """Display a warning message."""
        CustomMessageBox("Warning", message, QMessageBox.Warning).show_message()

    def toggle_password_visibility(self):
        """Toggle the visibility of the master password."""
        if self.password_input.echoMode() == QLineEdit.Password:
            self.password_input.setEchoMode(QLineEdit.Normal)
            self.toggle_password_button.setText("Hide")
        else:
            self.password_input.setEchoMode(QLineEdit.Password)
            self.toggle_password_button.setText("Show")

    def center(self):
        """Center the dialog on the primary screen."""
        screen = QGuiApplication.primaryScreen()
        if screen is None:
            logger.warning("Primary screen not found. Dialog will not be centered.")
            return
        screen_geometry = screen.availableGeometry()
        dialog_geometry = self.frameGeometry()
        dialog_geometry.moveCenter(screen_geometry.center())
        self.move(dialog_geometry.topLeft())
