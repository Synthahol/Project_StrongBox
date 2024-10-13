# frontend/login_dialog.py

import json
import logging
import os
import re
from typing import Optional

from PySide6.QtCore import QEvent, Qt
from PySide6.QtGui import QGuiApplication, QIcon, QPixmap
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
    get_user_id,
    is_master_password_set,
    set_master_password,
    update_master_password,
    verify_master_password,
    wipe_user_data,
)
from backend.two_factor_auth import TwoFactorAuthentication
from frontend.blueprints import ButtonFactory, CustomMessageBox

# Configure the logger for this module
logger = logging.getLogger(__name__)


class ConfirmPasswordDialog(QDialog):
    """Dialog to confirm the master password."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("Confirm Master Password")
        self.setWindowIcon(QIcon(r"frontend/icons/encryption.png"))
        self.setFixedSize(400, 150)

        self.layout = QVBoxLayout()
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(15)

        self.label = QLabel("Please re-enter your master password to confirm:")
        self.layout.addWidget(self.label)

        # Password input with toggle visibility
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your master password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setFixedHeight(30)

        self.toggle_password_button = QPushButton("Show")
        self.toggle_password_button.setFixedSize(60, 30)
        self.toggle_password_button.setStyleSheet("padding: 0px;")
        self.toggle_password_button.clicked.connect(self.toggle_password_visibility)

        # Layout for password input and toggle button
        self.password_layout = QHBoxLayout()
        self.password_layout.addWidget(self.password_input)
        self.password_layout.addWidget(self.toggle_password_button)

        self.layout.addLayout(self.password_layout)

        # Buttons
        self.button_layout = QHBoxLayout()
        self.button_layout.addStretch()

        self.confirm_button = QPushButton("Confirm")
        self.confirm_button.setFixedWidth(100)
        self.confirm_button.clicked.connect(self.accept)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setFixedWidth(100)
        self.cancel_button.clicked.connect(self.reject)

        self.button_layout.addWidget(self.confirm_button)
        self.button_layout.addWidget(self.cancel_button)
        self.button_layout.addStretch()

        self.layout.addLayout(self.button_layout)
        self.setLayout(self.layout)

    def toggle_password_visibility(self):
        """Toggle the visibility of the password."""
        if self.password_input.echoMode() == QLineEdit.Password:
            self.password_input.setEchoMode(QLineEdit.Normal)
            self.toggle_password_button.setText("Hide")
        else:
            self.password_input.setEchoMode(QLineEdit.Password)
            self.toggle_password_button.setText("Show")

    def get_password(self) -> Optional[str]:
        """Retrieve the entered password."""
        return self.password_input.text()


class QRCodeDialog(QDialog):
    """Dialog to display the QR code for 2FA setup."""

    def __init__(self, qr_code_image_data: bytes, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("Scan QR Code for 2FA Setup")
        self.setWindowIcon(QIcon(r"frontend/icons/encryption.png"))
        self.setFixedSize(400, 500)

        self.layout = QVBoxLayout()
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(15)

        self.label = QLabel("Scan this QR code with your authenticator app:")
        self.label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.label)

        # Display QR code
        self.qr_label = QLabel()
        pixmap = QPixmap()
        pixmap.loadFromData(qr_code_image_data)
        self.qr_label.setPixmap(
            pixmap.scaled(300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        )
        self.qr_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.qr_label)

        # Instruction
        self.instruction_label = QLabel("After scanning, click 'Done' to proceed.")
        self.instruction_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.instruction_label)

        # Buttons
        self.button_layout = QHBoxLayout()
        self.button_layout.addStretch()

        self.done_button = QPushButton("Done")
        self.done_button.setFixedWidth(100)
        self.done_button.clicked.connect(self.accept)

        self.button_layout.addWidget(self.done_button)
        self.button_layout.addStretch()

        self.layout.addLayout(self.button_layout)
        self.setLayout(self.layout)


class TwoFATokenDialog(QDialog):
    """Dialog to enter the 2FA token."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("Enter 2FA Token")
        self.setWindowIcon(QIcon(r"frontend/icons/encryption.png"))
        self.setFixedSize(400, 200)

        self.layout = QVBoxLayout()
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(15)

        self.label = QLabel("Enter the 2FA token from your authenticator app:")
        self.layout.addWidget(self.label)

        self.token_input = QLineEdit()
        self.token_input.setPlaceholderText("6-digit token")
        self.token_input.setMaxLength(6)
        self.token_input.setFixedHeight(30)
        self.layout.addWidget(self.token_input)

        # Buttons
        self.button_layout = QHBoxLayout()
        self.button_layout.addStretch()

        self.submit_button = QPushButton("Submit")
        self.submit_button.setFixedWidth(100)
        self.submit_button.clicked.connect(self.accept)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setFixedWidth(100)
        self.cancel_button.clicked.connect(self.reject)

        self.button_layout.addWidget(self.submit_button)
        self.button_layout.addWidget(self.cancel_button)
        self.button_layout.addStretch()

        self.layout.addLayout(self.button_layout)
        self.setLayout(self.layout)

    def get_token(self) -> Optional[str]:
        """Retrieve the entered token."""
        return self.token_input.text().strip()


class LoginDialog(QDialog):
    """Consolidated login dialog with email, master password, and 2FA options."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.main_window = parent  # Reference to PasswordManager
        self.conn = self.main_window.conn if self.main_window else None
        self.device_id = self.main_window.device_id if self.main_window else None

        self.setWindowTitle("Fortalice - Login")
        self.setWindowIcon(QIcon(r"frontend/icons/encryption.png"))
        self.setFixedSize(400, 350)  # Adjusted height to accommodate all elements

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
            style="",  # Add style if needed
        )
        self.cancel_button = self.button_factory.create_button(
            "Cancel",
            100,
            self.reject,  # Connect to dialog's reject method
            icon_path="frontend/icons/cancel_icon.png",  # Replace with your icon path
            tooltip="Click to cancel",
            object_name="cancelButton",
            style="",  # Add style if needed
        )

        self.button_layout.addWidget(self.login_button)
        self.button_layout.addWidget(self.cancel_button)
        self.button_layout.addStretch()  # Right spacer

        self.layout.addLayout(self.button_layout)

        # "Forgot master password" button, hidden initially
        self.forgot_password_button = self.button_factory.create_button(
            "Forgot Master Password?",
            200,
            self.handle_forgot_password,
            icon_path="frontend/icons/forgot_password_icon.png",  # Replace with your icon path
            tooltip="Click to recover master password",
            object_name="forgotPasswordButton",
            style="background: none; color: blue; text-decoration: underline; border: none;",  # Custom style
        )
        self.forgot_password_button.setCursor(Qt.PointingHandCursor)
        self.forgot_password_button.hide()  # Hidden initially
        self.layout.addWidget(self.forgot_password_button, alignment=Qt.AlignCenter)

        self.setLayout(self.layout)

        # Initialize credentials
        self.user_email = None
        self.user_password = None
        self.user_two_fa_token = None
        self.remember_device = False  # Initialize remember_device

    def showEvent(self, event: QEvent):
        """Override the showEvent to center the dialog when it's shown."""
        super().showEvent(event)
        self.center()  # This method needs to be defined

    def center(self):
        """Center the dialog on the screen."""
        qr = self.frameGeometry()
        cp = QGuiApplication.primaryScreen().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def handle_login(self):
        """Handle the login logic when the Login button is clicked."""
        email = self.email_input.text().strip().lower()
        password = self.password_input.text()
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

        # Check if master password is set for this email
        if not is_master_password_set(self.conn, email):
            # If master password is not set, set it now
            if not self.set_master_password_from_dialog(email, password):
                self.show_warning("Failed to set master password.")
                return
            # Proceed to set up 2FA
            self.setup_two_factor_authentication(email)
            return

        # Verify master password
        if not verify_master_password(self.conn, email, password):
            self.show_warning("Incorrect master password.")
            return

        # Open ConfirmPasswordDialog
        confirm_dialog = ConfirmPasswordDialog(self)
        if confirm_dialog.exec() == QDialog.Accepted:
            confirm_password = confirm_dialog.get_password()
            if confirm_password != password:
                self.show_warning("Passwords do not match.")
                return
            else:
                logger.info("Master password confirmed.")

        else:
            # User canceled confirmation
            self.show_warning("Master password confirmation canceled.")
            return

        # Handle 2FA verification
        two_fa = TwoFactorAuthentication(self.user_email, self.conn)
        if not self.is_device_trusted():
            # Check if 2FA is already set up
            if not two_fa.get_secret():
                # 2FA not set up, initiate setup
                self.setup_two_factor_authentication(email)
                return
            else:
                # 2FA is set up, prompt for token
                token_dialog = TwoFATokenDialog(self)
                if token_dialog.exec() == QDialog.Accepted:
                    token = token_dialog.get_token()
                    if two_fa.verify_token(token):
                        logger.info("2FA verification successful.")
                    else:
                        self.show_warning("Invalid 2FA token.")
                        return
                else:
                    self.show_warning("2FA token entry canceled.")
                    return
        else:
            logger.info("Device is trusted. Skipping 2FA verification.")

        # If all validations pass, accept the dialog and pass the data
        self.accept()

        # Handle "Remember this device" feature via main_window
        if remember_device and self.main_window:
            self.main_window.mark_device_as_trusted()

    def setup_two_factor_authentication(self, email: str):
        """Set up Two-Factor Authentication for the user."""
        two_fa = TwoFactorAuthentication(email, self.conn)
        try:
            # Generate 2FA secret
            secret = two_fa.generate_secret()
            logger.info("2FA secret generated successfully.")

            # Store the 2FA secret in the database
            if not two_fa.store_secret(secret):
                self.show_warning("Failed to store 2FA secret.")
                return

            # Generate QR code
            qr_code_image_data = two_fa.generate_qr_code()

            # Show QR code dialog
            qr_dialog = QRCodeDialog(qr_code_image_data, self)
            qr_dialog.exec()

            # After scanning QR code, prompt for 2FA token
            token_dialog = TwoFATokenDialog(self)
            if token_dialog.exec() == QDialog.Accepted:
                token = token_dialog.get_token()
                if two_fa.verify_token(token):
                    logger.info("2FA verification successful.")
                    # Mark device as trusted if needed
                    if self.remember_device and self.main_window:
                        self.main_window.mark_device_as_trusted()
                    # Show "Forgot master password" button
                    self.forgot_password_button.show()
                    # Accept the login
                    self.accept()
                else:
                    self.show_warning("Invalid 2FA token. Please try again.")
            else:
                self.show_warning("2FA token entry canceled.")
        except Exception as e:
            logger.error(f"Failed to set up 2FA: {e}")
            self.show_warning(f"Failed to set up Two-Factor Authentication: {e}")

    def set_master_password_from_dialog(self, email: str, password: str) -> bool:
        """Set the master password using the provided password from the dialog."""
        if self.validate_master_password(password):
            confirm_password, ok = QInputDialog.getText(
                self,
                "Confirm Master Password",
                "Confirm your master password:",
                QLineEdit.Password,
            )
            if ok and password == confirm_password:
                try:
                    set_master_password(self.conn, email, password)
                    # Corrected line: Access session via main_window
                    if self.main_window:
                        self.main_window.session.set_master_password(password)
                    CustomMessageBox(
                        "Info",
                        "Master password set successfully!",
                        QMessageBox.Information,
                    ).show_message()
                    logger.info(f"Master password set successfully for user: {email}")
                    return True
                except Exception as e:
                    logger.error(f"Error setting master password for {email}: {e}")
                    self.show_warning(
                        "Failed to set master password. Please try again."
                    )
                    return False
            else:
                self.show_warning("Passwords do not match. Please try again.")
                return False
        else:
            self.show_warning(
                "Password does not meet the required criteria. Please try again."
            )
            return False

    def handle_forgot_password(self):
        """Handle the master password recovery process using 2FA."""
        # This functionality is now accessible only after initial setup
        email, ok = QInputDialog.getText(
            self,
            "Master Password Recovery",
            "Enter your registered email address:",
            QLineEdit.Normal,
        )
        if ok and email:
            email = email.strip().lower()
            if not self.validate_email(email):
                self.show_warning("Please enter a valid email address.")
                return

            # Verify that the email exists in the database
            user_id = get_user_id(self.conn, email)
            if user_id is None:
                self.show_warning("Email address not found.")
                return

            # Initiate 2FA verification
            two_fa = TwoFactorAuthentication(email, self.conn)
            if not two_fa.get_secret():
                self.show_warning("2FA is not set up for this account.")
                return

            # Prompt for 2FA token
            token, ok = QInputDialog.getText(
                self,
                "Two-Factor Authentication",
                "Enter your 2FA token:",
                QLineEdit.Normal,
            )
            if ok and token:
                if two_fa.verify_token(token.strip()):
                    logger.info("2FA verification successful for password recovery.")
                    # Proceed to reset master password
                    self.reset_master_password(email)
                else:
                    self.show_warning("Invalid 2FA token.")
            else:
                self.show_warning("2FA token is required for password recovery.")
        else:
            self.show_warning("Email address is required for password recovery.")

    def reset_master_password(self, email: str):
        """Allow the user to reset their master password after successful 2FA verification."""
        # Warn the user about data loss if applicable
        warning_msg = (
            "Resetting your master password will erase all your stored passwords and notes, "
            "as they cannot be recovered without the old master password. Do you wish to proceed?"
        )
        reply = QMessageBox.question(
            self,
            "Data Loss Warning",
            warning_msg,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )

        if reply == QMessageBox.Yes:
            # Prompt for new master password
            new_password, ok = QInputDialog.getText(
                self,
                "Reset Master Password",
                "Enter your new master password:",
                QLineEdit.Password,
            )
            if ok and new_password:
                confirm_password, ok = QInputDialog.getText(
                    self,
                    "Confirm Master Password",
                    "Confirm your new master password:",
                    QLineEdit.Password,
                )
                if ok and new_password == confirm_password:
                    if self.validate_master_password(new_password):
                        # Update the master password in the database
                        success, message = update_master_password(
                            self.conn, email, self.user_password, new_password
                        )
                        if success:
                            # Wipe user data if necessary
                            wipe_user_data(self.conn, email)
                            # Optionally, set the new master password
                            if self.main_window:
                                self.main_window.session.set_master_password(
                                    new_password
                                )
                            CustomMessageBox(
                                "Success",
                                "Your master password has been reset. All your stored data has been cleared.",
                                QMessageBox.Information,
                            ).show_message()
                            self.accept()  # Close the dialog and proceed as needed
                        else:
                            self.show_warning(message)
                    else:
                        self.show_warning(
                            "Password does not meet the complexity requirements."
                        )
                else:
                    self.show_warning("Passwords do not match.")
            else:
                self.show_warning("Master password reset cancelled.")
        else:
            self.show_info("Master password reset cancelled.")

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

    def validate_master_password(self, password: str) -> bool:
        """
        Validate the master password against defined security criteria.

        Args:
            password (str): The master password to validate.

        Returns:
            bool: True if the password meets all criteria, False otherwise.
        """
        # Define password criteria
        min_length = 8
        if len(password) < min_length:
            self.show_warning(
                f"Password must be at least {min_length} characters long."
            )
            return False
        if not re.search(r"[A-Z]", password):
            self.show_warning("Password must contain at least one uppercase letter.")
            return False
        if not re.search(r"[a-z]", password):
            self.show_warning("Password must contain at least one lowercase letter.")
            return False
        if not re.search(r"[0-9]", password):
            self.show_warning("Password must contain at least one digit.")
            return False
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            self.show_warning(
                'Password must contain at least one special character (!@#$%^&*(),.?":{}|<>).'
            )
            return False
        # Add more criteria as needed
        return True

    def show_warning(self, message: str):
        """Display a warning message."""
        CustomMessageBox("Warning", message, QMessageBox.Warning).show_message()

    def show_info(self, message: str):
        """Display an informational message."""
        CustomMessageBox("Information", message, QMessageBox.Information).show_message()

    def toggle_password_visibility(self):
        """Toggle the visibility of the master password."""
        if self.password_input.echoMode() == QLineEdit.Password:
            self.password_input.setEchoMode(QLineEdit.Normal)
            self.toggle_password_button.setText("Hide")
        else:
            self.password_input.setEchoMode(QLineEdit.Password)
            self.toggle_password_button.setText("Show")

    def get_credentials(self) -> Optional[dict]:
        """
        Retrieve the entered credentials after a successful login.

        Returns:
            Optional[dict]: A dictionary containing 'email', 'password', 'two_fa_token', and 'remember_device' if available.
        """
        if self.result() == QDialog.Accepted:
            return {
                "email": self.user_email,
                "password": self.user_password,
                "two_fa_token": self.user_two_fa_token,
                "remember_device": self.remember_device,
            }
        return None
