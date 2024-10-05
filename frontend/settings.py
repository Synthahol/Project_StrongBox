# settings.py

"""This module contains the SettingsTab class for managing user and visual settings."""

import json
import logging
import os
import re

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon, QPixmap
from PySide6.QtWidgets import (
    QColorDialog,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSlider,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from backend.database import (
    delete_2fa_secret,
    update_email,  # Corrected import
    update_master_password,  # Corrected import
)
from backend.exceptions import SecretAlreadyExistsError  # Ensure this is defined
from backend.two_factor_auth import TwoFactorAuthentication
from frontend.blueprints import ButtonFactory, add_title_and_description

logger = logging.getLogger(__name__)

SETTINGS_DIR = os.path.join(os.path.expanduser("~"), ".fortalice")
os.makedirs(SETTINGS_DIR, exist_ok=True)
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "settings.json")


class ChangeMasterPasswordDialog(QDialog):
    """Dialog for changing the master password."""

    def __init__(self, main_window):
        super().__init__(main_window)
        self.main_window = main_window
        self.setWindowTitle("Change Master Password")
        self.setWindowIcon(QIcon(r"frontend/icons/encryption.png"))
        self.setMinimumSize(400, 300)

        layout = QVBoxLayout(self)

        # Current Password
        self.current_pw_label = QLabel("Enter Current Master Password:")
        self.current_pw_input = QLineEdit()
        self.current_pw_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.current_pw_label)
        layout.addWidget(self.current_pw_input)

        # New Password
        self.new_pw_label = QLabel("Enter New Master Password:")
        self.new_pw_input = QLineEdit()
        self.new_pw_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.new_pw_label)
        layout.addWidget(self.new_pw_input)

        # Confirm New Password
        self.confirm_pw_label = QLabel("Confirm New Master Password:")
        self.confirm_pw_input = QLineEdit()
        self.confirm_pw_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.confirm_pw_label)
        layout.addWidget(self.confirm_pw_input)

        # Buttons
        button_factory = ButtonFactory(self)
        buttons = [
            ("Change Password", 140, self.change_password),
            ("Cancel", 100, self.reject),
        ]
        button_layout = button_factory.create_buttons_with_spacing(buttons)
        layout.addLayout(button_layout)

    def change_password(self):
        current_pw = self.current_pw_input.text()
        new_pw = self.new_pw_input.text()
        confirm_pw = self.confirm_pw_input.text()

        if not current_pw or not new_pw or not confirm_pw:
            self.main_window.show_warning("All fields are required.")
            return

        if new_pw != confirm_pw:
            self.main_window.show_warning("New passwords do not match.")
            return

        try:
            success, message = update_master_password(  # Updated function call
                self.main_window.conn, current_pw, new_pw
            )
            if success:
                self.main_window.show_info("Master password changed successfully.")
                self.accept()
            else:
                self.main_window.show_warning(message)
        except Exception as e:
            self.main_window.show_warning(f"Failed to change master password: {str(e)}")
            logger.error(f"Failed to change master password: {str(e)}")


class ChangeEmailDialog(QDialog):
    """Dialog for changing the user's email address."""

    def __init__(self, main_window):
        super().__init__(main_window)
        self.main_window = main_window
        self.setWindowTitle("Change Email Address")
        self.setWindowIcon(QIcon(r"frontend/icons/encryption.png"))
        self.setMinimumSize(400, 250)

        layout = QVBoxLayout(self)

        # Current Master Password
        self.current_pw_label = QLabel("Enter Current Master Password:")
        self.current_pw_input = QLineEdit()
        self.current_pw_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.current_pw_label)
        layout.addWidget(self.current_pw_input)

        # New Email Address
        self.new_email_label = QLabel("Enter New Email Address:")
        self.new_email_input = QLineEdit()
        layout.addWidget(self.new_email_label)
        layout.addWidget(self.new_email_input)

        # Buttons
        button_factory = ButtonFactory(self)
        buttons = [
            ("Change Email", 120, self.change_email),
            ("Cancel", 100, self.reject),
        ]
        button_layout = button_factory.create_buttons_with_spacing(buttons)
        layout.addLayout(button_layout)

    def change_email(self):
        current_pw = self.current_pw_input.text()
        new_email = self.new_email_input.text().strip().lower()

        if not current_pw or not new_email:
            self.main_window.show_warning("All fields are required.")
            return

        if not self.validate_email(new_email):
            self.main_window.show_warning("Invalid email address format.")
            return

        try:
            success, message = update_email(  # Updated function call
                self.main_window.conn, current_pw, new_email
            )
            if success:
                self.main_window.show_info("Email address updated successfully.")
                self.accept()
            else:
                self.main_window.show_warning(message)
        except Exception as e:
            self.main_window.show_warning(f"Failed to change email address: {str(e)}")
            logger.error(f"Failed to change email address: {str(e)}")

    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate the email format."""
        pattern = r"[^@]+@[^@]+\.[^@]+"
        return re.match(pattern, email) is not None


class SettingsTab(QWidget):
    """Settings tab with navigation for User Settings and Visual Settings."""

    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.layout = QVBoxLayout(self)

        # Default and current settings
        self.default_settings = {
            "font_size": 20,
            "font_family": "Roboto",
            "button_color": "#00A36C",
            "background_color": "#232430",
        }
        self.current_settings = self.load_settings() or self.default_settings.copy()
        self.local_settings = self.current_settings.copy()

        self.create_ui()
        self.apply_settings_globally()

    def create_ui(self):
        add_title_and_description(
            self.layout,
            "Settings",
            "Change the user settings and visual preferences to your liking.",
        )

        # Navigation Buttons
        nav_layout = QHBoxLayout()
        self.user_settings_button = QPushButton("User Settings")
        self.user_settings_button.clicked.connect(self.show_user_settings)
        self.visual_settings_button = QPushButton("Visual Settings")
        self.visual_settings_button.clicked.connect(self.show_visual_settings)

        # Style navigation buttons
        for btn in [self.user_settings_button, self.visual_settings_button]:
            btn.setCursor(Qt.PointingHandCursor)
            btn.setStyleSheet(
                "QPushButton {"
                "background-color: #00A36C;"
                "color: white;"
                "border: none;"
                "padding: 10px 20px;"
                "border-radius: 5px;"
                "font-weight: bold;"
                "}"
                "QPushButton::hover {"
                "background-color: #008f5e;"
                "}"
            )
            nav_layout.addWidget(btn)

        self.layout.addLayout(nav_layout)

        # Stacked Widget for User Settings and Visual Settings
        self.stacked_widget = QStackedWidget()
        self.layout.addWidget(self.stacked_widget)

        # User Settings Page
        self.user_settings_page = QWidget()
        user_layout = QVBoxLayout(self.user_settings_page)

        # Change Master Password Button
        change_master_pw_button = QPushButton("Change Master Password")
        change_master_pw_button.clicked.connect(self.change_master_password)
        user_layout.addWidget(change_master_pw_button)

        # Change Email Button
        change_email_button = QPushButton("Change Email")
        change_email_button.clicked.connect(self.change_email)
        user_layout.addWidget(change_email_button)

        # Two-Factor Authentication Section
        self.setup_two_factor_auth_section(user_layout)

        user_layout.addStretch()
        self.stacked_widget.addWidget(self.user_settings_page)

        # Visual Settings Page
        self.visual_settings_page = QWidget()
        visual_layout = QVBoxLayout(self.visual_settings_page)

        # Font Size Slider
        font_size_label = QLabel("Font Size:")
        self.font_size_slider = QSlider(Qt.Horizontal)
        self.font_size_slider.setRange(12, 38)
        self.font_size_slider.setValue(self.local_settings["font_size"])
        self.font_size_slider.valueChanged.connect(self.update_font_size)

        visual_layout.addWidget(font_size_label)
        visual_layout.addWidget(self.font_size_slider)

        # Font Dropdown
        font_label = QLabel("Font:")
        self.font_dropdown = QComboBox()
        self.font_dropdown.addItems(self.get_available_fonts())
        self.font_dropdown.setCurrentText(self.local_settings["font_family"])
        self.font_dropdown.currentIndexChanged.connect(self.update_font)

        visual_layout.addWidget(font_label)
        visual_layout.addWidget(self.font_dropdown)

        # Button Color Picker
        button_color_label = QLabel("Button Color:")
        self.button_color_picker = QPushButton("Pick Color")
        self.button_color_picker.clicked.connect(self.update_button_color)

        visual_layout.addWidget(button_color_label)
        visual_layout.addWidget(self.button_color_picker)

        # Background Color Picker
        bg_color_label = QLabel("Background Color:")
        self.bg_color_picker = QPushButton("Pick Color")
        self.bg_color_picker.clicked.connect(self.update_background_color)

        visual_layout.addWidget(bg_color_label)
        visual_layout.addWidget(self.bg_color_picker)

        # Apply and Reset Buttons
        apply_button = QPushButton("Apply Settings")
        apply_button.clicked.connect(self.apply_settings_globally)

        reset_button = QPushButton("Reset to Default")
        reset_button.clicked.connect(self.reset_settings)

        visual_layout.addWidget(apply_button)
        visual_layout.addWidget(reset_button)

        visual_layout.addStretch()
        self.stacked_widget.addWidget(self.visual_settings_page)

        # Set initial view to User Settings
        self.show_user_settings()

    def get_available_fonts(self):
        """Returns a list of available fonts for the font dropdown."""
        return [
            "Roboto",
            "Arial",
            "Verdana",
            "Helvetica",
            "Times New Roman",
            "Courier New",
            "Georgia",
            "Trebuchet MS",
            "Tahoma",
            "Comic Sans MS",
            "Impact",
            "Lucida Console",
            "Palatino Linotype",
            "Segoe UI",
            "Gill Sans",
            "Candara",
            "Arial Black",
            "Calibri",
            "Cambria",
            "Garamond",
            "Century Gothic",
        ]

    def show_user_settings(self):
        """Display the User Settings page."""
        self.stacked_widget.setCurrentWidget(self.user_settings_page)

    def show_visual_settings(self):
        """Display the Visual Settings page."""
        self.stacked_widget.setCurrentWidget(self.visual_settings_page)

    def setup_two_factor_auth_section(self, layout: QVBoxLayout):
        """Set up the Two-Factor Authentication section within User Settings."""
        group_box = QWidget()
        group_layout = QVBoxLayout(group_box)

        two_fa = TwoFactorAuthentication(
            self.main_window.user_identifier, self.main_window.conn
        )
        secret = two_fa.get_secret()

        if secret:
            self.two_fa_status_label = QLabel("Two-Factor Authentication is enabled.")
            self.disable_two_fa_button = QPushButton("Disable 2FA")
            self.disable_two_fa_button.clicked.connect(self.disable_two_factor_auth)
            group_layout.addWidget(self.two_fa_status_label)
            group_layout.addWidget(self.disable_two_fa_button)
        else:
            self.two_fa_status_label = QLabel(
                "Two-Factor Authentication is not enabled."
            )
            self.enable_two_fa_button = QPushButton("Enable 2FA")
            self.enable_two_fa_button.clicked.connect(self.enable_two_factor_auth)
            group_layout.addWidget(self.two_fa_status_label)
            group_layout.addWidget(self.enable_two_fa_button)

        layout.addWidget(group_box)

    def change_master_password(self):
        """Open the Change Master Password dialog."""
        dialog = ChangeMasterPasswordDialog(self.main_window)
        dialog.exec()

    def change_email(self):
        """Open the Change Email dialog."""
        dialog = ChangeEmailDialog(self.main_window)
        dialog.exec()

    def apply_settings(self, settings_to_apply=None):
        if settings_to_apply is None:
            settings_to_apply = {"font_size", "font_family", "colors"}

        stylesheet = "QWidget {"
        if "font_size" in settings_to_apply:
            stylesheet += f"font-size: {self.local_settings['font_size']}px;"
        if "font_family" in settings_to_apply:
            stylesheet += f"font-family: {self.local_settings['font_family']};"
        if "colors" in settings_to_apply:
            stylesheet += (
                f"background-color: {self.local_settings['background_color']};"
            )
        stylesheet += "}"

        if "colors" in settings_to_apply:
            stylesheet += (
                "QPushButton {"
                "background-color: transparent;"
                "color: #c1c1c1;"
                "font-weight: bold;"
                f"border: 2px solid {self.local_settings['button_color']};"
                "border-radius: 5px;"
                "min-height: 30px;"
                "}"
                "QPushButton::hover {"
                f"background-color: {self.local_settings['button_color']};"
                "color: #ffffff;"
                "}"
            )

        self.setStyleSheet(stylesheet)
        logger.info(f"Applied local settings: {self.local_settings}")

    def apply_settings_globally(self):
        self.current_settings = self.local_settings.copy()
        self.save_settings()
        self.apply_global_styles()
        logger.info(f"Applied global settings: {self.current_settings}")

    def apply_global_styles(self):
        stylesheet = (
            f"QWidget {{"
            f"background-color: {self.current_settings['background_color']};"
            f"font-size: {self.current_settings['font_size']}px;"
            f"font-family: {self.current_settings['font_family']};"
            f"}}"
            f"QPushButton {{"
            f"background-color: transparent;"
            f"color: #c1c1c1;"
            f"font-weight: bold;"
            f"border: 2px solid {self.current_settings['button_color']};"
            f"border-radius: 5px;"
            f"min-height: 30px;"
            f"}}"
            f"QPushButton::hover {{"
            f"background-color: {self.current_settings['button_color']};"
            f"color: #ffffff;"
            f"}}"
        )
        self.main_window.setStyleSheet(stylesheet)

    def reset_settings(self):
        self.local_settings = self.default_settings.copy()
        self.font_size_slider.setValue(self.default_settings["font_size"])
        self.font_dropdown.setCurrentText(self.default_settings["font_family"])
        self.apply_settings()
        self.apply_settings_globally()
        logger.info("Settings have been reset to default.")

    def save_settings(self):
        try:
            with open(SETTINGS_FILE, "w") as file:
                json.dump(self.current_settings, file)
            logger.info("Settings saved successfully.")
        except IOError as e:
            logger.error(f"Failed to save settings: {e}")

    def load_settings(self):
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, "r") as file:
                    return json.load(file)
            except (IOError, json.JSONDecodeError) as e:
                logger.error(f"Failed to load settings: {e}")
        return None

    def update_font_size(self):
        self.local_settings["font_size"] = self.font_size_slider.value()
        self.apply_settings({"font_size"})

    def update_font(self):
        self.local_settings["font_family"] = self.font_dropdown.currentText()
        self.apply_settings({"font_family"})

    def update_button_color(self):
        color = QColorDialog.getColor()
        if color.isValid():
            self.local_settings["button_color"] = color.name()
            self.apply_settings({"colors"})

    def update_background_color(self):
        color = QColorDialog.getColor()
        if color.isValid():
            self.local_settings["background_color"] = color.name()
            self.apply_settings({"colors"})

    def enable_two_factor_auth(self):
        two_fa = TwoFactorAuthentication(
            self.main_window.user_identifier, self.main_window.conn
        )
        try:
            two_fa.generate_secret()
            qr_code_image = two_fa.generate_qr_code()
            # Display the QR code to the user
            self.show_qr_code(qr_code_image)
            self.two_fa_status_label.setText("Two-Factor Authentication is enabled.")
            self.disable_two_fa_button = QPushButton("Disable 2FA")
            self.disable_two_fa_button.clicked.connect(self.disable_two_factor_auth)
            # Remove existing enable button and add disable button
            self.enable_two_fa_button.deleteLater()
            self.user_settings_page.layout().addWidget(self.disable_two_fa_button)
            logger.info("2FA enabled for user.")
        except SecretAlreadyExistsError:
            logger.info("2FA is already set up for this user.")
            self.main_window.show_warning(
                "Two-Factor Authentication is already enabled."
            )
        except Exception as e:
            self.main_window.show_warning(f"Failed to enable 2FA: {str(e)}")
            logger.error(f"Failed to enable 2FA: {str(e)}")

    def disable_two_factor_auth(self):
        reply = QMessageBox.question(
            self,
            "Disable 2FA",
            "Are you sure you want to disable Two-Factor Authentication?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            try:
                delete_2fa_secret(
                    self.main_window.conn, self.main_window.user_identifier
                )
                self.two_fa_status_label.setText(
                    "Two-Factor Authentication is disabled."
                )
                self.enable_two_fa_button = QPushButton("Enable 2FA")
                self.enable_two_fa_button.clicked.connect(self.enable_two_factor_auth)
                # Remove existing disable button and add enable button
                self.disable_two_fa_button.deleteLater()
                self.user_settings_page.layout().addWidget(self.enable_two_fa_button)
                logger.info("2FA disabled for user.")
            except Exception as e:
                self.main_window.show_warning(f"Failed to disable 2FA: {str(e)}")
                logger.error(f"Failed to disable 2FA: {str(e)}")

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
