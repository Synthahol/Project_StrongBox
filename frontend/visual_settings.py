# visual_settings.py

import json
import logging
import os

from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QColorDialog,
    QComboBox,
    QDialog,
    QLabel,
    QMessageBox,
    QPushButton,
    QSlider,
    QVBoxLayout,
    QWidget,
)

from backend.database import delete_2fa_secret
from backend.two_factor_auth import TwoFactorAuthentication
from frontend.blueprints import add_title_and_description

logger = logging.getLogger(__name__)

SETTINGS_DIR = os.path.join(os.path.expanduser("~"), ".fortalice")
os.makedirs(SETTINGS_DIR, exist_ok=True)
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "settings.json")


class SettingsTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.layout = QVBoxLayout(self)
        self.setup_two_factor_auth_section()

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
            "Visual Settings",
            "Change the font, font size, and color scheme to your liking.",
        )

        # Font Size Slider
        font_size_label = QLabel("Font Size:")
        self.font_size_slider = QSlider(Qt.Horizontal)
        self.font_size_slider.setRange(12, 38)
        self.font_size_slider.setValue(self.local_settings["font_size"])
        self.font_size_slider.valueChanged.connect(self.update_font_size)

        # Font Dropdown
        font_label = QLabel("Font:")
        self.font_dropdown = QComboBox()
        self.font_dropdown.addItems(self.get_available_fonts())
        self.font_dropdown.setCurrentText(self.local_settings["font_family"])
        self.font_dropdown.currentIndexChanged.connect(self.update_font)

        # Button Color Picker
        button_color_label = QLabel("Button Color:")
        self.button_color_picker = QPushButton("Pick Color")
        self.button_color_picker.clicked.connect(self.update_button_color)

        # Background Color Picker
        bg_color_label = QLabel("Background Color:")
        self.bg_color_picker = QPushButton("Pick Color")
        self.bg_color_picker.clicked.connect(self.update_background_color)

        # Apply and Reset Buttons
        apply_button = QPushButton("Apply Settings")
        apply_button.clicked.connect(self.apply_settings_globally)

        reset_button = QPushButton("Reset to Default")
        reset_button.clicked.connect(self.reset_settings)

        # Add widgets to layout
        for widget in [
            font_size_label,
            self.font_size_slider,
            font_label,
            self.font_dropdown,
            button_color_label,
            self.button_color_picker,
            bg_color_label,
            self.bg_color_picker,
            apply_button,
            reset_button,
        ]:
            self.layout.addWidget(widget)

        self.apply_settings()

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

    def setup_two_factor_auth_section(self):
        from PySide6.QtWidgets import QGroupBox

        group_box = QGroupBox("Two-Factor Authentication")
        layout = QVBoxLayout()

        two_fa = TwoFactorAuthentication(
            self.main_window.user_identifier, self.main_window.conn
        )
        secret = two_fa.get_secret()

        if secret:
            self.two_fa_status_label = QLabel("Two-Factor Authentication is enabled.")
            self.disable_two_fa_button = QPushButton("Disable 2FA")
            self.disable_two_fa_button.clicked.connect(self.disable_two_factor_auth)
            layout.addWidget(self.two_fa_status_label)
            layout.addWidget(self.disable_two_fa_button)
        else:
            self.two_fa_status_label = QLabel(
                "Two-Factor Authentication is not enabled."
            )
            self.enable_two_fa_button = QPushButton("Enable 2FA")
            self.enable_two_fa_button.clicked.connect(self.enable_two_factor_auth)
            layout.addWidget(self.two_fa_status_label)
            layout.addWidget(self.enable_two_fa_button)

        group_box.setLayout(layout)
        self.layout.addWidget(group_box)

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
            self.layout().addWidget(self.disable_two_fa_button)
            logger.info("2FA enabled for user.")
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
                self.layout().addWidget(self.enable_two_fa_button)
                logger.info("2FA disabled for user.")
            except Exception as e:
                self.main_window.show_warning(f"Failed to disable 2FA: {str(e)}")
                logger.error(f"Failed to disable 2FA: {str(e)}")

    def show_qr_code(self, qr_code_image_data: bytes):
        qr_dialog = QDialog(self)
        qr_dialog.setWindowTitle("Scan QR Code with Authenticator App")
        layout = QVBoxLayout()
        instructions = QLabel("Scan this QR code with your authenticator app.")
        layout.addWidget(instructions)
        qr_label = QLabel()
        qr_pixmap = QPixmap()
        qr_pixmap.loadFromData(qr_code_image_data)
        qr_label.setPixmap(qr_pixmap)
        layout.addWidget(qr_label)
        qr_dialog.setLayout(layout)
        qr_dialog.exec()
