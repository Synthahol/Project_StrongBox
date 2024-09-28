# settings.py

import json
import logging
import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QColorDialog,
    QComboBox,
    QLabel,
    QPushButton,
    QSlider,
    QVBoxLayout,
    QWidget,
)

from frontend.blueprints import add_title_and_description

logger = logging.getLogger(__name__)


class SettingsTab(QWidget):
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
            "Visual Settings",
            "Change the font, font size and color scheme to your liking.",
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
            with open("settings.json", "w") as file:
                json.dump(self.current_settings, file)
            logger.info("Settings saved successfully.")
        except IOError as e:
            logger.error(f"Failed to save settings: {e}")

    def load_settings(self):
        if os.path.exists("settings.json"):
            try:
                with open("settings.json", "r") as file:
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
