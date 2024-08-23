import json
import logging
import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QColorDialog,
    QComboBox,
    QLabel,
    QMainWindow,  # Assuming your main window class is derived from QMainWindow
    QPushButton,
    QSlider,
    QVBoxLayout,
    QWidget,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class SettingsTab(QWidget):
    def __init__(self, main_window: QMainWindow):
        super().__init__()
        self.layout = QVBoxLayout(self)

        # Reference to the main window to apply global styles
        self.main_window = main_window

        # Default settings
        self.default_settings = {
            "font_size": 14,
            "font_family": "Arial",
            "button_color": "#00A36C",  # Primary button color
            "background_color": "#232430",  # Background color
        }

        # Load or initialize current settings
        self.current_settings = self.load_settings() or self.default_settings.copy()

        # Local settings (for local changes on the settings page)
        self.local_settings = self.current_settings.copy()

        self.create_ui()

    def create_ui(self):
        # Font size slider
        font_size_label = QLabel("Font Size:")
        self.font_size_slider = QSlider(Qt.Horizontal)
        self.font_size_slider.setRange(12, 38)
        self.font_size_slider.setValue(self.local_settings["font_size"])
        self.font_size_slider.valueChanged.connect(self.update_font_size)

        # Font dropdown
        font_label = QLabel("Font:")
        self.font_dropdown = QComboBox()
        self.font_dropdown.addItems(
            [
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
        )

        self.font_dropdown.setCurrentText(self.local_settings["font_family"])
        self.font_dropdown.currentIndexChanged.connect(self.update_font)

        # Button color picker
        button_color_label = QLabel("Button Color:")
        self.button_color_picker = QPushButton("Pick Color")
        self.button_color_picker.clicked.connect(self.update_button_color)

        # Background color picker
        bg_color_label = QLabel("Background Color:")
        self.bg_color_picker = QPushButton("Pick Color")
        self.bg_color_picker.clicked.connect(self.update_background_color)

        # Apply and reset buttons
        apply_button = QPushButton("Apply Settings")
        apply_button.clicked.connect(self.apply_settings_globally)

        reset_button = QPushButton("Reset to Default")
        reset_button.clicked.connect(self.reset_settings)

        # Add widgets to layout
        self.layout.addWidget(font_size_label)
        self.layout.addWidget(self.font_size_slider)
        self.layout.addWidget(font_label)
        self.layout.addWidget(self.font_dropdown)
        self.layout.addWidget(button_color_label)
        self.layout.addWidget(self.button_color_picker)
        self.layout.addWidget(bg_color_label)
        self.layout.addWidget(self.bg_color_picker)
        self.layout.addWidget(apply_button)
        self.layout.addWidget(reset_button)

        # Apply the local settings to the settings page
        self.apply_settings(settings_to_apply={"font_size", "font_family", "colors"})

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

        # Apply custom button styling (Default or user-defined)
        if "colors" in settings_to_apply:
            stylesheet += (
                "QPushButton {"
                "background-color: transparent;"  # Transparent background
                "color: #c1c1c1;"  # Light white text color by default
                "font-weight: bold;"
                f"border: 2px solid {self.local_settings['button_color']};"  # Colored border
                "padding: 0px;"  # Remove padding
                "margin: 0px;"  # Remove margin
                "border-radius: 5px;"  # Rounded corners
                "min-height: 30px;"  # Set minimum height
                "qproperty-iconSize: 32px;"
                "}"
                "QPushButton::hover {"
                f"background-color: {self.local_settings['button_color']};"  # Background color on hover
                "color: #ffffff;"  # White text color on hover
                "}"
            )

        self.setStyleSheet(stylesheet)

        logging.info(
            f"Applying Local Settings: "
            f"Font Size = {self.local_settings['font_size'] if 'font_size' in settings_to_apply else 'No Change'}, "
            f"Font Family = {self.local_settings['font_family'] if 'font_family' in settings_to_apply else 'No Change'}, "
            f"Button Color = {self.local_settings['button_color'] if 'colors' in settings_to_apply else 'No Change'}, "
            f"Background Color = {self.local_settings['background_color'] if 'colors' in settings_to_apply else 'No Change'}"
        )

    def apply_settings_globally(self):
        # Apply local settings globally
        self.current_settings = self.local_settings.copy()

        # Log the global settings application
        logging.info(f"Applying Global Settings: {self.current_settings}")

        # Save the settings to a file
        self.save_settings(self.current_settings)

        # Apply globally to the entire application
        self.apply_global_styles()

    def apply_global_styles(self):
        # Create a global stylesheet using current settings
        global_stylesheet = (
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
            f"padding: 0px;"
            f"margin: 0px;"
            f"border-radius: 5px;"
            f"min-height: 30px;"
            f"qproperty-iconSize: 32px;"
            f"}}"
            f"QPushButton::hover {{"
            f"background-color: {self.current_settings['button_color']};"
            f"color: #ffffff;"
            f"}}"
            # Apply background color to the left column and other relevant areas
            f"#leftColumn {{"
            f"background-color: {self.current_settings['background_color']};"
            f"}}"
            # Apply background color to the passwords table and its cells
            f"QTableWidget {{"
            f"background-color: {self.current_settings['background_color']};"
            f"gridline-color: {self.current_settings['button_color']};"
            f"color: #ffffff;"  # Adjust text color if needed
            f"}}"
            f"QTableWidget::item {{"
            f"background-color: {self.current_settings['background_color']};"
            f"color: #ffffff;"  # Text color for cells
            f"}}"
            # Apply background color to the table headers
            f"QHeaderView::section {{"
            f"background-color: {self.current_settings['background_color']};"
            f"color: #ffffff;"  # Text color for headers
            f"border: 1px solid {self.current_settings['button_color']};"  # Border for headers
            f"}}"
        )

        # Apply the global stylesheet to the main window
        self.main_window.setStyleSheet(global_stylesheet)

    def reset_settings(self):
        self.local_settings = self.default_settings.copy()
        self.apply_settings(settings_to_apply={"font_size", "font_family", "colors"})
        self.font_size_slider.setValue(self.default_settings["font_size"])
        self.font_dropdown.setCurrentText(self.default_settings["font_family"])

    def save_settings(self, settings):
        try:
            with open("settings.json", "w") as file:
                json.dump(settings, file)
        except IOError as e:
            logging.error(f"Failed to save settings: {e}")

    def load_settings(self):
        if os.path.exists("settings.json"):
            try:
                with open("settings.json", "r") as file:
                    return json.load(file)
            except (IOError, json.JSONDecodeError) as e:
                logging.error(f"Failed to load settings: {e}")
        return None

    def update_font_size(self):
        font_size = self.font_size_slider.value()
        self.local_settings["font_size"] = font_size
        # Apply font size, font family, and colors to retain the selected settings
        self.apply_settings(settings_to_apply={"font_size", "font_family", "colors"})

    def update_font(self):
        font = self.font_dropdown.currentText()
        self.local_settings["font_family"] = font
        # Apply font family, font size, and colors to retain the selected settings
        self.apply_settings(settings_to_apply={"font_size", "font_family", "colors"})

    def update_button_color(self):
        color = QColorDialog.getColor()
        if color.isValid():
            self.local_settings["button_color"] = color.name()
            # Apply button color, font size, and font family to retain the selected settings
            self.apply_settings(
                settings_to_apply={"font_size", "font_family", "colors"}
            )

    def update_background_color(self):
        color = QColorDialog.getColor()
        if color.isValid():
            self.local_settings["background_color"] = color.name()
            # Apply background color, font size, and font family to retain the selected settings
            self.apply_settings(
                settings_to_apply={"font_size", "font_family", "colors"}
            )
