import json
import logging
import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QColorDialog,
    QComboBox,
    QLabel,
    QMainWindow,
    QPushButton,
    QSlider,
    QVBoxLayout,
    QWidget,
)

# Configure logging only if it has not been configured already
if not logging.getLogger().hasHandlers():
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )

logger = logging.getLogger(__name__)


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
        self.font_dropdown.addItems(self.get_available_fonts())
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

    def get_available_fonts(self):
        """Returns a list of available fonts for the font dropdown."""
        return [
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
        """Apply the local settings to the current settings page and main window."""
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

        # Apply custom button styling
        if "colors" in settings_to_apply:
            stylesheet += (
                "QPushButton {"
                "background-color: transparent;"
                "color: #c1c1c1;"
                "font-weight: bold;"
                f"border: 2px solid {self.local_settings['button_color']};"
                "padding: 0px;"
                "margin: 0px;"
                "border-radius: 5px;"
                "min-height: 30px;"
                "qproperty-iconSize: 32px;"
                "}"
                "QPushButton::hover {"
                f"background-color: {self.local_settings['button_color']};"
                "color: #ffffff;"
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
        """Apply local settings globally and save them."""
        self.current_settings = self.local_settings.copy()
        logging.info(f"Applying Global Settings: {self.current_settings}")
        self.save_settings(self.current_settings)
        self.apply_global_styles()

    def apply_global_styles(self):
        """Apply the global stylesheet to the main window."""
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
            f"#leftColumn {{"
            f"background-color: {self.current_settings['background_color']};"
            f"}}"
            f"QTableWidget {{"
            f"background-color: {self.current_settings['background_color']};"
            f"color: #ffffff;"
            f"}}"
            f"QTableWidget::item {{"
            f"background-color: {self.current_settings['background_color']};"
            f"color: #ffffff;"
            f"}}"
            f"QHeaderView::section {{"
            f"background-color: {self.current_settings['background_color']};"
            f"color: #ffffff;"
            f"}}"
        )

        self.main_window.setStyleSheet(global_stylesheet)

    def reset_settings(self):
        """Reset settings to default values."""
        self.local_settings = self.default_settings.copy()
        self.apply_settings(settings_to_apply={"font_size", "font_family", "colors"})
        self.font_size_slider.setValue(self.default_settings["font_size"])
        self.font_dropdown.setCurrentText(self.default_settings["font_family"])
        logging.info("Settings have been reset to default.")

    def save_settings(self, settings):
        """Save the current settings to a JSON file."""
        try:
            with open("settings.json", "w") as file:
                json.dump(settings, file)
            logging.info("Settings saved successfully.")
        except IOError as e:
            logging.error(f"Failed to save settings: {e}")

    def load_settings(self):
        """Load settings from a JSON file, falling back to default settings if necessary."""
        if os.path.exists("settings.json"):
            try:
                with open("settings.json", "r") as file:
                    return json.load(file)
            except (IOError, json.JSONDecodeError) as e:
                logging.error(f"Failed to load settings: {e}")
        return None

    def update_font_size(self):
        """Update the font size based on the slider value."""
        font_size = self.font_size_slider.value()
        self.local_settings["font_size"] = font_size
        self.apply_settings(settings_to_apply={"font_size", "font_family", "colors"})

    def update_font(self):
        """Update the font family based on the dropdown selection."""
        font = self.font_dropdown.currentText()
        self.local_settings["font_family"] = font
        self.apply_settings(settings_to_apply={"font_size", "font_family", "colors"})

    def update_button_color(self):
        """Update the button color using the color picker."""
        color = QColorDialog.getColor()
        if color.isValid():
            self.local_settings["button_color"] = color.name()
            self.apply_settings(
                settings_to_apply={"font_size", "font_family", "colors"}
            )

    def update_background_color(self):
        """Update the background color using the color picker."""
        color = QColorDialog.getColor()
        if color.isValid():
            self.local_settings["background_color"] = color.name()
            self.apply_settings(
                settings_to_apply={"font_size", "font_family", "colors"}
            )
