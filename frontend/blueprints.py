# blueprints.py

from typing import Callable, List, Tuple

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QStyle,  # Import QStyle to use standard icons
    QVBoxLayout,
)


class ButtonFactory:
    def __init__(self, parent):
        """
        Initialize ButtonFactory with a parent widget.

        Args:
            parent: The parent widget where buttons will be placed.
        """
        self.parent = parent

    def create_button(
        self, button_text: str, button_width: int, button_callback
    ) -> QPushButton:
        """
        Create a QPushButton with specified text, width, and callback.

        Args:
            button_text (str): The text to display on the button.
            button_width (int): The width of the button.
            button_callback (callable): The function to call when the button is clicked.

        Returns:
            QPushButton: The created button.
        """
        button = QPushButton(button_text, parent=self.parent)
        button.setFixedWidth(button_width)
        button.clicked.connect(button_callback)
        return button

    def create_button_with_layout(
        self, label_text: str, button_text: str, button_width: int, button_callback
    ) -> QHBoxLayout:
        """
        Create a button within a QHBoxLayout with optional label.

        Args:
            label_text (str): The text for the label next to the button.
            button_text (str): The text to display on the button.
            button_width (int): The width of the button.
            button_callback (callable): The function to call when the button is clicked.

        Returns:
            QHBoxLayout: A horizontal layout containing the label and button.
        """
        layout = QHBoxLayout()
        if label_text:
            layout.addWidget(QLabel(label_text))

        button = self.create_button(button_text, button_width, button_callback)
        layout.addStretch()
        layout.addWidget(button)
        layout.addStretch()

        return layout

    def create_buttons_with_spacing(
        self, buttons: List[Tuple[str, int, Callable]]
    ) -> QHBoxLayout:
        """
        Create multiple buttons with spacing between them.

        Args:
            buttons (list of tuples): Each tuple contains button text, width, and callback function.

        Returns:
            QHBoxLayout: A horizontal layout containing the buttons.
        """
        layout = QHBoxLayout()
        layout.addStretch(1)

        for button_text, button_width, button_callback in buttons:
            button = self.create_button(button_text, button_width, button_callback)
            layout.addWidget(button)
            layout.addSpacing(20)

        layout.addStretch(1)
        return layout


class CustomMessageBox(QDialog):
    def __init__(
        self,
        title: str,
        message: str,
        icon=QMessageBox.Information,
        button_text: str = "OK",
        parent=None,
    ):
        """
        Initialize a custom message box with a centered button.

        Args:
            title (str): The title of the message box.
            message (str): The message to display.
            icon (QMessageBox.Icon): The icon to display (default is Information).
            button_text (str): The text for the OK button (default is "OK").
            parent: The parent widget (optional).
        """
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setWindowIcon(QIcon("frontend/icons/encryption.png"))
        self.setMinimumSize(300, 150)  # Adjust size as needed

        layout = QVBoxLayout(self)

        # Icon and message
        message_layout = QHBoxLayout()
        icon_label = QLabel()

        # Map QMessageBox.Icon to QStyle.StandardPixmap
        standard_icon = QStyle.SP_MessageBoxInformation  # Default to Information icon
        if icon == QMessageBox.Warning:
            standard_icon = QStyle.SP_MessageBoxWarning
        elif icon == QMessageBox.Critical:
            standard_icon = QStyle.SP_MessageBoxCritical
        elif icon == QMessageBox.Question:
            standard_icon = QStyle.SP_MessageBoxQuestion

        icon_pixmap = self.style().standardIcon(standard_icon).pixmap(48, 48)
        icon_label.setPixmap(icon_pixmap)
        message_label = QLabel(message)
        message_layout.addWidget(icon_label)
        message_layout.addWidget(message_label)
        layout.addLayout(message_layout)

        # Spacer
        layout.addStretch()

        # Centered button
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        ok_button = QPushButton(button_text)
        ok_button.setFixedWidth(100)
        ok_button.clicked.connect(self.accept)
        button_layout.addWidget(ok_button)
        button_layout.addStretch()
        layout.addLayout(button_layout)

    def show_message(self):
        """Display the message box."""
        self.exec()
