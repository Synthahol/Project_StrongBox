import logging

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLayout,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

logger = logging.getLogger(__name__)


def create_button(
    text: str,
    icon_path: str = "",
    callback=None,
    style: str = "padding: 5px 10px; font-size: 14px;",
) -> QPushButton:
    """
    Create a styled QPushButton with optional icon and callback function.

    Args:
        text (str): The text to display on the button.
        icon_path (str): The file path to the button's icon. Default is an empty string.
        callback (callable): The function to be called when the button is clicked. Default is None.
        style (str): The CSS style string for the button. Default is 'padding: 5px 10px; font-size: 14px;'.

    Returns:
        QPushButton: The created button widget.
    """
    button = QPushButton(text)
    if icon_path:  # Check if an icon path is provided
        try:
            button.setIcon(QIcon(icon_path))
        except Exception as e:
            logger.error(f"Error loading icon from '{icon_path}': {e}")
            # Optionally, you can set a default icon or handle the UI accordingly
    button.setStyleSheet(style)
    if callback:
        button.clicked.connect(callback)
    return button


def create_input(
    label_text: str,
    placeholder: str,
    parent_layout: QLayout,
    echo_mode: QLineEdit.EchoMode = QLineEdit.Normal,
) -> QLineEdit:
    """
    Create a labeled QLineEdit input field with placeholder text.

    Args:
        label_text (str): The text to display as the label for the input field.
        placeholder (str): The placeholder text for the input field.
        parent_layout (QLayout): The layout to which the label and input field will be added.
        echo_mode (QLineEdit.EchoMode): The echo mode of the input field. Default is QLineEdit.Normal.

    Returns:
        QLineEdit: The created input field widget.
    """
    label = QLabel(label_text)
    parent_layout.addWidget(label)
    input_field = QLineEdit()
    input_field.setPlaceholderText(placeholder)
    input_field.setEchoMode(echo_mode)
    parent_layout.addWidget(input_field)
    return input_field


def create_horizontal_line() -> QFrame:
    """
    Create a horizontal line (QFrame) to be used as a separator.

    Returns:
        QFrame: The created horizontal line widget.
    """
    line = QFrame()
    line.setFrameShape(QFrame.HLine)
    line.setFrameShadow(QFrame.Sunken)
    return line


def create_simple_dialog(
    parent,
    title: str,
    message: str,
    button_text: str = "OK",
    button_alignment: Qt.AlignmentFlag = Qt.AlignCenter,
) -> QDialog:
    """
    Create a simple QDialog with a title, message, and a single button.

    Args:
        parent: The parent widget of the dialog.
        title (str): The title of the dialog window.
        message (str): The message to display in the dialog.
        button_text (str): The text to display on the button. Default is "OK".
        button_alignment (Qt.AlignmentFlag): The alignment for the button. Default is Qt.AlignCenter.

    Returns:
        QDialog: The created dialog widget.
    """
    dialog = QDialog(parent)
    dialog.setWindowTitle(title)
    dialog.setWindowModality(Qt.ApplicationModal)  # Set the dialog to be modal
    layout = QVBoxLayout()

    label = QLabel(message)
    label.setWordWrap(True)  # Enable word wrap for long messages
    layout.addWidget(label)

    button_layout = QHBoxLayout()
    button = QPushButton(button_text)
    button.clicked.connect(dialog.accept)
    button_layout.addWidget(button, alignment=button_alignment)

    layout.addLayout(button_layout)
    dialog.setLayout(layout)
    return dialog
