import logging
import os

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
    icon_path: str = None,
    callback=None,
    style: str = "padding: 5px 10px; font-size: 14px;",
) -> QPushButton:
    """Create a styled QPushButton with optional icon and callback."""
    button = QPushButton(text)
    if icon_path and os.path.exists(icon_path):
        button.setIcon(QIcon(icon_path))
    elif icon_path:
        logger.error(f"Icon path '{icon_path}' does not exist.")
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
    """Create a labeled QLineEdit input field with placeholder text."""
    label = QLabel(label_text)
    input_field = QLineEdit()
    input_field.setPlaceholderText(placeholder)
    input_field.setEchoMode(echo_mode)
    parent_layout.addWidget(label)
    parent_layout.addWidget(input_field)
    return input_field


def create_horizontal_line() -> QFrame:
    """Create a horizontal line (QFrame) to be used as a separator."""
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
    """Create a simple QDialog with a title, message, and a single button."""
    dialog = QDialog(parent)
    dialog.setWindowTitle(title)
    dialog.setWindowModality(Qt.ApplicationModal)
    layout = QVBoxLayout(dialog)

    label = QLabel(message)
    label.setWordWrap(True)
    layout.addWidget(label)

    button_layout = QHBoxLayout()
    button = QPushButton(button_text)
    button.clicked.connect(dialog.accept)
    button_layout.addStretch()
    button_layout.addWidget(button)
    button_layout.addStretch()
    layout.addLayout(button_layout)

    return dialog
