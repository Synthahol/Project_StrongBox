from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)


def create_button(
    text, icon_path, callback, style="padding: 5px 10px; font-size: 14px;"
):
    button = QPushButton(text)
    if icon_path:  # Check if an icon path is provided
        button.setIcon(QIcon(icon_path))
    button.setStyleSheet(style)
    button.clicked.connect(callback)
    return button


def create_input(label_text, placeholder, parent_layout, echo_mode=QLineEdit.Normal):
    label = QLabel(label_text)
    parent_layout.addWidget(label)
    input_field = QLineEdit()
    input_field.setPlaceholderText(placeholder)
    input_field.setEchoMode(echo_mode)
    parent_layout.addWidget(input_field)
    return input_field


def create_horizontal_line():
    line = QFrame()
    line.setFrameShape(QFrame.HLine)
    line.setFrameShadow(QFrame.Sunken)
    return line


def create_simple_dialog(parent, title, message, button_text="OK"):
    dialog = QDialog(parent)
    dialog.setWindowTitle(title)
    layout = QVBoxLayout()

    label = QLabel(message)
    layout.addWidget(label)

    button = QPushButton(button_text)
    button.clicked.connect(dialog.accept)
    layout.addWidget(button)

    dialog.setLayout(layout)
    return dialog
