# blueprints.py

import os
from typing import Callable, List, Optional, Tuple

from PySide6.QtGui import QGuiApplication
from PySide6.QtCore import QSize
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QStyle,
    QVBoxLayout,
)


class ButtonFactory:
    def __init__(self, parent=None):
        self.parent = parent

    def create_button(
        self,
        button_text: str,
        button_width: int,
        button_callback: Callable,
        icon_path: Optional[str] = None,
        tooltip: Optional[str] = None,
        object_name: Optional[str] = None,
    ) -> QPushButton:
        """Create a QPushButton with specified properties."""
        button = QPushButton(button_text, parent=self.parent)
        button.setFixedWidth(button_width)
        if icon_path and os.path.exists(icon_path):
            button.setIcon(QIcon(icon_path))
            button.setIconSize(QSize(24, 24))
        if tooltip:
            button.setToolTip(tooltip)
        if object_name:
            button.setObjectName(object_name)
        button.clicked.connect(button_callback)
        button.setStyleSheet("QPushButton { text-align: center; padding: 5px; }")
        return button

    def create_buttons_with_spacing(self, action_buttons: List[Tuple]) -> QHBoxLayout:
        """Create a horizontal layout with buttons spaced evenly."""
        layout = QHBoxLayout()
        layout.setSpacing(20)
        for btn in action_buttons:
            button_text = btn[0]
            button_width = btn[1]
            button_callback = btn[2]
            icon_path = btn[3] if len(btn) > 3 else None
            tooltip = btn[4] if len(btn) > 4 else None
            object_name = btn[5] if len(btn) > 5 else None
            button = self.create_button(
                button_text,
                button_width,
                button_callback,
                icon_path,
                tooltip,
                object_name,
            )
            layout.addWidget(button)
        layout.addStretch()
        return layout

    def create_horizontal_line(self) -> QFrame:
        """Create a horizontal line using QFrame."""
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        return line

    def create_button_with_layout(
        self,
        label_text: str,
        button_text: str,
        button_width: int,
        button_callback: Callable,
        icon_path: Optional[str] = None,
    ) -> QHBoxLayout:
        """Create a button within a QHBoxLayout with optional label and icon."""
        layout = QHBoxLayout()
        if label_text:
            layout.addWidget(QLabel(label_text))
        button = self.create_button(
            button_text, button_width, button_callback, icon_path
        )
        layout.addStretch()
        layout.addWidget(button)
        layout.addStretch()
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
        """Initialize a custom message box with a centered button."""
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setWindowIcon(QIcon("frontend/icons/encryption.png"))
        self.setMinimumSize(300, 150)
        layout = QVBoxLayout(self)

        # Icon and message
        message_layout = QHBoxLayout()
        icon_label = QLabel()
        icon_map = {
            QMessageBox.Warning: QStyle.SP_MessageBoxWarning,
            QMessageBox.Critical: QStyle.SP_MessageBoxCritical,
            QMessageBox.Question: QStyle.SP_MessageBoxQuestion,
            QMessageBox.Information: QStyle.SP_MessageBoxInformation,
        }
        standard_icon = icon_map.get(icon, QStyle.SP_MessageBoxInformation)
        icon_pixmap = self.style().standardIcon(standard_icon).pixmap(48, 48)
        icon_label.setPixmap(icon_pixmap)
        message_label = QLabel(message)
        message_label.setWordWrap(True)
        message_layout.addWidget(icon_label)
        message_layout.addWidget(message_label)
        layout.addLayout(message_layout)

        # Centered button
        layout.addStretch()
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        ok_button = QPushButton(button_text)
        ok_button.setFixedWidth(100)
        ok_button.clicked.connect(self.accept)
        button_layout.addWidget(ok_button)
        button_layout.addStretch()
        layout.addLayout(button_layout)

        # Set fixed size to prevent resizing issues
        self.setFixedSize(self.sizeHint())

        # Center the dialog
        self.center()

    def show_message(self):
        """Display the message box."""
        self.exec()

    def center(self):
        """Center the message box on the screen."""
        screen = QGuiApplication.primaryScreen()
        screen_geometry = screen.availableGeometry()
        x = (screen_geometry.width() - self.width()) // 2
        y = (screen_geometry.height() - self.height()) // 2
        self.move(x, y)
