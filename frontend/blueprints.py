# blueprints.py

import os
from functools import partial
from typing import Callable, List, Optional, Tuple

from PySide6.QtCore import QSize
from PySide6.QtGui import QGuiApplication, QIcon
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QStyle,
    QTableWidget,
    QVBoxLayout,
    QWidget,
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


class PasswordHealthReportDialog(QDialog):
    def __init__(self, report_text, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Password Health Report")
        self.setMinimumSize(500, 400)  # You can adjust the size if needed

        # Create a layout for the dialog
        layout = QVBoxLayout()

        # Create a QScrollArea
        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)

        # Create a container for the scroll content
        scroll_content = QFrame()
        scroll_layout = QVBoxLayout(scroll_content)

        # Create QLabel for the report and add it to the scrollable content
        report_label = QLabel(report_text)
        report_label.setWordWrap(True)  # Ensure text wraps inside the label
        scroll_layout.addWidget(report_label)

        # Set the scroll content and add it to the scroll area
        scroll_area.setWidget(scroll_content)

        # Add the scroll area to the dialog layout
        layout.addWidget(scroll_area)

        # Set the main layout
        self.setLayout(layout)


def display_password_health_table(password_health_data, parent=None):
    """
    Create a scrollable table to display all passwords (whether compromised, weak, or strong),
    with columns: Password, Compromised, Health, Status Report.
    """
    # Create a table widget to display the results
    table_widget = QTableWidget()
    table_widget.setRowCount(len(password_health_data))
    table_widget.setColumnCount(4)
    table_widget.setHorizontalHeaderLabels(
        ["Password", "Compromised", "Health", "Status Report"]
    )

    # Load the icons (ensure paths are correct)
    safe_icon = QIcon("frontend/icons/safe.png")
    danger_icon = QIcon("frontend/icons/danger.png")

    # Helper function to toggle password visibility
    def toggle_password_visibility(button, password_input):
        if password_input.echoMode() == QLineEdit.Password:
            password_input.setEchoMode(QLineEdit.Normal)
            button.setText("Hide")
        else:
            password_input.setEchoMode(QLineEdit.Password)
            button.setText("Show")

    # Helper function to show the details popup with compromised count and feedback
    def show_status_report_dialog(password, compromised_count, feedback, parent=None):
        # Create a message box to show the details
        details_message = f"Password: {password}\n"
        details_message += (
            f"Compromised {compromised_count} times.\n"
            if compromised_count > 0
            else "Password has not been compromised.\n"
        )
        details_message += "\nFeedback:\n" + "\n".join(feedback)

        # Display the pop-up with feedback and compromised count
        QMessageBox.information(parent, "Password Details", details_message)

    # Populate the table with password health data
    for row, data in enumerate(password_health_data):
        password = data["password"]
        compromised_count = data["compromised_count"]
        is_compromised = data["is_compromised"]
        is_strong = data["is_strong"]
        feedback = data["feedback"]

        # Password column with hidden password and "Show" button
        password_input = QLineEdit(password)
        password_input.setEchoMode(QLineEdit.Password)  # Initially hidden

        show_button = QPushButton("Show")
        show_button.setStyleSheet("padding: 5px; margin-left: 5px;")  # Adjust spacing

        # Use `partial` to ensure each button references its own password_input field
        show_button.clicked.connect(
            partial(toggle_password_visibility, show_button, password_input)
        )

        # Create a layout to hold the password and the button side by side
        password_layout = QWidget()
        layout = QHBoxLayout(password_layout)
        layout.addWidget(password_input)
        layout.addWidget(show_button)
        layout.setContentsMargins(
            0, 0, 0, 0
        )  # Remove margins around the layout to fit in the cell
        layout.setSpacing(0)

        table_widget.setCellWidget(row, 0, password_layout)

        # Compromised column: display safe or danger icon based on whether the password is compromised
        compromised_icon_widget = QLabel()
        if is_compromised:
            compromised_icon_widget.setPixmap(
                danger_icon.pixmap(24, 24)
            )  # Show danger icon
        else:
            compromised_icon_widget.setPixmap(
                safe_icon.pixmap(24, 24)
            )  # Show safe icon
        table_widget.setCellWidget(row, 1, compromised_icon_widget)

        # Health column: display safe or danger icon based on password strength
        health_icon_widget = QLabel()
        if is_strong:
            health_icon_widget.setPixmap(
                safe_icon.pixmap(24, 24)
            )  # Show safe icon if password is strong
        else:
            health_icon_widget.setPixmap(
                danger_icon.pixmap(24, 24)
            )  # Show danger icon if password is weak
        table_widget.setCellWidget(row, 2, health_icon_widget)

        # Status Report column with a button to show detailed feedback
        report_button = QPushButton("Details")
        report_button.setStyleSheet("padding: 5px; margin: 5px;")  # Add spacing
        report_button.clicked.connect(
            partial(
                show_status_report_dialog, password, compromised_count, feedback, parent
            )
        )
        table_widget.setCellWidget(row, 3, report_button)

        # Set row height to accommodate buttons and icons plus spacing
        table_widget.setRowHeight(
            row, 50
        )  # Adjust this value as needed to prevent overlap

    # Set the header view to stretch to fill the table width
    header = table_widget.horizontalHeader()

    # Set fixed widths for the Compromised and Health columns (e.g., 100px each)
    header.setSectionResizeMode(
        0, QHeaderView.Stretch
    )  # Password column stretches to fill remaining space
    header.setSectionResizeMode(1, QHeaderView.Fixed)  # Compromised column fixed width
    header.setSectionResizeMode(2, QHeaderView.Fixed)  # Health column fixed width
    header.setSectionResizeMode(3, QHeaderView.Fixed)  # Status report button fixed size

    # Set the width for Compromised and Health columns (adjust as necessary)
    table_widget.setColumnWidth(1, 100)  # Compromised column width
    table_widget.setColumnWidth(2, 100)  # Health column width
    table_widget.setColumnWidth(3, 120)  # Status Report column width

    # Create a scrollable area for the table
    scroll_area = QScrollArea()
    scroll_area.setWidget(table_widget)
    scroll_area.setWidgetResizable(True)

    # Create a layout to hold the scroll area
    layout = QVBoxLayout()
    layout.addWidget(scroll_area)

    # Create a QWidget to hold the layout
    results_widget = QWidget()
    results_widget.setLayout(layout)

    return results_widget


def toggle_password_visibility(button, password):
    """
    Toggle the visibility of the password.
    """
    if button.text() == "Show":
        button.setText(password)
    else:
        button.setText("Show")


def show_status_report_dialog(password, data, parent=None):
    """
    Show a dialog that provides a detailed status report for the password.

    :param password: The password being reviewed.
    :param data: A dictionary containing the status of the password (compromised and health).
    :param parent: The parent window or widget.
    """
    dialog = QDialog(parent)
    dialog.setWindowTitle("Password Status Report")

    compromised_status = (
        f"Compromised {data['compromised_count']} times."
        if data["compromised"]
        else "Not compromised."
    )
    health_status = (
        "Password meets all health requirements."
        if data["health"]
        else f"Weaknesses: {' '.join(data['feedback'])}"
    )

    # Create labels for displaying password status
    compromised_label = QLabel(
        f"Password: {password}\nCompromise Status: {compromised_status}"
    )
    health_label = QLabel(f"Health Status: {health_status}")

    # Create the layout for the dialog
    layout = QVBoxLayout()
    layout.addWidget(compromised_label)
    layout.addWidget(health_label)

    # Add OK button to close the dialog
    ok_button = QPushButton("OK")
    ok_button.clicked.connect(dialog.accept)
    layout.addWidget(ok_button)

    dialog.setLayout(layout)
    dialog.exec()
