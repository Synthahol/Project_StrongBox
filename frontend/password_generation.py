import logging
import os
import sys

# Add the backend directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QVBoxLayout,
    QWidget,
)

from backend.password_generator import generate_password

logger = logging.getLogger(__name__)


class PasswordGenerationTab(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        self.create_ui()

    def create_ui(self):
        # Add the title at the top
        title_label = QLabel("StrongBox Secure Password Generator")
        title_label.setStyleSheet(
            "font-size: 30px; font-weight: bold; margin-bottom: 15px;"
        )
        title_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(title_label)

        # Add some space between the title and the content
        self.layout.addSpacerItem(
            QSpacerItem(20, 10, QSizePolicy.Minimum, QSizePolicy.Fixed)
        )

        # Create the layout for the strength selection and button
        strength_layout = QHBoxLayout()
        self.layout.addLayout(strength_layout)

        self.strength_label = QLabel("Select Strength:")
        strength_layout.addWidget(self.strength_label)

        self.strength_combo = QComboBox()
        self.strength_combo.addItems(
            ["1 (16-28 chars)", "2 (29-42 chars)", "3 (43-60 chars)"]
        )
        strength_layout.addWidget(self.strength_combo)

        self.generate_btn = QPushButton("Generate Password")
        self.generate_btn.clicked.connect(self.generate_password)
        strength_layout.addWidget(self.generate_btn)

        # Add the generated password display
        password_layout = QHBoxLayout()
        self.generated_password = QLineEdit()
        self.generated_password.setReadOnly(True)
        password_layout.addWidget(self.generated_password)

        self.copy_btn = QPushButton("Copy Password")
        self.copy_btn.clicked.connect(self.copy_to_clipboard)
        password_layout.addWidget(self.copy_btn)

        self.layout.addLayout(password_layout)

        self.layout.addStretch(1)

    def generate_password(self):
        try:
            strength = self.strength_combo.currentIndex() + 1
            password = generate_password(strength)
            self.generated_password.setText(password)
            logger.info(f"Generated password with strength {strength}.")
        except Exception as e:
            logger.error(f"Failed to generate password: {e}")
            QMessageBox.critical(self, "Error", f"Failed to generate password: {e}")

    def copy_to_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.generated_password.text())

        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Information)
        msg_box.setText("Password copied to clipboard!")
        msg_box.setWindowTitle("Copied")
        msg_box.setStandardButtons(QMessageBox.Ok)

        # Access the "OK" button directly
        ok_button = msg_box.button(QMessageBox.Ok)

        # Set the minimum width for the "OK" button
        ok_button.setMinimumWidth(100)  # Optional: Adjust the button width as needed

        # Create a new horizontal layout for centering the button
        centered_layout = QHBoxLayout()
        centered_layout.addStretch(1)  # Add stretchable space to the left
        centered_layout.addWidget(ok_button)  # Add the OK button
        centered_layout.addStretch(1)  # Add stretchable space to the right

        # Access the layout of the QMessageBox
        layout = msg_box.layout()

        # Replace the original layout's button box with the centered layout
        layout.addLayout(centered_layout, layout.rowCount(), 0, 1, layout.columnCount())

        # Show the message box
        msg_box.exec()
