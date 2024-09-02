import logging
import os
import sys

# Add the backend directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from blueprints import CustomMessageBox  # Import CustomMessageBox for consistency
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
        title_label = QLabel("Fortalice Secure Password Generator")
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
            msg_box = CustomMessageBox(
                title="Error",
                message=f"Failed to generate password: {e}",
                icon=QMessageBox.Critical,
            )
            msg_box.show_message()

    def copy_to_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.generated_password.text())

        msg_box = CustomMessageBox(
            title="Copied",
            message="Password copied to clipboard!",
            icon=QMessageBox.Information,
        )
        msg_box.show_message()
