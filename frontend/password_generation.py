import logging
import os
import sys

# Add the backend directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.password_generator import generate_password
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

logger = logging.getLogger(__name__)


class PasswordGenerationTab(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        self.create_ui()

    def create_ui(self):
        self.layout.addWidget(QLabel("Password Generator"))

        strength_layout = QHBoxLayout()
        self.layout.addLayout(strength_layout)

        self.strength_label = QLabel("Select Strength:")
        strength_layout.addWidget(self.strength_label)

        self.strength_combo = QComboBox()
        self.strength_combo.addItems(
            ["1 (12-24 chars)", "2 (25-37 chars)", "3 (38-50 chars)"]
        )
        strength_layout.addWidget(self.strength_combo)

        self.generate_btn = QPushButton("Generate Password")
        self.generate_btn.clicked.connect(self.generate_password)
        strength_layout.addWidget(self.generate_btn)

        self.generated_password = QLineEdit()
        self.generated_password.setReadOnly(True)
        self.layout.addWidget(self.generated_password)

    def generate_password(self):
        try:
            strength = self.strength_combo.currentIndex() + 1
            password = generate_password(strength)
            self.generated_password.setText(password)
            logger.info(f"Generated password with strength {strength}.")
        except Exception as e:
            logger.error(f"Failed to generate password: {e}")
            QMessageBox.critical(self, "Error", f"Failed to generate password: {e}")
