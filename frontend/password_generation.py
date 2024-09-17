import logging
import os
import secrets
import sys

# Add the backend directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,  # Added QComboBox
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from backend.password_generator import (  # Imported generate_hybrid
    generate_hybrid,
    generate_passphrase,
    generate_password,
)
from frontend.blueprints import (
    CustomMessageBox,  # Import CustomMessageBox for consistency
)

logger = logging.getLogger(__name__)


class PasswordGenerationTab(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        self.create_ui()

    def create_ui(self):
        # Add the title at the top
        title_label = QLabel("Fortalice Secure Generator")
        title_label.setStyleSheet(
            "font-size: 30px; font-weight: bold; margin-bottom: 15px;"
        )
        title_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(title_label)

        # Add some space between the title and the content
        self.layout.addSpacing(10)

        # Create the layout for the type selection and generate button
        type_layout = QHBoxLayout()
        self.layout.addLayout(type_layout)

        type_label = QLabel("Generate:")
        type_layout.addWidget(type_label)

        self.type_combo = QComboBox()
        self.type_combo.addItems(
            ["Password", "Passphrase", "Hybrid"]
        )  # Added "Hybrid" option
        type_layout.addWidget(self.type_combo)

        self.generate_btn = QPushButton("Generate")
        self.generate_btn.clicked.connect(self.generate)
        type_layout.addWidget(self.generate_btn)

        # Add the generated output display
        output_layout = QHBoxLayout()
        self.generated_output = QLineEdit()
        self.generated_output.setReadOnly(True)
        output_layout.addWidget(self.generated_output)

        self.copy_btn = QPushButton("Copy")
        self.copy_btn.clicked.connect(self.copy_to_clipboard)
        output_layout.addWidget(self.copy_btn)

        self.layout.addLayout(output_layout)

        # Add a label indicating the security level
        self.entropy_label = QLabel()
        self.entropy_label.setAlignment(Qt.AlignCenter)
        self.entropy_label.setStyleSheet(
            "font-size: 14px; color: #00A36C; margin-top: 10px;"
        )
        self.layout.addWidget(self.entropy_label)

        self.layout.addStretch(1)

    def generate(self):
        try:
            selected_type = self.type_combo.currentText()
            if selected_type == "Password":
                result = generate_password()
                self.generated_output.setText(result)
                self.entropy_label.setText(
                    "This password has at least 256 bits of entropy."
                )
                logger.info("Generated password with at least 256 bits of entropy.")
            elif selected_type == "Passphrase":
                # You can choose a different separator or make it random
                separator = secrets.choice("!@#$%^&*()-_=+[]{}|;:,.<>?/~")
                result = generate_passphrase(separator=separator)
                self.generated_output.setText(result)
                self.entropy_label.setText(
                    f"This passphrase has at least 256 bits of entropy using Diceware with '{separator}' as separators."
                )
                logger.info(
                    f"Generated passphrase with at least 256 bits of entropy using Diceware with '{separator}' as separators."
                )
            elif selected_type == "Hybrid":
                result = generate_hybrid()
                self.generated_output.setText(result)
                self.entropy_label.setText(
                    "This hybrid passphrase has at least 256 bits of entropy."
                )
                logger.info(
                    "Generated hybrid passphrase with at least 256 bits of entropy."
                )
            else:
                raise ValueError("Unknown selection.")
        except Exception as e:
            logger.error(f"Failed to generate {selected_type.lower()}: {e}")
            msg_box = CustomMessageBox(
                title="Error",
                message=f"Failed to generate {selected_type.lower()}: {e}",
                icon=QMessageBox.Critical,
            )
            msg_box.show_message()

    def copy_to_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.generated_output.text())

        msg_box = CustomMessageBox(
            title="Copied",
            message=f"{self.type_combo.currentText()} copied to clipboard!",
            icon=QMessageBox.Information,
        )
        msg_box.show_message()
