import logging
import math
import random
import re

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from backend.password_generator import generate_password
from frontend.blueprints import CustomMessageBox, add_title_and_description

logger = logging.getLogger(__name__)


class PasswordGenerationTab(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        self.create_ui()

    def create_ui(self):
        add_title_and_description(
            self.layout,  # Pass the correct layout here
            "E.Z.P.Z. Secure Password Generator",
            "Passwords generated with 256 bits of entropy for absolute security.",
        )

        # Generate Button
        generate_btn = QPushButton("Generate Password")
        generate_btn.setFixedHeight(40)
        generate_btn.setStyleSheet("font-size: 16px;")
        generate_btn.setToolTip("Click to generate a totally secure password.")
        generate_btn.clicked.connect(self.generate)
        self.layout.addWidget(generate_btn)

        # Output Layout
        output_layout = QHBoxLayout()
        self.generated_output = QLineEdit()
        self.generated_output.setReadOnly(True)
        self.generated_output.setStyleSheet("font-size: 16px; padding: 5px;")
        output_layout.addWidget(self.generated_output)

        copy_btn = QPushButton("Copy")
        copy_btn.setFixedWidth(80)
        copy_btn.setStyleSheet("font-size: 14px;")
        copy_btn.setToolTip("Click to copy the generated password to the clipboard.")
        copy_btn.clicked.connect(self.copy_to_clipboard)
        output_layout.addWidget(copy_btn)

        self.layout.addLayout(output_layout)

        # Information Labels
        self.entropy_label = QLabel("Entropy: N/A")
        self.entropy_label.setAlignment(Qt.AlignCenter)
        self.entropy_label.setStyleSheet(
            "font-size: 14px; color: #00A36C; margin-top: 15px;"
        )
        self.layout.addWidget(self.entropy_label)

        self.brute_force_label = QLabel("Brute-Force Time: N/A")
        self.brute_force_label.setAlignment(Qt.AlignCenter)
        self.brute_force_label.setStyleSheet(
            "font-size: 14px; color: #00A36C; margin-top: 5px;"
        )
        self.layout.addWidget(self.brute_force_label)

        self.comparison_label = QLabel("Comparison: N/A")
        self.comparison_label.setAlignment(Qt.AlignCenter)
        self.comparison_label.setStyleSheet(
            "font-size: 14px; color: #00A36C; margin-top: 5px;"
        )
        self.layout.addWidget(self.comparison_label)

        self.layout.addStretch(1)

    def generate(self):
        try:
            # Define character set and calculate bits per character
            charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/~"
            bits_per_char = math.log2(len(charset))

            # Calculate required password length for at least 256 bits of entropy
            total_length = math.ceil(256 / bits_per_char) + random.randint(3, 7)
            password = generate_password(length=total_length, charset=charset)
            self.generated_output.setText(password)

            # Calculate entropy and brute-force time
            actual_entropy = total_length * bits_per_char
            brute_force_time_str = self.calculate_brute_force_time(actual_entropy)
            brute_force_ratio_text = self.calculate_brute_force_ratio(
                brute_force_time_str
            )

            # Update labels
            self.entropy_label.setText(f"Entropy: {actual_entropy:.2f} bits")
            self.brute_force_label.setText(
                f"At 100 billion guesses per second, it would take {brute_force_time_str} to crack this password."
            )
            self.comparison_label.setText(brute_force_ratio_text)

            logger.info(
                f"Generated password with {actual_entropy:.2f} bits of entropy, requiring {brute_force_time_str} to brute-force."
            )
        except Exception as e:
            logger.error(f"Failed to generate password: {e}")
            CustomMessageBox(
                "Error", f"Failed to generate password: {e}", QMessageBox.Critical
            ).show_message()

    def calculate_brute_force_time(
        self, entropy: float, guesses_per_second: float = 1e11
    ) -> str:
        """Calculate the time required to brute-force the password."""
        seconds = (2**entropy) / guesses_per_second
        years = seconds / (365.25 * 24 * 3600)
        if years >= 1e6:
            return f"{years/1e6:.2e} million years"
        elif years >= 1e3:
            return f"{years/1e3:.2e} thousand years"
        else:
            return f"{years:.2e} years"

    def calculate_brute_force_ratio(self, brute_force_time_str: str) -> str:
        """Calculate the ratio of brute-force time to the age of the universe."""
        match = re.match(r"([\d.eE+-]+)\s+(\w+)", brute_force_time_str)
        if match:
            time_value = float(match.group(1))
            unit = match.group(2)
            if unit.startswith("million"):
                brute_force_time_in_years = time_value * 1e6
            elif unit.startswith("thousand"):
                brute_force_time_in_years = time_value * 1e3
            else:
                brute_force_time_in_years = time_value
        else:
            brute_force_time_in_years = 0
            logger.warning("Failed to parse brute-force time string.")

        universe_age_years = 1.38e10  # 13.8 billion years
        if brute_force_time_in_years > 0:
            ratio = brute_force_time_in_years / universe_age_years
            return f"This is {ratio:.2e} times the age of the universe. The password is secure."
        else:
            return "Comparison: N/A"

    def copy_to_clipboard(self):
        if self.generated_output.text():
            QApplication.clipboard().setText(self.generated_output.text())
            CustomMessageBox(
                "Copied", "Password copied to clipboard!", QMessageBox.Information
            ).show_message()
        else:
            CustomMessageBox(
                "Error", "No password to copy!", QMessageBox.Warning
            ).show_message()
