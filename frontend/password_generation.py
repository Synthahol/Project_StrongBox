# password_generation_tab.py

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
from frontend.blueprints import CustomMessageBox

logger = logging.getLogger(__name__)


class PasswordGenerationTab(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        self.create_ui()

    def create_ui(self):
        # Add the title at the top
        title_label = QLabel("E.Z.P.Z. Secure Password Generator")
        title_label.setStyleSheet(
            "font-size: 30px; font-weight: bold; margin-bottom: 20px;"
        )
        title_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(title_label)

        # Password Length Information (Optional: Inform users about the dynamic length)
        info_label = QLabel(
            "Each generated password will have a minimum of 256 bits of entropy for absolute security."
        )
        info_label.setWordWrap(True)
        info_label.setStyleSheet(
            "font-size: 14px; color: #555555; margin-bottom: 15px;"
        )
        info_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(info_label)

        # Generate Button
        self.generate_btn = QPushButton("Generate Password")
        self.generate_btn.setFixedHeight(40)
        self.generate_btn.setStyleSheet("font-size: 16px;")
        self.generate_btn.setToolTip(
            "Click to generate a secure password with at least 256 bits of entropy plus additional characters."
        )
        self.generate_btn.clicked.connect(self.generate)
        self.layout.addWidget(self.generate_btn)

        # Generated Password Display and Copy Button
        output_layout = QHBoxLayout()
        self.generated_output = QLineEdit()
        self.generated_output.setReadOnly(True)
        self.generated_output.setStyleSheet("font-size: 16px; padding: 5px;")
        output_layout.addWidget(self.generated_output)

        self.copy_btn = QPushButton("Copy")
        self.copy_btn.setFixedWidth(80)
        self.copy_btn.setStyleSheet("font-size: 14px;")
        self.copy_btn.setToolTip(
            "Click to copy the generated password to the clipboard."
        )
        self.copy_btn.clicked.connect(self.copy_to_clipboard)
        output_layout.addWidget(self.copy_btn)

        self.layout.addLayout(output_layout)

        # Entropy Information
        self.entropy_label = QLabel("Entropy: N/A")
        self.entropy_label.setAlignment(Qt.AlignCenter)
        self.entropy_label.setStyleSheet(
            "font-size: 14px; color: #00A36C; margin-top: 15px;"
        )
        self.layout.addWidget(self.entropy_label)

        # Brute-Force Time Information
        self.brute_force_label = QLabel("Brute-Force Time: N/A")
        self.brute_force_label.setAlignment(Qt.AlignCenter)
        self.brute_force_label.setStyleSheet(
            "font-size: 14px; color: #00A36C; margin-top: 5px;"
        )
        self.layout.addWidget(self.brute_force_label)

        # Comparison to Universe Lifespan
        self.comparison_label = QLabel("Comparison: N/A")
        self.comparison_label.setAlignment(Qt.AlignCenter)
        self.comparison_label.setStyleSheet(
            "font-size: 14px; color: #00A36C; margin-top: 5px;"
        )
        self.layout.addWidget(self.comparison_label)

        self.layout.addStretch(1)

    def calculate_entropy(self, length: int, charset_size: int) -> float:
        """
        Calculate the entropy of the password.

        Args:
            length (int): Length of the password.
            charset_size (int): Number of unique characters in the charset.

        Returns:
            float: Entropy in bits.
        """
        if charset_size <= 1:
            return 0.0
        return length * math.log2(charset_size)

    def calculate_brute_force_time(
        self, entropy: float, guesses_per_second: float = 1e11
    ) -> str:
        """
        Calculate the time required to brute-force the password.

        Args:
            entropy (float): Entropy in bits.
            guesses_per_second (float, optional): Number of guesses per second. Defaults to 1e11.

        Returns:
            str: Time required in a human-readable format.
        """
        # Total number of guesses needed (on average)
        total_guesses = 2**entropy
        # Time in seconds
        seconds = total_guesses / guesses_per_second

        # Convert seconds to more readable units
        minutes = seconds / 60
        hours = minutes / 60
        days = hours / 24
        years = days / 365.25

        if years >= 1e6:
            millennia = years / 1000
            return f"{millennia:.2e} millennia"
        elif years >= 100:
            centuries = years / 100
            return f"{centuries:.2e} centuries"
        else:
            return f"{years:.2e} years"

    def generate(self):
        try:
            # Define the character set (94 printable ASCII characters)
            charset = (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789"
                "!@#$%^&*()-_=+[]{}|;:,.<>?/~"
            )
            charset_size = len(charset)
            bits_per_char = math.log2(charset_size)

            # Calculate the required password length for at least 256 bits of entropy
            required_entropy = 256
            min_length = math.ceil(required_entropy / bits_per_char)

            # Define the number of additional characters to add
            additional_length = random.randint(
                3, 7
            )  # Adds between 3 to 7 extra characters
            total_length = min_length + additional_length

            logger.debug(
                f"Generating password with min_length={min_length}, additional_length={additional_length}, total_length={total_length}"
            )

            # Generate the password with the specified total length and charset
            password = generate_password(length=total_length, charset=charset)
            self.generated_output.setText(password)

            # Calculate actual entropy using the separate function
            actual_entropy = self.calculate_entropy(len(password), charset_size)

            # Calculate brute-force time using the separate function
            brute_force_time_str = self.calculate_brute_force_time(actual_entropy)

            # Extract the numerical value and unit from brute_force_time_str
            match = re.match(r"([\d.eE+-]+)\s+(\w+)", brute_force_time_str)
            if match:
                time_value = float(match.group(1))
                unit = match.group(2)

                # Convert all units to years for the ratio
                if unit.startswith("millennia"):
                    brute_force_time_in_years = time_value * 1000
                elif unit.startswith("centuries"):
                    brute_force_time_in_years = time_value * 100
                elif unit.startswith("years"):
                    brute_force_time_in_years = time_value
                else:
                    brute_force_time_in_years = time_value  # Default to years
            else:
                brute_force_time_in_years = 0
                logger.warning("Failed to parse brute-force time string.")

            # Calculate the ratio to the lifespan of the universe from the big bang until now
            universe_age_years = 1.38e10  # 13.8 billion years
            if universe_age_years > 0:
                brute_force_ratio = brute_force_time_in_years / universe_age_years
                brute_force_ratio_text = f"For context, the time for a super computer to crack this password is equivalent to {brute_force_ratio:.2e} times the amount of time from the Big Bang to right now. This password is definitely secure."
            else:
                brute_force_ratio_text = "Comparison: N/A"
                logger.warning("Universe age is zero or undefined.")

            # Format entropy and time
            entropy_text = f"Entropy: {actual_entropy:.2f} bits"
            brute_force_time_text = f"At 100 billion guesses per second, (yes you read that correctly), the time it would take to crack this password is {brute_force_time_str}. That's a very long time."
            comparison_text = brute_force_ratio_text

            # Update the info labels with all information
            self.entropy_label.setText(entropy_text)
            self.brute_force_label.setText(brute_force_time_text)
            self.comparison_label.setText(comparison_text)

            logger.info(
                f"Generated password with {actual_entropy:.2f} bits of entropy, requiring {brute_force_time_str} "
                f"to brute-force at 1e11 guesses/sec, which is {brute_force_ratio:.2e} times the lifespan of the universe."
            )
        except ValueError as ve:
            logger.error(f"ValueError during password generation: {ve}")
            msg_box = CustomMessageBox(
                title="Error",
                message=str(ve),
                icon=QMessageBox.Critical,
            )
            msg_box.show_message()
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
        clipboard.setText(self.generated_output.text())

        msg_box = CustomMessageBox(
            title="Copied",
            message="Password copied to clipboard!",
            icon=QMessageBox.Information,
        )
        msg_box.show_message()
