import logging
import math

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSlider,
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
            self.layout,
            "E.Z.P.Z. Secure Password Generator",
            "Passwords generated with maximum entropy for security.",
        )

        # Exclude Characters
        exclusion_layout = QHBoxLayout()

        exclude_label = QLabel("Optional Character Exclusion:")
        exclude_label.setStyleSheet("font-size: 14px;")
        exclusion_layout.addWidget(exclude_label)

        self.exclude_input = QLineEdit()
        self.exclude_input.setPlaceholderText("Example: $/#%")
        self.exclude_input.setStyleSheet("font-size: 14px; padding: 5px;")
        self.exclude_input.setToolTip(
            "Enter characters you want to exclude from the password. For example, to exclude characters like '$', '/', '#','%', enter $/#% then click generate password."
        )
        exclusion_layout.addWidget(self.exclude_input)

        self.layout.addLayout(exclusion_layout)
        # **End of Exclusion Section**

        # *** New Section: Password Length Slider ***
        slider_layout = QHBoxLayout()

        slider_label = QLabel("Password Length:")
        slider_label.setStyleSheet("font-size: 14px;")
        slider_layout.addWidget(slider_label)

        self.length_slider = QSlider(Qt.Horizontal)
        self.length_slider.setRange(12, 128)  # Set reasonable range
        self.length_slider.setValue(16)  # Default value
        self.length_slider.setTickInterval(8)
        self.length_slider.setTickPosition(QSlider.TicksBelow)
        self.length_slider.setStyleSheet("padding: 5px;")
        self.length_slider.setToolTip("Slide to select the desired password length.")
        self.length_slider.valueChanged.connect(self.update_slider_label)
        slider_layout.addWidget(self.length_slider)

        self.length_display = QLabel("16")
        self.length_display.setStyleSheet("font-size: 14px; margin-left: 10px;")
        slider_layout.addWidget(self.length_display)

        self.layout.addLayout(slider_layout)
        # *** End of New Section ***

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

        self.layout.addStretch(1)

    def update_slider_label(self, value):
        """Update the label next to the slider to show the current value."""
        self.length_display.setText(str(value))

    def generate(self):
        try:
            # Define the default character set
            default_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/~"

            # Get excluded characters from user input
            excluded_chars = self.exclude_input.text()
            if excluded_chars:
                # Remove excluded characters from the charset
                charset = "".join(
                    [c for c in default_charset if c not in excluded_chars]
                )
            else:
                charset = default_charset

            if not charset:
                raise ValueError(
                    "Character set is empty. Please adjust your exclusions."
                )

            bits_per_char = math.log2(len(charset))

            # Get password length from slider
            total_length = self.length_slider.value()

            password = generate_password(length=total_length, charset=charset)
            self.generated_output.setText(password)

            # Calculate entropy and brute-force time
            actual_entropy = total_length * bits_per_char
            brute_force_time_str = self.calculate_brute_force_time(actual_entropy)

            # Update labels
            self.entropy_label.setText(f"Entropy: {actual_entropy:.2f} bits")
            self.brute_force_label.setText(
                f"At 100 billion guesses per second, it would take {brute_force_time_str} to crack this password."
            )

            logger.info(
                f"Generated password with {actual_entropy:.2f} bits of entropy, requiring {brute_force_time_str} to brute-force."
            )
        except ValueError as ve:
            logger.warning(f"Password generation issue: {ve}")
            CustomMessageBox(
                "Invalid Input", str(ve), QMessageBox.Warning
            ).show_message()
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
