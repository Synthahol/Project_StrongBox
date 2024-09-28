import logging

from PySide6.QtWidgets import (
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from backend.database import decrypt_data
from backend.password_health import (
    check_password_pwned,
    check_password_strength,
    get_password_feedback,
)
from frontend.blueprints import add_title_and_description, display_password_health_table

logger = logging.getLogger(__name__)


class PasswordHealthTab(QWidget):
    def __init__(self, conn, stacked_widget, parent=None):
        super().__init__(parent)
        self.conn = conn
        self.stacked_widget = stacked_widget
        self.init_ui()

    def init_ui(self):
        """Set up the UI for the password health tab."""
        main_layout = QVBoxLayout(self)  # Avoid name conflicts with 'layout()' method

        add_title_and_description(
            main_layout,
            "Fortalice Password Health Check",
            "Monitor the strength and compromise status of your passwords.",
        )

        # Label and input for manual password check
        self.password_input_label = QLabel("Enter Password to Check Health:")
        self.password_input_label.setObjectName("passwordHealthInputLabel")
        main_layout.addWidget(self.password_input_label)

        self.password_input = QLineEdit()
        self.password_input.setObjectName("passwordHealthInput")
        self.password_input.setPlaceholderText("Enter your password here")
        main_layout.addWidget(self.password_input)

        # Button to check password health manually
        self.check_health_button = QPushButton("Check Password Health")
        self.check_health_button.setObjectName("checkHealthButton")
        self.check_health_button.clicked.connect(self._check_password_health)
        main_layout.addWidget(self.check_health_button)

        # Button to check all passwords in the database
        self.check_all_passwords_button = QPushButton("Check All Passwords in Database")
        self.check_all_passwords_button.setObjectName("checkAllPasswordsButton")
        self.check_all_passwords_button.clicked.connect(
            self._check_all_passwords_in_database
        )
        main_layout.addWidget(self.check_all_passwords_button)

        # Stretch to push widgets to the top
        main_layout.addStretch()

    def _check_password_health(self):
        """Check the health of a single password entered by the user."""
        password = self.password_input.text().strip()
        if not password:
            QMessageBox.warning(self, "Error", "Please enter a password")
            return

        try:
            compromised_count = check_password_pwned(password)
            if compromised_count > 0:
                QMessageBox.information(
                    self,
                    "Password Health",
                    f"Password has been compromised {compromised_count} times.",
                )
            else:
                QMessageBox.information(
                    self, "Password Health", "Password is safe and not compromised."
                )
            logger.info(
                f"Password checked: {password}, Compromised count: {compromised_count}"
            )
        except Exception as e:
            logger.error(f"Error checking password health: {e}")
            QMessageBox.critical(
                self, "Error", "An error occurred while checking password health."
            )

    def _check_all_passwords_in_database(self):
        """Check all passwords in the database for compromise and strength."""
        passwords = self._fetch_passwords_from_database()

        if not passwords:
            QMessageBox.information(
                self, "No Passwords", "No passwords found in the database."
            )
            return

        password_health_data = []

        for password in passwords:
            compromised_count = check_password_pwned(password)
            is_compromised = compromised_count > 0
            is_strong, rules = check_password_strength(password)
            feedback = get_password_feedback(is_strong, rules)

            password_health_data.append(
                {
                    "password": password,
                    "compromised_count": compromised_count if is_compromised else 0,
                    "is_compromised": is_compromised,
                    "is_strong": is_strong,
                    "feedback": feedback,
                }
            )

        # Display the password health data using a dialog/table
        results_widget = display_password_health_table(
            password_health_data, parent=self
        )

        # Add and display the results in the stacked widget
        self.stacked_widget.addWidget(results_widget)
        self.stacked_widget.setCurrentWidget(results_widget)

    def _fetch_passwords_from_database(self):
        """Fetch and decrypt passwords from the database."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT password FROM passwords")

        encrypted_passwords = [row[0] for row in cursor.fetchall()]
        decrypted_passwords = []

        for encrypted_password in encrypted_passwords:
            try:
                decrypted = decrypt_data(encrypted_password)
                decrypted_passwords.append(decrypted)
            except Exception as e:
                logger.error(f"Failed to decrypt password: {e}")
                decrypted_passwords.append("Decryption Failed")

        if not decrypted_passwords:
            logger.info("No passwords found in the database.")

        return decrypted_passwords
