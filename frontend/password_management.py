import hashlib
import logging

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from backend.database import (
    check_existing_entry,
    get_all_passwords,
    retrieve_password,
    store_password,
)

logger = logging.getLogger(__name__)


class PasswordManagementTab(QWidget):
    def __init__(self, conn, cipher_suite):
        super().__init__()
        self.conn = conn
        self.cipher_suite = cipher_suite
        self.layout = QVBoxLayout(self)
        self.create_ui()

    def create_ui(self):
        # Add title and styling for better UI
        title_label = QLabel("StrongBox Password Manager")
        title_label.setStyleSheet(
            "font-size: 20px; font-weight: bold; margin-bottom: 15px;"
        )
        self.layout.addWidget(title_label)

        self.layout.addWidget(self.create_horizontal_line())

        # Create input fields
        self.service_input = self.create_input(
            "Service:", "Enter or copy/paste service name"
        )
        self.username_input = self.create_input("Username:", "Enter username")
        self.password_input = self.create_input(
            "Password:", "Enter password", QLineEdit.Password
        )

        # Create buttons
        btn_layout = QHBoxLayout()
        self.layout.addLayout(btn_layout)
        self.store_btn = self.create_button(
            "Store Password", "icons/store.png", self.store_password
        )
        btn_layout.addWidget(self.store_btn)
        self.retrieve_btn = self.create_button(
            "Retrieve Password", "icons/retrieve.png", self.verify_and_retrieve_password
        )
        btn_layout.addWidget(self.retrieve_btn)

        self.layout.addWidget(self.create_horizontal_line())

        # Create table for displaying stored passwords
        self.layout.addWidget(QLabel("Stored Passwords"))
        self.password_table = self.create_password_table()
        self.layout.addWidget(self.password_table)

        self.load_passwords()

    def create_input(self, label_text, placeholder, echo_mode=QLineEdit.Normal):
        label = QLabel(label_text)
        self.layout.addWidget(label)
        input_field = QLineEdit()
        input_field.setPlaceholderText(placeholder)
        input_field.setEchoMode(echo_mode)
        self.layout.addWidget(input_field)
        return input_field

    def create_button(self, text, icon_path, callback):
        button = QPushButton(text)
        button.setIcon(QIcon(icon_path))
        button.setStyleSheet("padding: 5px 10px; font-size: 14px;")
        button.clicked.connect(callback)
        return button

    def create_password_table(self):
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["Service", "Username", "Password", "Action"])
        table.setStyleSheet("font-size: 12px;")
        return table

    def create_horizontal_line(self):
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        return line

    def load_passwords(self):
        self.password_table.setRowCount(0)
        passwords = get_all_passwords(self.conn)
        for row_num, (service, username, encrypted_password) in enumerate(passwords):
            self.password_table.insertRow(row_num)
            self.password_table.setItem(row_num, 0, QTableWidgetItem(service))
            self.password_table.setItem(row_num, 1, QTableWidgetItem(username))

            password = self.cipher_suite.decrypt(encrypted_password.encode()).decode()
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            self.password_table.setItem(row_num, 2, QTableWidgetItem(hashed_password))

            show_btn = self.create_button(
                "Show", "", lambda ch, r=row_num: self.show_password(r)
            )
            self.password_table.setCellWidget(row_num, 3, show_btn)

    def show_password(self, row):
        # Access the main window, which should be an instance of PasswordManager
        main_window = self.window()

        # Ensure the master password is verified before showing the password
        if not main_window.verify_master_password():
            logger.debug("Master password verification failed.")
            return  # Exit if the master password verification fails

        service = self.password_table.item(row, 0).text()
        logger.debug(f"Service selected: {service}")

        try:
            # Retrieve the username and encrypted password for the selected service
            username, encrypted_password = retrieve_password(
                self.conn, service, self.cipher_suite
            )
            logger.debug(
                f"Retrieved Username: {username}, Encrypted Password: {encrypted_password}"
            )

            if username and encrypted_password:
                # Decrypt the password using the cipher suite
                decrypted_password = self.cipher_suite.decrypt(
                    encrypted_password.encode()
                ).decode()
                logger.debug(f"Decrypted Password: {decrypted_password}")

                # Display the decrypted password in a message box
                QMessageBox.information(
                    self,
                    "Password Details",
                    f"Service: {service}\nUsername: {username}\nPassword: {decrypted_password}",
                )
            else:
                logger.warning("Failed to retrieve password details.")
                QMessageBox.warning(
                    self, "Error", "Failed to retrieve password details."
                )
        except Exception as e:
            logger.error(f"Error during password retrieval: {e}")
            QMessageBox.critical(self, "Error", f"Failed to retrieve password: {e}")

    def store_password(self):
        service = self.service_input.text()
        username = self.username_input.text()
        password = self.password_input.text()

        if not service or not username or not password:
            self.show_warning("All fields are required to store a password.")
            return

        if not check_existing_entry(self.conn, service, username):
            if self.confirm_action(
                f"Do you want to add the service: {service}, username: {username}, password: {password} to StrongBox?"
            ):
                self.execute_store_password(service, username, password)
        else:
            self.show_info(f"Password for service: {service} already exists.")

    def execute_store_password(self, service, username, password):
        try:
            store_password(self.conn, service, username, password, self.cipher_suite)
            logger.info(
                f"Stored password for service: {service}, username: {username}."
            )
            self.show_info(f"Password for {service} stored successfully!")
            self.load_passwords()
        except Exception as e:
            logger.error(f"Failed to store password: {e}")
            QMessageBox.critical(self, "Error", f"Failed to store password: {e}")

    def verify_and_retrieve_password(self):
        service = self.service_input.text()

        if not service:
            self.show_warning("Service field is required to retrieve a password.")
            return

        password, ok = QInputDialog.getText(
            self,
            "Master Password",
            "Enter master password to retrieve the service password:",
            QLineEdit.Password,
        )
        if ok and password:
            from backend.database import verify_master_password

            if verify_master_password(self.conn, password):
                self.retrieve_password(service)
                logger.info(
                    f"Master password verified for retrieving service: {service}."
                )
            else:
                self.show_warning("Incorrect master password. Please try again.")
        else:
            self.show_warning(
                "Master password is required to retrieve the service password."
            )

    def retrieve_password(self, service):
        try:
            username, encrypted_password = retrieve_password(
                self.conn, service, self.cipher_suite
            )
            if username and encrypted_password:
                password = self.cipher_suite.decrypt(
                    encrypted_password.encode()
                ).decode()
                self.show_info(f"Username: {username}\nPassword: {password}")
            else:
                self.show_info(f"No password found for {service}.")
        except Exception as e:
            logger.error(f"Failed to retrieve password: {e}")
            QMessageBox.critical(self, "Error", f"Failed to retrieve password: {e}")

    def show_info(self, message):
        QMessageBox.information(self, "Info", message)

    def show_warning(self, message):
        QMessageBox.warning(self, "Warning", message)

    def confirm_action(self, message):
        return (
            QMessageBox.question(
                self,
                "Add Entry",
                message,
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            == QMessageBox.Yes
        )


class UsernameSelectionDialog(QDialog):
    def __init__(self, usernames):
        super().__init__()
        self.setWindowTitle("Select Username")
        self.selected_username = None

        layout = QVBoxLayout()
        self.list_widget = QListWidget()
        self.list_widget.addItems(usernames)
        layout.addWidget(self.list_widget)

        select_button = QPushButton("Select")
        select_button.clicked.connect(self.select_username)
        layout.addWidget(select_button)

        self.setLayout(layout)

    def select_username(self):
        selected_items = self.list_widget.selectedItems()
        if selected_items:
            self.selected_username = selected_items[0].text()
            self.accept()
        else:
            QMessageBox.warning(self, "Selection Error", "Please select a username.")
