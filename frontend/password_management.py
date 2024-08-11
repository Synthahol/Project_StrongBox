import hashlib
import logging
import os
import sys

# Add the backend directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
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
        self.cipher_suite = cipher_suite  # Store the cipher suite
        self.layout = QVBoxLayout(self)
        self.create_ui()

    def create_ui(self):
        self.layout.addWidget(QLabel("Password Storage"))

        self.service_label = QLabel("Service:(Website, Application, etc)")
        self.layout.addWidget(self.service_label)

        self.service_input = QLineEdit()
        self.service_input.setPlaceholderText("Enter or copy/paste service name")
        self.layout.addWidget(self.service_input)

        self.username_label = QLabel("Username:")
        self.layout.addWidget(self.username_label)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username")
        self.layout.addWidget(self.username_input)

        self.password_label = QLabel("Password:")
        self.layout.addWidget(self.password_label)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.layout.addWidget(self.password_input)

        btn_layout = QHBoxLayout()
        self.layout.addLayout(btn_layout)

        self.store_btn = QPushButton("Store Password")
        self.store_btn.setIcon(QIcon("icons/store.png"))
        self.store_btn.clicked.connect(self.store_password)
        btn_layout.addWidget(self.store_btn)

        self.retrieve_btn = QPushButton("Retrieve Password")
        self.retrieve_btn.setIcon(QIcon("icons/retrieve.png"))
        self.retrieve_btn.clicked.connect(self.verify_and_retrieve_password)
        btn_layout.addWidget(self.retrieve_btn)

        self.layout.addWidget(QLabel("Stored Passwords"))

        self.password_table = QTableWidget()
        self.password_table.setColumnCount(4)
        self.password_table.setHorizontalHeaderLabels(
            ["Service", "Username", "Password", "Action"]
        )
        self.layout.addWidget(self.password_table)

        self.load_passwords()

    def load_passwords(self):
        self.password_table.setRowCount(0)
        passwords = get_all_passwords(self.conn)
        for row_num, (service, username, encrypted_password) in enumerate(passwords):
            self.password_table.insertRow(row_num)
            self.password_table.setItem(row_num, 0, QTableWidgetItem(service))
            self.password_table.setItem(row_num, 1, QTableWidgetItem(username))

            # Decrypt the password using cipher_suite before displaying it
            password = self.cipher_suite.decrypt(encrypted_password.encode()).decode()
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            self.password_table.setItem(row_num, 2, QTableWidgetItem(hashed_password))

            show_btn = QPushButton("Show")
            show_btn.clicked.connect(lambda ch, r=row_num: self.show_password(r))
            self.password_table.setCellWidget(row_num, 3, show_btn)

    def show_password(self, row):
        service = self.password_table.item(row, 0).text()
        username, encrypted_password = retrieve_password(
            self.conn, service, self.cipher_suite
        )

        # Decrypt the password before showing it
        if username and encrypted_password:
            password = self.cipher_suite.decrypt(encrypted_password.encode()).decode()
            QMessageBox.information(
                self,
                "Password Details",
                f"Service: {service}\nUsername: {username}\nPassword: {password}",
            )
        else:
            QMessageBox.warning(self, "Error", "Failed to retrieve password details.")

    def store_password(self):
        service = self.service_input.text()
        username = self.username_input.text()
        password = self.password_input.text()

        if not service or not username or not password:
            logger.warning("All fields are required to store a password.")
            QMessageBox.warning(self, "Error", "All fields are required.")
            return

        try:
            if not check_existing_entry(self.conn, service, username):
                reply = QMessageBox.question(
                    self,
                    "Add Entry",
                    f"Do you want to add the service: {service}, username: {username}, password: {password} to StrongBox?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No,
                )

                if reply == QMessageBox.Yes:
                    # Pass the plain password and cipher_suite to the database function
                    store_password(
                        self.conn, service, username, password, self.cipher_suite
                    )
                    logger.info(
                        f"Stored password for service: {service}, username: {username}."
                    )
                    QMessageBox.information(
                        self, "Stored", f"Password for {service} stored successfully!"
                    )
                    self.load_passwords()
            else:
                logger.info(f"Password for service: {service} already exists.")
                QMessageBox.information(
                    self, "Exists", f"Password for {service} already exists."
                )
        except Exception as e:
            logger.error(f"Failed to store password: {e}")
            QMessageBox.critical(self, "Error", f"Failed to store password: {e}")

    def verify_and_retrieve_password(self):
        service = self.service_input.text()

        if not service:
            logger.warning("Service field is required to retrieve a password.")
            QMessageBox.warning(self, "Error", "Service field is required.")
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
                # Pass the cipher_suite to retrieve_password
                self.retrieve_password(service)
                logger.info(
                    f"Master password verified for retrieving service: {service}."
                )
            else:
                logger.warning("Incorrect master password for retrieval.")
                QMessageBox.warning(
                    self, "Error", "Incorrect master password. Please try again."
                )
        else:
            logger.warning(
                "Master password is required to retrieve the service password."
            )
            QMessageBox.warning(
                self,
                "Error",
                "Master password is required to retrieve the service password.",
            )

    def retrieve_password(self, service):
        try:
            # Ensure cipher_suite is passed to retrieve_password
            username, encrypted_password = retrieve_password(self.conn, service, self.cipher_suite)
            
            if username and encrypted_password:
                password = self.cipher_suite.decrypt(encrypted_password.encode()).decode()
                logger.info(f"Retrieved password for service: {service}.")
                QMessageBox.information(
                    self, "Retrieved", f"Username: {username}\nPassword: {password}"
                )
            else:
                logger.info(f"No password found for service: {service}.")
                QMessageBox.information(
                    self, "Not Found", f"No password found for {service}."
                )
        except Exception as e:
            logger.error(f"Failed to retrieve password: {e}")
            QMessageBox.critical(self, "Error", f"Failed to retrieve password: {e}")
