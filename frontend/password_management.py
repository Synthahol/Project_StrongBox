import logging

from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QHeaderView,
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
    get_all_passwords,
    retrieve_password,
    store_password,  # Import store_password function from database
)
from backend.utils import (  # Import utility functions
    create_button,
    create_horizontal_line,
    create_input,
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

        # Add horizontal line using utility function
        self.layout.addWidget(create_horizontal_line())

        # Use utility functions to create input fields
        self.service_input = create_input(
            "Service:", "Enter or copy/paste service name", self.layout
        )
        self.username_input = create_input("Username:", "Enter username", self.layout)
        self.password_input = create_input(
            "Password:", "Enter password", self.layout, QLineEdit.Password
        )

        # Create buttons using utility function
        btn_layout = QHBoxLayout()
        self.layout.addLayout(btn_layout)
        self.store_btn = create_button(
            "Store Password", "icons/store.png", self.store_password
        )
        btn_layout.addWidget(self.store_btn)

        # Add another horizontal line
        self.layout.addWidget(create_horizontal_line())

        # Create table for displaying stored passwords
        self.layout.addWidget(QLabel("Stored Passwords"))
        self.password_table = self.create_password_table()
        self.layout.addWidget(self.password_table)

        self.load_passwords()

    def create_password_table(self):
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["Service", "Username", "Password", "Action"])
        table.setStyleSheet("font-size: 12px;")

        # Make the columns responsive to the width of the main window
        header = table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)

        return table

    def load_passwords(self):
        self.password_table.setRowCount(0)
        passwords = get_all_passwords(self.conn)
        for row_num, (service, username, encrypted_password) in enumerate(passwords):
            self.password_table.insertRow(row_num)
            self.password_table.setItem(row_num, 0, QTableWidgetItem(service))
            self.password_table.setItem(row_num, 1, QTableWidgetItem(username))

            # Display masked password instead of hashed or encrypted password
            masked_password = "******"
            self.password_table.setItem(row_num, 2, QTableWidgetItem(masked_password))

            show_btn = create_button(
                "Show", "", lambda ch, r=row_num: self.show_password(r)
            )
            self.password_table.setCellWidget(row_num, 3, show_btn)

    def show_password(self, row):
        main_window = self.window()

        if not main_window.verify_master_password():
            logger.debug("Master password verification failed.")
            return

        service = self.password_table.item(row, 0).text()
        logger.debug(f"Service selected: {service}")

        try:
            cursor = self.conn.execute(
                "SELECT username FROM passwords WHERE service = ?", (service,)
            )
            usernames = [username[0] for username in cursor.fetchall()]

            if not usernames:
                logger.warning(f"No usernames found for service: {service}")
                QMessageBox.warning(
                    self, "Error", f"No usernames found for service: {service}"
                )
                return

            if len(usernames) > 1:
                dialog = UsernameSelectionDialog(usernames)
                if dialog.exec():
                    selected_username = dialog.selected_username
                else:
                    logger.info("Username selection canceled.")
                    return
            else:
                selected_username = usernames[0]

            username, encrypted_password = retrieve_password(
                self.conn, service, selected_username, self.cipher_suite
            )
            logger.debug(
                f"Retrieved Username: {username}, Encrypted Password: {encrypted_password}"
            )

            if username and encrypted_password:
                decrypted_password = self.cipher_suite.decrypt(
                    encrypted_password.encode()
                ).decode()
                logger.debug(f"Decrypted Password: {decrypted_password}")

                # Create a custom dialog for showing the password details with copy buttons
                self.show_password_details_dialog(service, username, decrypted_password)

            else:
                logger.warning("Failed to retrieve password details.")
                QMessageBox.warning(
                    self, "Error", "Failed to retrieve password details."
                )
        except Exception as e:
            logger.error(f"Error during password retrieval: {e}")
            QMessageBox.critical(self, "Error", f"Failed to retrieve password: {e}")

    def show_password_details_dialog(self, service, username, decrypted_password):
        details_dialog = QDialog(self)
        details_dialog.setWindowTitle("Password Details")

        # Set a fixed width for the dialog to ensure it looks neat
        details_dialog.setFixedWidth(500)  # Adjust this value as needed

        layout = QVBoxLayout(details_dialog)

        service_label = QLabel(f"Service: {service}")
        layout.addWidget(service_label)

        username_layout = QHBoxLayout()
        username_label = QLabel(f"Username: {username}")
        copy_username_btn = QPushButton("Copy Username")
        copy_username_btn.clicked.connect(lambda: self.copy_to_clipboard(username))
        username_layout.addWidget(username_label)
        username_layout.addWidget(copy_username_btn)
        layout.addLayout(username_layout)

        password_layout = QHBoxLayout()
        password_label = QLabel(f"Password: {decrypted_password}")
        copy_password_btn = QPushButton("Copy Password")
        copy_password_btn.clicked.connect(
            lambda: self.copy_to_clipboard(decrypted_password)
        )
        password_layout.addWidget(password_label)
        password_layout.addWidget(copy_password_btn)
        layout.addLayout(password_layout)

        close_button = QPushButton("Close")
        close_button.clicked.connect(details_dialog.accept)
        layout.addWidget(close_button)

        details_dialog.setLayout(layout)
        details_dialog.exec()

    def copy_to_clipboard(self, text):
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        QMessageBox.information(self, "Copied", "Text copied to clipboard!")

    def store_password(self):
        service = self.service_input.text()
        username = self.username_input.text()
        password = self.password_input.text()

        if not service or not username or not password:
            QMessageBox.warning(
                self, "Warning", "All fields must be filled out to store a password."
            )
            return

        try:
            # Call the store_password function with the plain text password
            store_password(self.conn, service, username, password, self.cipher_suite)
            logger.info(f"Password for {service} stored successfully.")
            QMessageBox.information(
                self, "Success", f"Password for {service} stored successfully."
            )
            self.load_passwords()
        except Exception as e:
            logger.error(f"Failed to store password: {e}")
            QMessageBox.critical(self, "Error", f"Failed to store password: {e}")


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
