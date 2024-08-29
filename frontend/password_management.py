import logging

from blueprints import ButtonFactory, CustomMessageBox
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from backend.database import (
    delete_password,
    get_all_passwords,
    retrieve_password,
    store_password,
    update_password,
)
from backend.master_password import verify_password
from backend.utils import create_button, create_horizontal_line, create_input

logger = logging.getLogger(__name__)


class PasswordManagementTab(QWidget):
    def __init__(self, conn, cipher_suite):
        super().__init__()
        self.conn = conn
        self.cipher_suite = cipher_suite
        self.layout = QVBoxLayout(self)
        self.setWindowIcon(QIcon("frontend/icons/muscles.png"))  # Set the custom icon

        # Create an instance of ButtonFactory
        self.button_factory = ButtonFactory(self)
        self.create_ui()

    def create_ui(self):
        title_label = QLabel("StrongBox Password Manager")
        title_label.setStyleSheet(
            "font-size: 30px; font-weight: bold; margin-bottom: 15px;"
        )
        title_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(title_label)
        self.layout.addWidget(create_horizontal_line())

        self.service_input = create_input(
            "Service:", "Enter or copy/paste service name", self.layout
        )
        self.username_input = create_input("Username:", "Enter username", self.layout)
        self.password_input = create_input(
            "Password:", "Enter password", self.layout, QLineEdit.Password
        )

        btn_layout = QHBoxLayout()
        self.layout.addLayout(btn_layout)
        self.store_btn = create_button(
            "Store Password", "icons/store.png", self.store_password
        )
        btn_layout.addWidget(self.store_btn)

        self.layout.addWidget(create_horizontal_line())
        self.layout.addWidget(QLabel("Stored Passwords"))
        self.password_table = self.create_password_table()
        self.layout.addWidget(self.password_table)

        self.load_passwords()

    def create_password_table(self):
        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(
            ["Service", "Username", "Password", "Action", "Modify"]
        )
        table.setStyleSheet("QTableWidget::item { padding: 0px; margin: 0px; }")
        table.verticalHeader().setDefaultSectionSize(40)
        header = table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        return table

    def show_success_message(self, message):
        msg_box = CustomMessageBox(
            title="Success", message=message, icon=QMessageBox.Information
        )
        msg_box.show_message()

    def show_error(self, message):
        msg_box = CustomMessageBox(
            title="Error", message=message, icon=QMessageBox.Critical
        )
        msg_box.show_message()

    def load_passwords(self):
        self.password_table.setRowCount(0)
        passwords = get_all_passwords(self.conn)
        for row_num, (service, username, encrypted_password) in enumerate(passwords):
            self.password_table.insertRow(row_num)
            self.password_table.setItem(row_num, 0, QTableWidgetItem(service))
            self.password_table.setItem(row_num, 1, QTableWidgetItem(username))
            self.password_table.setItem(row_num, 2, QTableWidgetItem("******"))

            show_btn = create_button(
                "Show", "", lambda ch, r=row_num: self.show_password(r)
            )
            show_btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            show_btn.setStyleSheet("padding: 0px; margin: 0px;")
            self.password_table.setCellWidget(row_num, 3, show_btn)

            modify_btn = QPushButton("Modify")
            modify_btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            modify_btn.setStyleSheet("padding: 0px; margin: 0px;")
            modify_btn.clicked.connect(lambda ch, r=row_num: self.modify_password(r))
            self.password_table.setCellWidget(row_num, 4, modify_btn)

    def modify_password(self, row):
        dialog = MasterPasswordDialog(self.verify_master_password)
        if dialog.exec() == QDialog.Accepted:
            service = self.password_table.item(row, 0).text()
            username = self.password_table.item(row, 1).text()

            cursor = self.conn.execute(
                "SELECT password FROM passwords WHERE service = ? AND username = ?",
                (service, username),
            )
            encrypted_password = cursor.fetchone()[0]

            modify_dialog = ModifyPasswordDialog(
                self.conn, self.cipher_suite, service, username, encrypted_password, row
            )
            if modify_dialog.exec() == QDialog.Accepted:
                self.load_passwords()

    def verify_master_password(self, entered_password: str) -> bool:
        try:
            cursor = self.conn.execute("SELECT salt, password FROM master_password")
            row = cursor.fetchone()

            if row is None:
                logger.error("No master password found in the database.")
                return False

            stored_salt, stored_password = row
            return verify_password(stored_password, entered_password, stored_salt)
        except Exception as e:
            logger.error(f"Error verifying master password: {e}")
            return False

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
                CustomMessageBox(
                    "Error",
                    f"No usernames found for service: {service}",
                    QMessageBox.Warning,
                ).show_message()
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
                self.show_password_details_dialog(service, username, decrypted_password)
            else:
                logger.warning("Failed to retrieve password details.")
                CustomMessageBox(
                    "Error", "Failed to retrieve password details.", QMessageBox.Warning
                ).show_message()
        except Exception as e:
            logger.error(f"Error during password retrieval: {e}")
            CustomMessageBox(
                "Error", f"Failed to retrieve password: {e}", QMessageBox.Critical
            ).show_message()

    def show_password_details_dialog(self, service, username, decrypted_password):
        details_dialog = QDialog(self)
        details_dialog.setWindowTitle("Password Details")
        details_dialog.setWindowIcon(
            QIcon("frontend/icons/muscles.png")
        )  # Set the custom icon

        layout = QVBoxLayout(details_dialog)
        details_dialog.setFixedWidth(700)
        details_dialog.setFixedHeight(200)

        service_layout = QHBoxLayout()
        service_label = QLabel(f"Service: {service}")
        service_layout.addWidget(service_label)
        service_layout.addStretch()
        copy_service_button = QPushButton("Copy Service")
        copy_service_button.setFixedWidth(self.width() * 0.15)
        copy_service_button.clicked.connect(lambda: self.copy_to_clipboard(service))
        service_layout.addWidget(copy_service_button)
        layout.addLayout(service_layout)

        username_layout = QHBoxLayout()
        username_label = QLabel(f"Username: {username}")
        username_layout.addWidget(username_label)
        username_layout.addStretch()
        copy_username_button = QPushButton("Copy Username")
        copy_username_button.setFixedWidth(self.width() * 0.15)
        copy_username_button.clicked.connect(lambda: self.copy_to_clipboard(username))
        username_layout.addWidget(copy_username_button)
        layout.addLayout(username_layout)

        password_layout = QHBoxLayout()
        password_label = QLabel(f"Password: {decrypted_password}")
        password_layout.addWidget(password_label)
        password_layout.addStretch()
        copy_password_button = QPushButton("Copy Password")
        copy_password_button.setFixedWidth(self.width() * 0.15)
        copy_password_button.clicked.connect(
            lambda: self.copy_to_clipboard(decrypted_password)
        )
        password_layout.addWidget(copy_password_button)
        layout.addLayout(password_layout)

        close_button_layout = QHBoxLayout()
        close_button = QPushButton("Close")
        close_button.setFixedWidth(self.width() * 0.15)
        close_button.clicked.connect(details_dialog.accept)
        close_button_layout.addStretch()
        close_button_layout.addWidget(close_button)
        close_button_layout.addStretch()
        layout.addLayout(close_button_layout)

        details_dialog.setLayout(layout)
        details_dialog.adjustSize()
        details_dialog.exec()

    def copy_to_clipboard(self, text):
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        self.show_success_message("Text copied to clipboard!")

    def store_password(self):
        service = self.service_input.text()
        username = self.username_input.text()
        password = self.password_input.text()

        if not service or not username or not password:
            self.show_error("All fields must be filled out to store a password.")
            return

        try:
            store_password(self.conn, service, username, password, self.cipher_suite)
            logger.info(f"Password for {service} stored successfully.")
            self.show_success_message(f"Password for {service} stored successfully.")
            self.load_passwords()
            self.service_input.clear()
            self.username_input.clear()
            self.password_input.clear()
        except Exception as e:
            logger.error(f"Failed to store password: {e}")
            self.show_error(f"Failed to store password: {e}")


class ModifyPasswordDialog(QDialog):
    def __init__(self, conn, cipher_suite, service, username, encrypted_password, row):
        super().__init__()

        self.conn = conn
        self.cipher_suite = cipher_suite
        self.service = service
        self.username = username
        self.encrypted_password = encrypted_password
        self.row = row

        self.setWindowTitle("Modify Service, Username, or Password")
        self.setMinimumWidth(400)
        self.setWindowIcon(QIcon("frontend/icons/muscles.png"))  # Set the custom icon

        layout = QVBoxLayout(self)
        self.layout = QGridLayout()

        self.layout.addWidget(QLabel("Service:"), 0, 0)
        self.service_input = QLineEdit(service)
        self.layout.addWidget(self.service_input, 0, 1)

        self.layout.addWidget(QLabel("Username:"), 1, 0)
        self.username_input = QLineEdit(username)
        self.layout.addWidget(self.username_input, 1, 1)

        try:
            decrypted_password = self.cipher_suite.decrypt(
                encrypted_password.encode()
            ).decode()
        except Exception as e:
            logger.error(f"Failed to decrypt password for {service}: {e}")
            decrypted_password = ""

        self.layout.addWidget(QLabel("Password:"), 2, 0)
        self.password_input = QLineEdit(decrypted_password)
        self.password_input.setEchoMode(QLineEdit.Password)
        self.layout.addWidget(self.password_input, 2, 1)

        button_factory = ButtonFactory(self)
        buttons = [
            ("Save", 100, self.save_password),
            ("Delete", 100, self.delete_password),
        ]
        button_layout = button_factory.create_buttons_with_spacing(buttons)

        layout.addLayout(self.layout)
        layout.addLayout(button_layout)
        self.setLayout(layout)
        self.adjustSize()

    def save_password(self):
        new_service = self.service_input.text()
        new_username = self.username_input.text()
        new_password = self.password_input.text()

        update_password(
            self.conn,
            self.service,
            self.username,
            self.encrypted_password,
            new_service,
            new_username,
            new_password,
            self.cipher_suite,
        )
        CustomMessageBox(
            "Success", "Password updated successfully!", QMessageBox.Information
        ).show_message()
        self.accept()

    def delete_password(self):
        delete_password(self.conn, self.service, self.username, self.cipher_suite)
        CustomMessageBox(
            "Deleted", "Password deleted successfully!", QMessageBox.Information
        ).show_message()
        self.accept()


class MasterPasswordDialog(QDialog):
    def __init__(self, verify_master_password_callback, parent=None):
        super().__init__(parent)
        self.verify_master_password_callback = verify_master_password_callback
        self.setWindowTitle("Enter Master Password")
        self.setMinimumWidth(400)
        self.setWindowIcon(QIcon("frontend/icons/muscles.png"))  # Set the custom icon

        layout = QVBoxLayout(self)

        self.label = QLabel("Please enter the master password:")
        layout.addWidget(self.label)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        button_factory = ButtonFactory(self)
        self.button_box = QHBoxLayout()
        ok_button_layout = button_factory.create_button_with_layout(
            "", "OK", 100, self.check_password
        )
        cancel_button_layout = button_factory.create_button_with_layout(
            "", "Cancel", 100, self.reject
        )

        self.button_box.addLayout(ok_button_layout)
        self.button_box.addLayout(cancel_button_layout)
        layout.addLayout(self.button_box)

    def check_password(self):
        entered_password = self.password_input.text()
        if self.verify_master_password_callback(entered_password):
            self.accept()
        else:
            msg_box = CustomMessageBox(
                title="Incorrect Password",
                message="The password you entered is incorrect.",
                icon=QMessageBox.Warning,
            )
            msg_box.show_message()
            self.password_input.clear()


class UsernameSelectionDialog(QDialog):
    def __init__(self, usernames):
        super().__init__()
        self.setWindowTitle("Select Username")
        self.setWindowIcon(QIcon("frontend/icons/muscles.png"))  # Set the custom icon
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
            msg_box = CustomMessageBox(
                title="Selection Error",
                message="Please select a username.",
                icon=QMessageBox.Warning,
            )
            msg_box.show_message()
