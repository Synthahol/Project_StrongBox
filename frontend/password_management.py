# password_management.py

import logging

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QApplication,
    QCompleter,
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
    check_existing_entry,
    create_connection,
    delete_password,
    get_all_passwords,
    retrieve_password,
    store_password,
    update_password,
)
from backend.utils import create_button, create_horizontal_line, create_input
from frontend.blueprints import ButtonFactory, CustomMessageBox
from session_manager import SessionManager

logger = logging.getLogger(__name__)


class PasswordManagementTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.conn = create_connection()
        self.session = SessionManager.get_instance()
        self.layout = QVBoxLayout(self)
        self.setWindowIcon(QIcon("frontend/icons/encryption.png"))

        self.button_factory = ButtonFactory(self)
        self.create_ui()

    def create_ui(self):
        title_label = QLabel("Fortalice Password Manager")
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

        self.add_autocomplete(self.service_input, self.get_services_list())
        self.add_autocomplete(self.username_input, self.get_usernames_list())

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

    def add_autocomplete(self, line_edit, items):
        completer = QCompleter(items)
        completer.setCaseSensitivity(Qt.CaseInsensitive)
        line_edit.setCompleter(completer)

    def get_services_list(self):
        try:
            cursor = self.conn.execute("SELECT DISTINCT service FROM passwords")
            services = [row[0] for row in cursor.fetchall()]
            return services
        except Exception as e:
            logger.error(f"Error fetching services for autocomplete: {e}")
            return []

    def get_usernames_list(self):
        try:
            cursor = self.conn.execute("SELECT DISTINCT username FROM passwords")
            usernames = [row[0] for row in cursor.fetchall()]
            return usernames
        except Exception as e:
            logger.error(f"Error fetching usernames for autocomplete: {e}")
            return []

    def create_password_table(self):
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["Service", "Username", "Password", "Action"])
        table.setStyleSheet("QTableWidget::item { padding: 0px; margin: 0px; }")

        # Removed the fixed default row height to allow automatic adjustment
        # table.verticalHeader().setDefaultSectionSize(40)

        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)

        # Adjusted size policy to allow expansion
        table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        # Optionally, you can remove the fixed minimum width
        # table.setMinimumWidth(800)

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
        for row_num, (service, username, password) in enumerate(passwords):
            self.password_table.insertRow(row_num)
            self.password_table.setItem(row_num, 0, QTableWidgetItem(service))
            self.password_table.setItem(row_num, 1, QTableWidgetItem(username))

            # Masked Password
            masked_password = "•" * 8
            password_item = QTableWidgetItem(masked_password)
            password_item.setData(Qt.UserRole, password)  # Store actual password
            self.password_table.setItem(row_num, 2, password_item)

            # Actions (Reveal, Copy, Modify)
            action_layout = QHBoxLayout()
            action_layout.setAlignment(Qt.AlignCenter)
            action_layout.setContentsMargins(
                5, 5, 5, 5
            )  # Add margins around the buttons
            action_layout.setSpacing(5)

            button_style = """
            QPushButton {
                padding: 5px;
                min-width: 60px;
                min-height: 30px;  /* Ensure buttons have minimum height */
            }
            """

            from PySide6.QtWidgets import QSizePolicy

            button_size_policy = QSizePolicy(
                QSizePolicy.Preferred, QSizePolicy.Preferred
            )
            button_height = 30  # Adjust as needed

            reveal_button = QPushButton("Reveal")
            reveal_button.setStyleSheet(button_style)
            reveal_button.setSizePolicy(button_size_policy)
            reveal_button.setMinimumHeight(button_height)
            reveal_button.clicked.connect(
                lambda checked, row=row_num: self.toggle_password_visibility(row)
            )
            action_layout.addWidget(reveal_button)

            copy_button = QPushButton("Copy")
            copy_button.setStyleSheet(button_style)
            copy_button.setSizePolicy(button_size_policy)
            copy_button.setMinimumHeight(button_height)
            copy_button.clicked.connect(
                lambda checked, row=row_num: self.copy_password_to_clipboard(row)
            )
            action_layout.addWidget(copy_button)

            modify_button = QPushButton("Modify")
            modify_button.setStyleSheet(button_style)
            modify_button.setSizePolicy(button_size_policy)
            modify_button.setMinimumHeight(button_height)
            modify_button.clicked.connect(
                lambda checked, row=row_num: self.modify_password(row)
            )
            action_layout.addWidget(modify_button)

            action_widget = QWidget()
            action_widget.setLayout(action_layout)
            action_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
            self.password_table.setCellWidget(row_num, 3, action_widget)

        # Adjust row heights to fit contents
        self.password_table.resizeRowsToContents()

    def toggle_password_visibility(self, row):
        item = self.password_table.item(row, 2)
        current_text = item.text()
        actual_password = item.data(Qt.UserRole)
        if current_text == "•" * 8:
            # Reveal the password
            item.setText(actual_password)
            # Update the button text
            action_widget = self.password_table.cellWidget(row, 3)
            buttons = action_widget.findChildren(QPushButton)
            for button in buttons:
                if button.text() == "Reveal":
                    button.setText("Hide")
                    break
        else:
            # Mask the password
            item.setText("•" * 8)
            # Update the button text
            action_widget = self.password_table.cellWidget(row, 3)
            buttons = action_widget.findChildren(QPushButton)
            for button in buttons:
                if button.text() == "Hide":
                    button.setText("Reveal")
                    break

    def copy_password_to_clipboard(self, row):
        item = self.password_table.item(row, 2)
        actual_password = item.data(Qt.UserRole)
        if actual_password:
            clipboard = QApplication.clipboard()
            clipboard.setText(actual_password)
            self.show_success_message("Password copied to clipboard!")
        else:
            self.show_error("Failed to copy password.")

    def modify_password(self, row):
        service = self.password_table.item(row, 0).text()
        username = self.password_table.item(row, 1).text()
        password = self.password_table.item(row, 2).data(Qt.UserRole)

        modify_dialog = ModifyPasswordDialog(
            self.conn, service, username, password, row
        )
        if modify_dialog.exec() == QDialog.Accepted:
            self.load_passwords()

    def delete_password(self, row):
        service = self.password_table.item(row, 0).text()
        username = self.password_table.item(row, 1).text()
        reply = QMessageBox.question(
            self,
            "Delete Confirmation",
            f"Are you sure you want to delete the password for {service}?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            try:
                delete_password(self.conn, service, username)
                QMessageBox.information(
                    self, "Success", "Password deleted successfully."
                )
                self.load_passwords()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete password: {e}")

    def show_password_details_dialog(self, service, username, password):
        details_dialog = QDialog(self)
        details_dialog.setWindowTitle("Password Details")
        details_dialog.setWindowIcon(QIcon("frontend/icons/encryption.png"))

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
        password_label = QLabel(f"Password: {password}")
        password_layout.addWidget(password_label)
        password_layout.addStretch()
        copy_password_button = QPushButton("Copy Password")
        copy_password_button.setFixedWidth(self.width() * 0.15)
        copy_password_button.clicked.connect(lambda: self.copy_to_clipboard(password))
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
            if check_existing_entry(self.conn, service, username):
                self.show_error("This service and username already exist.")
                return

            store_password(self.conn, service, username, password)
            logger.info("Password stored successfully.")
            self.show_success_message("Password stored successfully.")
            self.load_passwords()
            self.service_input.clear()
            self.username_input.clear()
            self.password_input.clear()
        except Exception as e:
            logger.error(f"Failed to store password: {e}")
            self.show_error("Failed to store password.")

    def show_password(self, row):
        main_window = self.window()
        if not main_window.verify_master_password():
            logger.debug("Master password verification failed.")
            return

        service = self.password_table.item(row, 0).text()
        username = self.password_table.item(row, 1).text()

        try:
            username, password = retrieve_password(self.conn, service, username)
            if username and password:
                # Password is already decrypted by retrieve_password
                self.show_password_details_dialog(service, username, password)
            else:
                logger.warning("Failed to retrieve password details.")
                QMessageBox.warning(
                    self, "Error", "Failed to retrieve password details."
                )
        except Exception as e:
            logger.error(f"Error during password retrieval: {e}")
            QMessageBox.critical(self, "Error", "Failed to retrieve password.")

    def verify_master_password(self):
        # Implement this method if needed
        pass


class ModifyPasswordDialog(QDialog):
    def __init__(self, conn, service, username, password, row):
        super().__init__()

        self.conn = conn
        self.service = service
        self.username = username
        self.password = password
        self.row = row

        self.setWindowTitle("Modify Service, Username, or Password")
        self.setMinimumWidth(400)
        self.setWindowIcon(QIcon("frontend/icons/encryption.png"))

        layout = QVBoxLayout(self)
        self.layout = QGridLayout()

        self.layout.addWidget(QLabel("Service:"), 0, 0)
        self.service_input = QLineEdit(self.service)
        self.layout.addWidget(self.service_input, 0, 1)

        self.layout.addWidget(QLabel("Username:"), 1, 0)
        self.username_input = QLineEdit(self.username)
        self.layout.addWidget(self.username_input, 1, 1)

        self.layout.addWidget(QLabel("Password:"), 2, 0)
        self.password_input = QLineEdit(self.password)
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
        self.center_on_screen()

    def center_on_screen(self):
        screen = QApplication.primaryScreen().geometry()
        dialog_rect = self.geometry()
        center_x = (screen.width() - dialog_rect.width()) // 2
        center_y = (screen.height() - dialog_rect.height()) // 2
        self.move(center_x, center_y)

    def save_password(self):
        new_service = self.service_input.text()
        new_username = self.username_input.text()
        new_password = self.password_input.text()

        try:
            update_password(
                self.conn,
                self.service,
                self.username,
                new_service,
                new_username,
                new_password,
            )
            CustomMessageBox(
                "Success", "Password updated successfully!", QMessageBox.Information
            ).show_message()
            self.accept()
        except Exception as e:
            logger.error(f"Failed to update password: {e}")
            CustomMessageBox(
                "Error", "Failed to update password.", QMessageBox.Critical
            ).show_message()

    def delete_password(self):
        reply = QMessageBox.question(
            self,
            "Delete Confirmation",
            f"Are you sure you want to delete the password for {self.service}?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            try:
                delete_password(self.conn, self.service, self.username)
                CustomMessageBox(
                    "Deleted", "Password deleted successfully!", QMessageBox.Information
                ).show_message()
                self.accept()
            except Exception as e:
                logger.error(f"Failed to delete password: {e}")
                CustomMessageBox(
                    "Error", "Failed to delete password.", QMessageBox.Critical
                ).show_message()


class UsernameSelectionDialog(QDialog):
    def __init__(self, usernames):
        super().__init__()
        self.setWindowTitle("Select Username")
        self.setWindowIcon(QIcon("frontend/icons/encryption.png"))
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
