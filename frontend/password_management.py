# frontend/password_management.py

import logging
import os

from PySide6.QtCore import QItemSelectionModel, Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QApplication,
    QCompleter,
    QDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
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
    store_password,
    update_password,
)
from frontend.blueprints import (
    ButtonFactory,
    CustomMessageBox,
    add_title_and_description,
)
from session_manager import SessionManager

logger = logging.getLogger(__name__)

# Constants
ICON_PATH = os.path.join("frontend", "icons", "encryption.png")


class PasswordManagementTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.conn = create_connection()
        self.session = SessionManager()

        self.setWindowIcon(QIcon(ICON_PATH))
        self.button_factory = ButtonFactory(self)
        self.layout = QVBoxLayout(self)
        self.password_data = []  # Store all password data for filtering
        self.create_ui()

    def create_ui(self):
        # Add title and description using the helper function
        add_title_and_description(
            self.layout,
            "Fortalice Secure Password Vault",
            "Secure storage of your usernames and passwords.",
        )
        # Assuming 'add_title_and_description' sets the objectName for the title label
        # If not, you need to modify 'add_title_and_description' to set it.

        # Input Fields using QFormLayout
        form_layout = QFormLayout()
        self.service_input = self.create_input_field(
            "Service:", "Enter or copy/paste service name"
        )
        self.username_input = self.create_input_field("Username:", "Enter username")
        self.password_input = self.create_input_field(
            "Password:", "Enter password", echo_mode=QLineEdit.Password
        )
        form_layout.addRow("Service:", self.service_input)
        form_layout.addRow("Username:", self.username_input)
        form_layout.addRow("Password:", self.password_input)
        self.layout.addLayout(form_layout)

        # Autocomplete for Inputs
        self.add_autocomplete(self.service_input, self.get_distinct_values("service"))
        self.add_autocomplete(self.username_input, self.get_distinct_values("username"))

        # Action Buttons
        buttons_layout = QHBoxLayout()
        store_button = self.button_factory.create_button(
            button_text="Store Password",
            button_width=250,
            button_callback=self.store_password,
            icon_path=os.path.join("frontend", "icons", "store.png"),
            tooltip="Click to store the entered password",
        )
        store_button.setObjectName("storePasswordButton")  # Set objectName for QSS
        buttons_layout.addWidget(store_button)
        self.layout.addLayout(buttons_layout)

        # Add some vertical space for clarity
        spacer = QWidget()
        spacer.setFixedHeight(40)  # Adjust the height of the spacer as needed
        self.layout.addWidget(spacer)

        # Search bar for filtering passwords
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search by service or username...")
        self.search_bar.textChanged.connect(
            self.filter_passwords
        )  # Connect the search input to filter method
        self.layout.addWidget(self.search_bar)

        # Stored Passwords Section
        stored_label = QLabel("Stored Passwords")
        stored_label.setObjectName("passwordHealthTitle")  # Set objectName for QSS
        stored_label.setStyleSheet("font-size: 20px; font-weight: bold;")
        stored_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(stored_label)

        self.password_table = self.create_password_table()
        self.layout.addWidget(self.password_table)

        self.load_passwords()

    def create_input_field(
        self, label_text, placeholder_text, echo_mode=QLineEdit.Normal
    ):
        input_field = QLineEdit()
        input_field.setPlaceholderText(placeholder_text)
        input_field.setEchoMode(echo_mode)
        input_field.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        return input_field

    def add_autocomplete(self, line_edit, items):
        completer = QCompleter(items)
        completer.setCaseSensitivity(Qt.CaseInsensitive)
        line_edit.setCompleter(completer)

    def get_distinct_values(self, column_name):
        try:
            cursor = self.conn.execute(f"SELECT DISTINCT {column_name} FROM passwords")
            values = [row[0] for row in cursor.fetchall()]
            return values
        except Exception as e:
            logger.error(f"Error fetching {column_name} for autocomplete: {e}")
            return []

    def create_password_table(self):
        table = QTableWidget()
        table.setObjectName("passwordTable")  # Set objectName for QSS
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["Service", "Username", "Password", "Action"])
        table.setAlternatingRowColors(True)  # Enable alternating row colors
        table.setFrameShape(
            QFrame.NoFrame
        )  # Remove default frame to allow rounded corners
        table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        table.horizontalHeader().setObjectName(
            "passwordTableHeader"
        )  # Set objectName for QSS

        header = table.horizontalHeader()
        for i in range(3):
            header.setSectionResizeMode(i, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # Set selection behavior and mode to allow selecting individual cells, rows, or columns
        table.setSelectionBehavior(QTableWidget.SelectItems)
        table.setSelectionMode(QTableWidget.ExtendedSelection)

        # Connect doubleClicked signal for cells
        table.doubleClicked.connect(self.handle_cell_double_click)

        # Connect doubleClicked signals for headers
        table.horizontalHeader().doubleClicked.connect(
            self.handle_horizontal_header_double_click
        )
        table.verticalHeader().doubleClicked.connect(
            self.handle_vertical_header_double_click
        )

        return table

    def show_message(self, title, message, icon=QMessageBox.Information):
        msg_box = CustomMessageBox(title=title, message=message, icon=icon)
        msg_box.show_message()

    def load_passwords(self):
        """Load passwords from the database and display them in the table."""
        self.password_table.setRowCount(0)
        self.password_data = get_all_passwords(
            self.conn
        )  # Store all passwords for filtering
        self.populate_table(self.password_data)

    def populate_table(self, passwords):
        """Populate the table with password data."""
        self.password_table.setRowCount(0)  # Clear the table
        for row_num, (service, username, password) in enumerate(passwords):
            self.password_table.insertRow(row_num)
            self.add_password_row(row_num, service, username, password)
            self.password_table.setRowHeight(row_num, 50)
        self.password_table.resizeRowsToContents()

    def add_password_row(self, row_num, service, username, password):
        # Service Item
        service_item = QTableWidgetItem(service)
        service_item.setFlags(service_item.flags() & ~Qt.ItemIsEditable)
        self.password_table.setItem(row_num, 0, service_item)

        # Username Item
        username_item = QTableWidgetItem(username)
        username_item.setFlags(username_item.flags() & ~Qt.ItemIsEditable)
        self.password_table.setItem(row_num, 1, username_item)

        # Password Item
        masked_password = "•" * 8
        password_item = QTableWidgetItem(masked_password)
        password_item.setData(Qt.UserRole, password)  # Store actual password
        password_item.setFlags(password_item.flags() & ~Qt.ItemIsEditable)
        self.password_table.setItem(row_num, 2, password_item)

        # Actions
        action_widget = self.create_action_widget(row_num)
        self.password_table.setCellWidget(row_num, 3, action_widget)

    def create_action_widget(self, row_num):
        action_layout = QHBoxLayout()
        action_layout.setAlignment(Qt.AlignCenter)
        action_layout.setContentsMargins(5, 5, 5, 5)
        action_layout.setSpacing(5)

        # Define action buttons
        action_buttons = [
            (
                "Reveal",
                80,
                lambda checked, r=row_num: self.toggle_password_visibility(r),
                os.path.join("frontend", "icons", "reveal.png"),
                "Click to reveal or hide the password",
            ),
            (
                "Copy",
                80,
                lambda checked, r=row_num: self.copy_to_clipboard(r),
                os.path.join("frontend", "icons", "copy.png"),
                "Click to copy the password to clipboard",
            ),
            (
                "Modify",
                80,
                lambda checked, r=row_num: self.modify_password(r),
                os.path.join("frontend", "icons", "modify.png"),
                "Click to modify the password entry",
            ),
        ]

        for text, width, callback, icon_path, tooltip in action_buttons:
            button = self.button_factory.create_button(
                button_text=text,
                button_width=width,
                button_callback=callback,
                icon_path=icon_path,
                tooltip=tooltip,
            )
            # Optionally set object names if you have specific styles
            # button.setObjectName(f"{text.lower()}Button")
            action_layout.addWidget(button)

        action_widget = QWidget()
        action_widget.setLayout(action_layout)
        return action_widget

    def filter_passwords(self):
        """Filter the table based on the search bar input."""
        search_text = self.search_bar.text().lower()
        filtered_data = [
            (service, username, password)
            for service, username, password in self.password_data
            if search_text in service.lower() or search_text in username.lower()
        ]
        self.populate_table(filtered_data)

    def toggle_password_visibility(self, row):
        item = self.password_table.item(row, 2)
        current_text = item.text()
        actual_password = item.data(Qt.UserRole)
        if current_text == "•" * 8:
            item.setText(actual_password)
            self.update_action_button_text(row, "Reveal", "Hide")
        else:
            item.setText("•" * 8)
            self.update_action_button_text(row, "Hide", "Reveal")

    def update_action_button_text(self, row, current_text, new_text):
        action_widget = self.password_table.cellWidget(row, 3)
        buttons = action_widget.findChildren(QPushButton)
        for button in buttons:
            if button.text() == current_text:
                button.setText(new_text)
                break

    def copy_to_clipboard(self, row):
        item = self.password_table.item(row, 2)
        actual_password = item.data(Qt.UserRole)
        if actual_password:
            clipboard = QApplication.clipboard()
            clipboard.setText(actual_password)
            self.show_message(
                "Success", "Password copied to clipboard!", QMessageBox.Information
            )
            logger.info(
                f"Copied password for service: {self.password_table.item(row, 0).text()}"
            )
        else:
            self.show_message("Error", "Failed to copy password.", QMessageBox.Critical)
            logger.error(f"Failed to copy password for row: {row}")

    def modify_password(self, row):
        service = self.password_table.item(row, 0).text()
        username = self.password_table.item(row, 1).text()
        password = self.password_table.item(row, 2).data(Qt.UserRole)

        modify_dialog = ModifyPasswordDialog(self.conn, service, username, password)
        if modify_dialog.exec() == QDialog.Accepted:
            self.load_passwords()

    def store_password(self):
        service = self.service_input.text().strip()
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        if not service or not username or not password:
            self.show_message(
                "Error",
                "All fields must be filled out to store a password.",
                QMessageBox.Critical,
            )
            return

        try:
            if check_existing_entry(self.conn, service, username):
                self.show_message(
                    "Error",
                    "This service and username already exist.",
                    QMessageBox.Critical,
                )
                return

            store_password(self.conn, service, username, password)
            logger.info(f"Stored password for service: {service}, username: {username}")
            self.show_message(
                "Success", "Password stored successfully.", QMessageBox.Information
            )
            self.load_passwords()
            self.service_input.clear()
            self.username_input.clear()
            self.password_input.clear()
        except Exception as e:
            logger.error(
                f"Failed to store password for service: {service}, username: {username} - {e}"
            )
            self.show_message(
                "Error", "Failed to store password.", QMessageBox.Critical
            )

    def handle_cell_double_click(self, index):
        """Handle double-click events on cells to unhighlight them."""
        if not index.isValid():
            return

        selection_model = self.password_table.selectionModel()

        if selection_model.isSelected(index):
            selection_model.select(
                index, QItemSelectionModel.Deselect | QItemSelectionModel.Select
            )

    def handle_horizontal_header_double_click(self, logicalIndex):
        """Handle double-click events on horizontal headers to unhighlight columns."""
        selection_model = self.password_table.selectionModel()
        if selection_model.isColumnSelected(logicalIndex):
            selection_model.select(
                self.password_table.model().index(0, logicalIndex),
                QItemSelectionModel.Deselect
                | QItemSelectionModel.Select
                | QItemSelectionModel.Columns,
            )

    def handle_vertical_header_double_click(self, logicalIndex):
        """Handle double-click events on vertical headers to unhighlight rows."""
        selection_model = self.password_table.selectionModel()
        if selection_model.isRowSelected(logicalIndex):
            selection_model.select(
                self.password_table.model().index(logicalIndex, 0),
                QItemSelectionModel.Deselect
                | QItemSelectionModel.Select
                | QItemSelectionModel.Rows,
            )


class ModifyPasswordDialog(QDialog):
    def __init__(self, conn, service, username, password):
        super().__init__()
        self.conn = conn
        self.service = service
        self.username = username
        self.password = password

        self.setWindowTitle("Modify Service, Username, or Password")
        self.setMinimumWidth(400)
        self.setWindowIcon(QIcon(ICON_PATH))

        self.layout = QVBoxLayout(self)
        form_layout = QFormLayout()

        self.service_input = QLineEdit(self.service)
        self.username_input = QLineEdit(self.username)
        self.password_input = QLineEdit(self.password)
        self.password_input.setEchoMode(QLineEdit.Password)

        form_layout.addRow("Service:", self.service_input)
        form_layout.addRow("Username:", self.username_input)
        form_layout.addRow("Password:", self.password_input)

        self.layout.addLayout(form_layout)

        # Action Buttons
        button_factory = ButtonFactory(self)
        action_buttons = [
            (
                "Save",
                120,
                self.save_password,
                os.path.join("frontend", "icons", "save.png"),
                "Click to save the updated password",
            ),
            (
                "Delete",
                120,
                self.delete_password,
                os.path.join("frontend", "icons", "delete.png"),
                "Click to delete this password entry",
            ),
        ]
        button_layout = button_factory.create_buttons_with_spacing(action_buttons)
        self.layout.addLayout(button_layout)
        self.adjustSize()
        self.center_on_screen()

    def center_on_screen(self):
        screen = QApplication.primaryScreen().geometry()
        dialog_rect = self.geometry()
        center_x = (screen.width() - dialog_rect.width()) // 2
        center_y = (screen.height() - dialog_rect.height()) // 2
        self.move(center_x, center_y)

    def save_password(self):
        new_service = self.service_input.text().strip()
        new_username = self.username_input.text().strip()
        new_password = self.password_input.text().strip()

        if not new_service or not new_username or not new_password:
            CustomMessageBox(
                title="Warning",
                message="All fields must be filled out to modify the password.",
                icon=QMessageBox.Warning,
            ).show_message()
            return

        try:
            update_password(
                self.conn,
                self.service,
                self.username,
                new_service,
                new_username,
                new_password,
            )
            logger.info(
                f"Updated password for service: {self.service}, username: {self.username}"
            )
            CustomMessageBox(
                "Success", "Password updated successfully!", QMessageBox.Information
            ).show_message()
            self.accept()
        except Exception as e:
            logger.error(
                f"Failed to update password for service: {self.service}, username: {self.username} - {e}"
            )
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
                logger.info(
                    f"Deleted password for service: {self.service}, username: {self.username}"
                )
                CustomMessageBox(
                    "Deleted", "Password deleted successfully!", QMessageBox.Information
                ).show_message()
                self.accept()
            except Exception as e:
                logger.error(
                    f"Failed to delete password for service: {self.service}, username: {self.username} - {e}"
                )
                CustomMessageBox(
                    "Error", "Failed to delete password.", QMessageBox.Critical
                ).show_message()
