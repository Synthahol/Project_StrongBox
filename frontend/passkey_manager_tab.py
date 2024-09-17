from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from backend import passkey_manager


class PasskeyManagerTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)

        # Set up the passkey table
        self.passkey_table = QTableWidget(self)
        self.passkey_table.setColumnCount(4)
        self.passkey_table.setHorizontalHeaderLabels(
            ["ID", "Passkey", "Description", "Actions"]
        )
        self.passkey_table.horizontalHeader().setStretchLastSection(True)
        self.layout.addWidget(self.passkey_table)

        # Buttons layout
        buttons_layout = QHBoxLayout()

        # Load passkeys button
        self.load_passkeys_button = QPushButton("Load Passkeys", self)
        self.load_passkeys_button.clicked.connect(self.load_passkeys)
        buttons_layout.addWidget(self.load_passkeys_button)

        # Add passkey button
        self.add_passkey_button = QPushButton("Add Passkey", self)
        self.add_passkey_button.clicked.connect(self.add_passkey)
        buttons_layout.addWidget(self.add_passkey_button)

        self.layout.addLayout(buttons_layout)

        # Set the main layout
        self.setLayout(self.layout)

    def load_passkeys(self):
        try:
            # Load passkeys and display them in the table
            passkeys = passkey_manager.get_all_passkeys()
            self.passkey_table.setRowCount(len(passkeys))
            for i, (id, passkey, description, created_at) in enumerate(passkeys):
                # ID
                self.passkey_table.setItem(i, 0, QTableWidgetItem(str(id)))

                # Masked Passkey
                masked_passkey = "•" * 8  # Display bullets or asterisks
                passkey_item = QTableWidgetItem(masked_passkey)
                passkey_item.setData(Qt.UserRole, passkey)  # Store actual passkey
                self.passkey_table.setItem(i, 1, passkey_item)

                # Description
                self.passkey_table.setItem(i, 2, QTableWidgetItem(description))

                # Actions (Reveal Button)
                reveal_button = QPushButton("Reveal")
                reveal_button.clicked.connect(
                    lambda checked, row=i: self.toggle_passkey_visibility(row)
                )
                self.passkey_table.setCellWidget(i, 3, reveal_button)

            # Resize columns to fit contents
            self.passkey_table.resizeColumnsToContents()

        except ValueError as ve:
            QMessageBox.warning(self, "Warning", str(ve))
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load passkeys:\n{str(e)}")

    def add_passkey(self):
        # Open a dialog to get passkey and description from the user
        dialog = AddPasskeyDialog(self)
        if dialog.exec() == QDialog.Accepted:
            passkey, description = dialog.get_inputs()
            if not passkey:
                QMessageBox.warning(self, "Input Error", "Passkey cannot be empty.")
                return
            try:
                # Add the passkey using the passkey_manager
                passkey_manager.add_passkey(passkey, description)
                QMessageBox.information(self, "Success", "Passkey added successfully.")
                # Reload the passkeys to include the new one
                self.load_passkeys()
            except ValueError as ve:
                QMessageBox.warning(self, "Warning", str(ve))
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to add passkey:\n{str(e)}")

    def toggle_passkey_visibility(self, row):
        item = self.passkey_table.item(row, 1)
        current_text = item.text()
        actual_passkey = item.data(Qt.UserRole)
        if current_text == "•" * 8:
            # Reveal the passkey
            item.setText(actual_passkey)
            self.passkey_table.cellWidget(row, 3).setText("Hide")
        else:
            # Mask the passkey
            item.setText("•" * 8)
            self.passkey_table.cellWidget(row, 3).setText("Reveal")


class AddPasskeyDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Passkey")
        self.setMinimumSize(400, 200)

        layout = QVBoxLayout(self)

        # Passkey input
        self.passkey_label = QLabel("Enter Passkey:")
        layout.addWidget(self.passkey_label)
        self.passkey_input = QLineEdit()
        self.passkey_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.passkey_input)

        # Description input
        self.description_label = QLabel("Enter Description:")
        layout.addWidget(self.description_label)
        self.description_input = QLineEdit()
        layout.addWidget(self.description_input)

        # Buttons
        buttons_layout = QHBoxLayout()
        self.ok_button = QPushButton("OK")
        self.ok_button.clicked.connect(self.accept)
        buttons_layout.addWidget(self.ok_button)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        buttons_layout.addWidget(self.cancel_button)

        layout.addLayout(buttons_layout)

    def get_inputs(self):
        passkey = self.passkey_input.text()
        description = self.description_input.text()
        return passkey, description
