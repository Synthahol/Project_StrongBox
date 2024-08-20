from PySide6.QtWidgets import (
    QDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from backend.database import verify_password


class MasterPasswordDialog(QDialog):
    def __init__(self, conn, cipher_suite):
        super().__init__()
        self.conn = conn
        self.cipher_suite = cipher_suite
        self.password_verified = False
        self.setWindowTitle("Enter Master Password")

        self.layout = QVBoxLayout()

        self.label = QLabel("Please enter your master password:")
        self.layout.addWidget(self.label)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.layout.addWidget(self.password_input)

        self.submit_button = QPushButton("Submit")
        self.submit_button.clicked.connect(self.verify_password)
        self.layout.addWidget(self.submit_button)

        self.setLayout(self.layout)

    def verify_password(self):
        password = self.password_input.text()
        if verify_password(self.conn, self.cipher_suite, password):
            self.password_verified = True
            self.accept()
        else:
            QMessageBox.warning(
                self, "Error", "Incorrect master password. Please try again."
            )

    def exec(self):
        super().exec()
        return self.password_verified
