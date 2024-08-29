from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QHBoxLayout, QLabel, QMessageBox, QPushButton


class ButtonFactory:
    def __init__(self, parent):
        self.parent = parent

    def create_button_with_layout(
        self, label_text, button_text, button_width, button_callback
    ):
        layout = QHBoxLayout()
        label = QLabel(label_text)
        button = QPushButton(button_text)
        button.setFixedWidth(button_width)
        button.clicked.connect(button_callback)

        layout.addStretch()  # Add stretchable space to the left
        layout.addWidget(label)  # Optional: Add label if needed
        layout.addWidget(button)
        layout.addStretch()  # Add stretchable space to the right to center the button

        return layout

    def create_buttons_with_spacing(self, buttons):
        layout = QHBoxLayout()
        layout.addStretch(1)  # Add stretchable space to the left

        for button_text, button_width, button_callback in buttons:
            button_layout = self.create_button_with_layout(
                "", button_text, button_width, button_callback
            )
            layout.addLayout(button_layout)
            layout.addSpacing(20)  # Add spacing between buttons

        layout.addStretch(1)  # Add stretchable space to the right

        return layout


class CustomMessageBox(QMessageBox):
    def __init__(
        self,
        title,
        message,
        icon=QMessageBox.Information,
        button_text="OK",
        parent=None,
    ):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setText(message)
        self.setIcon(icon)
        self.setStandardButtons(QMessageBox.Ok)
        # Ensure the icon path is correctly formatted and accessible
        self.setWindowIcon(QIcon("frontend/icons/muscles.png"))

        # Access the "OK" button directly
        ok_button = self.button(QMessageBox.Ok)
        ok_button.setText(button_text)  # Customize button text if needed
        ok_button.setMinimumWidth(100)  # Set the button width

        # Center the OK button
        centered_layout = QHBoxLayout()
        centered_layout.addStretch(1)  # Add stretchable space to the left
        centered_layout.addWidget(ok_button)  # Add the OK button
        centered_layout.addStretch(1)  # Add stretchable space to the right

        # Access the layout of the QMessageBox
        layout = self.layout()

        # Replace the original layout's button box with the centered layout
        layout.addLayout(centered_layout, layout.rowCount(), 0, 1, layout.columnCount())

    def show_message(self):
        self.exec()
