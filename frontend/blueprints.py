from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QHBoxLayout, QLabel, QMessageBox, QPushButton


class ButtonFactory:
    def __init__(self, parent):
        """
        Initialize ButtonFactory with a parent widget.

        Args:
            parent: The parent widget where buttons will be placed.
        """
        self.parent = parent

    def create_button(
        self, button_text: str, button_width: int, button_callback
    ) -> QPushButton:
        """
        Create a QPushButton with specified text, width, and callback.

        Args:
            button_text (str): The text to display on the button.
            button_width (int): The width of the button.
            button_callback (callable): The function to call when the button is clicked.

        Returns:
            QPushButton: The created button.
        """
        button = QPushButton(button_text)
        button.setFixedWidth(button_width)
        button.clicked.connect(button_callback)
        return button

    def create_button_with_layout(
        self, label_text: str, button_text: str, button_width: int, button_callback
    ) -> QHBoxLayout:
        """
        Create a button within a QHBoxLayout with optional label.

        Args:
            label_text (str): The text for the label next to the button.
            button_text (str): The text to display on the button.
            button_width (int): The width of the button.
            button_callback (callable): The function to call when the button is clicked.

        Returns:
            QHBoxLayout: A horizontal layout containing the label and button.
        """
        layout = QHBoxLayout()
        if label_text:
            layout.addWidget(QLabel(label_text))

        button = self.create_button(button_text, button_width, button_callback)
        layout.addStretch()
        layout.addWidget(button)
        layout.addStretch()

        return layout

    def create_buttons_with_spacing(
        self, buttons: list[tuple[str, int, callable]]
    ) -> QHBoxLayout:
        """
        Create multiple buttons with spacing between them.

        Args:
            buttons (list of tuples): Each tuple contains button text, width, and callback function.

        Returns:
            QHBoxLayout: A horizontal layout containing the buttons.
        """
        layout = QHBoxLayout()
        layout.addStretch(1)

        for button_text, button_width, button_callback in buttons:
            button = self.create_button(button_text, button_width, button_callback)
            layout.addWidget(button)
            layout.addSpacing(20)

        layout.addStretch(1)
        return layout


class CustomMessageBox(QMessageBox):
    def __init__(
        self,
        title: str,
        message: str,
        icon=QMessageBox.Information,
        button_text: str = "OK",
        parent=None,
    ):
        """
        Initialize a custom message box with a centered button.

        Args:
            title (str): The title of the message box.
            message (str): The message to display.
            icon (QMessageBox.Icon): The icon to display (default is Information).
            button_text (str): The text for the OK button (default is "OK").
            parent: The parent widget (optional).
        """
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setText(message)
        self.setIcon(icon)
        self.setStandardButtons(QMessageBox.Ok)
        self.setWindowIcon(QIcon("frontend/icons/muscles.png"))

        # Customize the "OK" button text and width
        ok_button = self.button(QMessageBox.Ok)
        ok_button.setText(button_text)
        ok_button.setMinimumWidth(100)

        # Create a new layout to center the button
        centered_layout = QHBoxLayout()
        centered_layout.addStretch(1)
        centered_layout.addWidget(ok_button)
        centered_layout.addStretch(1)

        # Get the existing layout of the QMessageBox and find the button box row
        layout = self.layout()
        button_row = layout.rowCount() - 1  # Assuming buttons are in the last row

        # Remove the original button and add the centered layout
        for i in range(layout.columnCount()):
            item = layout.itemAtPosition(button_row, i)
            if item and item.widget() == ok_button:
                layout.removeItem(item)
                break

        layout.addLayout(centered_layout, button_row, 0, 1, layout.columnCount())

    def show_message(self):
        """Display the message box."""
        self.exec()
