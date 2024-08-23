from PySide6.QtWidgets import QHBoxLayout, QLabel, QPushButton


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

        layout.addWidget(label)
        layout.addStretch()  # Add stretchable space to push the button to the right
        layout.addWidget(button)
        return layout
