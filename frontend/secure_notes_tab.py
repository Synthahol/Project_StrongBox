# frontend/secure_notes_tab.py

import logging

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from backend.secure_notes import (
    add_secure_note,
    create_secure_notes_table,
    delete_secure_note,
    get_all_secure_notes,
    get_secure_note_by_id,
    update_secure_note,
)
from frontend.blueprints import ButtonFactory, CustomMessageBox

logger = logging.getLogger(__name__)


class SecureNotesTab(QWidget):
    def __init__(self, conn):
        super().__init__()
        self.conn = conn
        if not self.conn:
            CustomMessageBox(
                "Error",
                "Failed to connect to the database.",
                QMessageBox.Critical,
            ).show_message()
            logger.error("Database connection failed in SecureNotesTab.")
            return
        create_secure_notes_table(self.conn)
        self.selected_note_id = None
        self.button_factory = ButtonFactory(self)
        self.init_ui()
        self.load_notes()

    def init_ui(self):
        main_layout = QHBoxLayout(self)

        # Notes List
        self.notes_list = QListWidget()
        self.notes_list.itemClicked.connect(self.display_note)
        main_layout.addWidget(self.notes_list, 1)

        # Note Details
        details_layout = QVBoxLayout()

        # Title
        title_layout = QHBoxLayout()
        title_layout.addWidget(QLabel("Title:"))
        self.title_input = QLineEdit()
        title_layout.addWidget(self.title_input)
        details_layout.addLayout(title_layout)

        # Content
        details_layout.addWidget(QLabel("Content:"))
        self.content_input = QTextEdit()
        details_layout.addWidget(self.content_input)

        # Action Buttons
        buttons = [
            ("Add", 100, self.add_note),
            ("Update", 100, self.update_note),
            ("Delete", 100, self.delete_note),
        ]
        buttons_layout = self.button_factory.create_buttons_with_spacing(buttons)
        details_layout.addLayout(buttons_layout)

        # Status Label
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: green;")
        details_layout.addWidget(self.status_label)

        main_layout.addLayout(details_layout, 2)

    def load_notes(self):
        self.notes_list.clear()
        notes = get_all_secure_notes(self.conn)
        for note in notes:
            item = QListWidgetItem(note.title)
            item.setData(Qt.UserRole, note.id)
            self.notes_list.addItem(item)
        logger.debug("Loaded all secure notes into the UI.")

    def display_note(self, item: QListWidgetItem):
        note_id = item.data(Qt.UserRole)
        note = get_secure_note_by_id(self.conn, note_id)
        if note:
            self.selected_note_id = note.id
            self.title_input.setText(note.title)
            self.content_input.setPlainText(note.content)
            logger.debug(f"Displayed note ID {note.id} in the UI.")
        else:
            self.clear_inputs()
            CustomMessageBox(
                "Error",
                "Failed to load the selected note.",
                QMessageBox.Critical,
            ).show_message()
            logger.error(f"Failed to retrieve note ID {note_id}.")

    def add_note(self):
        title = self.title_input.text().strip()
        content = self.content_input.toPlainText().strip()
        if not title or not content:
            self.show_message(
                "Warning", "Title and content cannot be empty.", QMessageBox.Warning
            )
            return
        try:
            add_secure_note(self.conn, title, content)
            self.load_notes()
            self.clear_inputs()
            self.status_label.setText("Note added successfully.")
            logger.info(f"Added new secure note with title: {title}")
        except Exception as e:
            self.show_message("Error", f"Failed to add note: {e}", QMessageBox.Critical)
            logger.error(f"Failed to add secure note: {e}")

    def update_note(self):
        if self.selected_note_id is None:
            self.show_message(
                "Warning", "Please select a note to update.", QMessageBox.Warning
            )
            return
        title = self.title_input.text().strip()
        content = self.content_input.toPlainText().strip()
        if not title or not content:
            self.show_message(
                "Warning", "Title and content cannot be empty.", QMessageBox.Warning
            )
            return
        try:
            update_secure_note(self.conn, self.selected_note_id, title, content)
            self.load_notes()
            self.status_label.setText("Note updated successfully.")
            logger.info(f"Updated secure note ID: {self.selected_note_id}")
        except Exception as e:
            self.show_message(
                "Error", f"Failed to update note: {e}", QMessageBox.Critical
            )
            logger.error(
                f"Failed to update secure note ID {self.selected_note_id}: {e}"
            )

    def delete_note(self):
        if self.selected_note_id is None:
            self.show_message(
                "Warning", "Please select a note to delete.", QMessageBox.Warning
            )
            return
        reply = QMessageBox.question(
            self,
            "Confirm Deletion",
            "Are you sure you want to delete this note?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            try:
                delete_secure_note(self.conn, self.selected_note_id)
                self.load_notes()
                self.clear_inputs()
                self.status_label.setText("Note deleted successfully.")
                logger.info(f"Deleted secure note ID: {self.selected_note_id}")
                self.selected_note_id = None
            except Exception as e:
                self.show_message(
                    "Error", f"Failed to delete note: {e}", QMessageBox.Critical
                )
                logger.error(
                    f"Failed to delete secure note ID {self.selected_note_id}: {e}"
                )

    def clear_inputs(self):
        self.title_input.clear()
        self.content_input.clear()

    def show_message(self, title, message, icon=QMessageBox.Information):
        CustomMessageBox(title, message, icon).show_message()
