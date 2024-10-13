# frontend/secure_notes_tab.py

import logging

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QDialog,
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

from backend.database import (
    delete_secure_note,
    retrieve_secure_notes,
    store_secure_note,
    update_secure_note,
)
from frontend.blueprints import (
    ButtonFactory,
    CustomMessageBox,
    add_title_and_description,
)

logger = logging.getLogger(__name__)


class SecureNotesTab(QWidget):
    def __init__(self, conn, email, parent=None):
        """
        Initialize the SecureNotesTab.

        Args:
            conn (sqlite3.Connection): The database connection object.
            email (str): The user's email address.
            parent (QWidget, optional): The parent widget. Defaults to None.
        """
        super().__init__(parent)
        self.conn = conn
        self.email = email
        if not self.conn:
            CustomMessageBox(
                "Error",
                "Failed to connect to the database.",
                QMessageBox.Critical,
            ).show_message()
            logger.error("Database connection failed in SecureNotesTab.")
            return
        # Initialize UI components
        self.selected_note_id = None
        self.button_factory = ButtonFactory(self)
        self.init_ui()
        self.load_notes()

    def init_ui(self):
        """
        Set up the user interface for the SecureNotesTab.
        """
        main_layout = QHBoxLayout(self)

        # Notes List
        self.notes_list = QListWidget()
        self.notes_list.itemClicked.connect(self.display_note)
        main_layout.addWidget(self.notes_list, 1)

        # Note Details
        details_layout = QVBoxLayout()

        # Add title and description using the helper function
        add_title_and_description(
            details_layout,
            "Secure Notes",
            "Manage your secure notes efficiently and safely.",
        )

        # Title Input
        details_layout.addWidget(QLabel("Title:"))
        self.title_input = QLineEdit()
        self.title_input.setPlaceholderText("Enter note title")
        details_layout.addWidget(self.title_input)

        # Content Input
        details_layout.addWidget(QLabel("Content:"))
        self.content_input = QTextEdit()
        self.content_input.setPlaceholderText("Enter note content")
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
        """
        Load all secure notes from the database and display them in the notes list.
        """
        self.notes_list.clear()
        try:
            # Retrieve all secure notes for the user
            notes = retrieve_secure_notes(self.conn, self.email)
            for note in notes:
                # Assuming retrieve_secure_notes returns a list of tuples: (id, title, content)
                note_id, title, content = note
                item = QListWidgetItem(title)
                item.setData(Qt.UserRole, note_id)
                self.notes_list.addItem(item)
            logger.debug("Loaded all secure notes into the UI.")
        except Exception as e:
            logger.error(f"Error loading secure notes: {e}")
            self.show_warning("Failed to load secure notes.")

    def display_note(self, item: QListWidgetItem):
        """
        Display the selected note's title and content.

        Args:
            item (QListWidgetItem): The selected item in the notes list.
        """
        note_id = item.data(Qt.UserRole)
        try:
            # Retrieve all notes and find the one with the matching ID
            notes = retrieve_secure_notes(self.conn, self.email)
            note = next((n for n in notes if n[0] == note_id), None)
            if note:
                _, title, content = note
                self.selected_note_id = note_id
                self.title_input.setText(title)
                self.content_input.setPlainText(content)
                logger.debug(f"Displayed note ID {note_id} in the UI.")
            else:
                self.clear_inputs()
                CustomMessageBox(
                    "Error",
                    "Failed to load the selected note.",
                    QMessageBox.Critical,
                ).show_message()
                logger.error(f"Failed to retrieve note ID {note_id}.")
        except Exception as e:
            self.clear_inputs()
            self.show_warning("Failed to load the selected note.")
            logger.error(f"Error displaying note ID {note_id}: {e}")

    def add_note(self):
        """
        Add a new secure note to the database.
        """
        title = self.title_input.text().strip()
        content = self.content_input.toPlainText().strip()
        if not title or not content:
            self.show_message(
                "Warning", "Title and content cannot be empty.", QMessageBox.Warning
            )
            return
        try:
            store_secure_note(self.conn, self.email, title, content)
            self.load_notes()
            self.clear_inputs()
            self.status_label.setText("Note added successfully.")
            logger.info(f"Added new secure note with title: {title}")
        except Exception as e:
            self.show_message("Error", f"Failed to add note: {e}", QMessageBox.Critical)
            logger.error(f"Failed to add secure note: {e}")

    def update_note(self):
        """
        Update the selected secure note in the database.
        """
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
            update_secure_note(
                self.conn, self.email, self.selected_note_id, title, content
            )
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
        """
        Delete the selected secure note from the database.
        """
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
                delete_secure_note(self.conn, self.email, self.selected_note_id)
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
        """
        Clear the title and content input fields.
        """
        self.title_input.clear()
        self.content_input.clear()

    def show_message(self, title, message, icon=QMessageBox.Information):
        """
        Display a custom message box.

        Args:
            title (str): The title of the message box.
            message (str): The message content.
            icon (QMessageBox.Icon, optional): The icon type. Defaults to QMessageBox.Information.
        """
        CustomMessageBox(title, message, icon).show_message()

    def show_warning(self, message: str):
        """
        Display a warning message box.

        Args:
            message (str): The warning message.
        """
        CustomMessageBox("Warning", message, QMessageBox.Warning).show_message()


class ModifySecureNoteDialog(QDialog):
    def __init__(self, conn, email, note_id, parent=None):
        """
        Initialize the ModifySecureNoteDialog.

        Args:
            conn (sqlite3.Connection): The database connection object.
            email (str): The user's email address.
            note_id (int): The ID of the note to modify.
            parent (QWidget, optional): The parent widget. Defaults to None.
        """
        super().__init__(parent)
        self.conn = conn
        self.email = email
        self.note_id = note_id

        self.setWindowTitle("Modify Secure Note")
        self.setMinimumWidth(400)
        self.setWindowIcon(QIcon("frontend/icons/edit.png"))

        self.layout = QVBoxLayout(self)
        form_layout = QVBoxLayout()

        # Title Input
        form_layout.addWidget(QLabel("Title:"))
        self.title_input = QLineEdit()
        self.title_input.setPlaceholderText("Enter new title")
        form_layout.addWidget(self.title_input)

        # Content Input
        form_layout.addWidget(QLabel("Content:"))
        self.content_input = QTextEdit()
        self.content_input.setPlaceholderText("Enter new content")
        form_layout.addWidget(self.content_input)

        self.layout.addLayout(form_layout)

        # Action Buttons
        buttons = [
            ("Save", 100, self.save_changes),
            ("Cancel", 100, self.reject),
        ]
        button_factory = ButtonFactory(self)
        buttons_layout = button_factory.create_buttons_with_spacing(buttons)
        self.layout.addLayout(buttons_layout)

        self.load_note_details()

    def load_note_details(self):
        """
        Load the current details of the note into the input fields.
        """
        try:
            notes = retrieve_secure_notes(self.conn, self.email)
            note = next((n for n in notes if n[0] == self.note_id), None)
            if note:
                _, title, content = note
                self.title_input.setText(title)
                self.content_input.setPlainText(content)
                logger.debug(f"Loaded note ID {self.note_id} details into the dialog.")
            else:
                self.show_warning("Failed to load the selected note.")
                logger.error(f"Note ID {self.note_id} not found.")
                self.reject()
        except Exception as e:
            self.show_warning("Failed to load the selected note.")
            logger.error(f"Error loading note details for ID {self.note_id}: {e}")
            self.reject()

    def save_changes(self):
        """
        Save the updated note details to the database.
        """
        new_title = self.title_input.text().strip()
        new_content = self.content_input.toPlainText().strip()
        if not new_title or not new_content:
            self.show_warning("Title and content cannot be empty.")
            return
        try:
            update_secure_note(
                self.conn, self.email, self.note_id, new_title, new_content
            )
            logger.info(f"Updated secure note ID: {self.note_id}")
            self.accept()
        except Exception as e:
            self.show_warning(f"Failed to update note: {e}")
            logger.error(f"Failed to update secure note ID {self.note_id}: {e}")

    def show_warning(self, message: str):
        """
        Display a warning message box.

        Args:
            message (str): The warning message.
        """
        CustomMessageBox("Warning", message, QMessageBox.Warning).show_message()
