
import logging
import os
import sys
import uuid

from blueprints import ButtonFactory, CustomMessageBox
from password_generation import PasswordGenerationTab
from password_management import PasswordManagementTab
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)