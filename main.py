import sys
import os
import json
import string
import secrets

import hashlib


from PyQt6.QtCore import Qt
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QPoint, QTimer
from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton, QLabel, QWidget, QVBoxLayout, QLineEdit \
    , QFrame, QMessageBox, QProgressBar, QDialog, QFileDialog, QListView, QAbstractItemView, QTableWidget \
    , QTableWidgetItem, QHBoxLayout, QStackedWidget, QGroupBox, QMenu
from PyQt6.QtGui import QDragEnterEvent, QDropEvent, QIcon, QAction, QStandardItemModel, QStandardItem, QPixmap, \
    QFontMetrics, QCursor

from cryptcrro.symetric import crro as scrro

import qdarkstyle

if not os.path.isfile("./parameters.json"):
    default_data = {"last_database":"", "dark_mode": False}
    with open("./parameters.json", "w") as file:
        json.dump(default_data, file)


def password_hashing(password):
    return hashlib.scrypt(
        password.encode(),
        salt=b"CryptCrroSalt",
        n=2 ** 14,
        r=8,
        p=1,
        dklen=32
    )


def try_except(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            print(f"Une exception s'est produite : {e}")

    return wrapper


class QPasswordLineEdit(QLineEdit):
    def __init__(self, parent=None, dark_mode=False):
        super().__init__(parent)
        self.dark_mode = dark_mode
        self.setEchoMode(QLineEdit.EchoMode.Password)
        self.update_icons()

        self.showPassAction = QAction(self.iconShow, 'Show password', self)
        self.addAction(self.showPassAction, QLineEdit.ActionPosition.TrailingPosition)
        self.showPassAction.setCheckable(True)
        self.showPassAction.toggled.connect(self.toggle_password_visibility)

    def update_icons(self):
        if self.dark_mode:
            self.iconShow = QIcon('img/eye_white_blind.png')
            self.iconHide = QIcon('img/eye_white.png')
        else:
            self.iconShow = QIcon('img/eye_blind.png')
            self.iconHide = QIcon('img/eye.png')

    def toggle_password_visibility(self, show):
        if show:
            self.setEchoMode(QLineEdit.EchoMode.Normal)
            self.showPassAction.setIcon(self.iconHide)
        else:
            self.setEchoMode(QLineEdit.EchoMode.Password)
            self.showPassAction.setIcon(self.iconShow)

    def set_dark_mode(self, dark_mode):
        self.dark_mode = dark_mode
        self.update_icons()
        if self.echoMode() == QLineEdit.EchoMode.Password:
            self.showPassAction.setIcon(self.iconShow)
        else:
            self.showPassAction.setIcon(self.iconHide)


class NewDataBase(QDialog):
    def __init__(self, parent=None, dark_mode=False):
        super().__init__(parent)
        self.setWindowTitle("Choose the Name of the DataBase")
        self.setWindowIcon(QIcon("img/logo.png"))
        self.decrypted_data_current_databasebase_name = ""
        self.file_path = ""
        self.key = b""

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.label = QLabel("Name for the DataBase:")
        self.input = QLineEdit()

        self.label2 = QLabel("Confirm Password:")
        self.confirm_password = QPasswordLineEdit(dark_mode=dark_mode)


        self.bouton = QPushButton("Next")
        self.bouton.clicked.connect(self.next_step)

        self.layout.addWidget(self.label)
        self.layout.addWidget(self.input)
        self.label2.hide()
        self.layout.addWidget(self.label2)
        self.confirm_password.hide()
        self.layout.addWidget(self.confirm_password)
        self.layout.addWidget(self.bouton)

        self.step = 1  # Étape 1 = nom BDD, Étape 2 = mot de passe

    @try_except
    def next_step(self, Event=None):
        if self.step == 1:
            if not self.input.text():
                QMessageBox.warning(self, "Error", "Please enter a Name for the DataBase.")
                return
            self.database_name = self.input.text()
            self.ask_password()
        elif self.step == 2:
            if self.input.text() != self.confirm_password.text():
                QMessageBox.warning(self, "Error", "Password are not the same.")
                return
            if not self.input.text():
                QMessageBox.warning(self, "Error", "Please enter a Password.")
                return
            self.password = self.input.text()

            self.file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Choose a Directory",
                f"{self.database_name}.crod",
                "Crro DataBase (*.crod);;All File (*)"
            )
            if not self.file_path:
                QMessageBox.information(self, "Error", "No Directory Set.")

            self.key = password_hashing(self.password)

            with open(self.file_path, "wb") as file:
                file.write(scrro.encrypt(self.key, b""))

            self.accept()

    def ask_password(self, Event=None):
        self.setWindowTitle("Choose the Password")
        self.step = 2
        self.label.setText(f"DataBase : {self.decrypted_data_current_databasebase_name}\n\nEnter a password :")
        self.input.clear()
        self.input.setEchoMode(QLineEdit.EchoMode.Password)
        self.label2.show()
        self.confirm_password.show()
        self.bouton.setText("Ok")

class AskPassword(QDialog):
    def __init__(self, parent=None, dark_mode=False):
        super().__init__(parent)
        self.setWindowTitle('Password')
        self.setWindowIcon(QIcon("img/logo.png"))
        self.password = ""

        layout = QVBoxLayout()
        self.setLayout(layout)

        self.label = QLabel('Password:', self)
        layout.addWidget(self.label)
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.input_field = QPasswordLineEdit(self, dark_mode=dark_mode)
        self.input_field.setMinimumWidth(200)
        layout.addWidget(self.input_field)


        self.ok_button = QPushButton('Ok', self)
        layout.addWidget(self.ok_button)

        layout.setContentsMargins(10, 40, 10, 50)

        self.ok_button.clicked.connect(self.close)

    def close(self, checked=False):
        self.password = self.input_field.text()
        self.accept()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CrroPass")
        self.setWindowIcon(QIcon("img/logo.png"))
        self.setGeometry(100, 100, 670, 400)
        self.file_path_current_database = "./test.crod"
        self.decrypted_data_current_database = []
        self.password_visible = False
        self.password_hash = b""

        with open("./parameters.json", "r") as file:
            data = json.load(file)

        self.last_database = data.get("last_database")
        self.dark_mode = data.get("dark_mode")
        if self.dark_mode:
            app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt6())
        else:
            self.dark_mode = False

        self.init_ui()

    def init_ui(self):
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.layout = QVBoxLayout(self.central_widget)
        self.central_widget.setLayout(self.layout)

        self.stack = QStackedWidget()
        self.layout.addWidget(self.stack)

        bar = self.menuBar()

        file_menu = bar.addMenu("File")

        new_data_base_action = QAction('New data base', self)
        file_menu.addAction(new_data_base_action)
        new_data_base_action.triggered.connect(self.create_new_database)

        open_data_base_action = QAction('open data base', self)
        file_menu.addAction(open_data_base_action)
        open_data_base_action.triggered.connect(self.ask_and_open_database)

        parameters_menu = bar.addMenu("Parameters")

        toggle_darke_mode_action = QAction("toggle dark mode", self)
        parameters_menu.addAction(toggle_darke_mode_action)
        toggle_darke_mode_action.triggered.connect(self.toggle_dark_mode)

        file_name = self.file_path_current_database.removesuffix(".crod")

        # Home Page
        self.page_home = QWidget()
        self.layout_home = QVBoxLayout(self.page_home)

        pixmap = QPixmap('./img/logo.png')
        resized_pixmap = pixmap.scaled(75, 75, Qt.AspectRatioMode.KeepAspectRatio)

        self.label_welcome = QLabel()
        self.label_welcome.setPixmap(resized_pixmap)
        self.label_welcome.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout_home.addWidget(self.label_welcome)

        self.label_welcome = QLabel("<b>Welcome to CrroPass 0.1.0</b>")
        self.label_welcome.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout_home.addWidget(self.label_welcome)

        home_spacer = QLabel("")
        self.layout_home.addWidget(home_spacer)

        group_box = QGroupBox("Unlock last Database")
        group_layout = QVBoxLayout()
        group_box.setLayout(group_layout)

        screen = QApplication.primaryScreen()
        screen_geometry = screen.availableGeometry()
        half_width = screen_geometry.width() // 2

        group_box.setMaximumWidth(half_width)

        self.label_last_database = QLabel(self.last_database)
        self.label_last_database.setAlignment(Qt.AlignmentFlag.AlignCenter)
        group_layout.addWidget(self.label_last_database)

        self.password_form = QPasswordLineEdit(dark_mode=self.dark_mode)
        self.password_form.setMinimumWidth(half_width // 4)
        self.password_form.returnPressed.connect(self.open_last_database)

        group_layout.addWidget(self.password_form)

        self.layout_home_button = QHBoxLayout()
        self.layout_home_button.addStretch()
        group_layout.addLayout(self.layout_home_button)

        self.unlock_button = QPushButton("Unlock")
        self.unlock_button.clicked.connect(self.open_last_database)
        self.unlock_button.setFocus()

        self.layout_home_button.addWidget(self.unlock_button)

        self.browse_button = QPushButton("Browse for Database")
        self.browse_button.clicked.connect(self.ask_and_open_database)
        self.layout_home_button.addWidget(self.browse_button)

        if not self.last_database:
            self.label_last_database.hide()

        group_box_layout = QHBoxLayout()
        group_box_layout.addStretch()
        group_box_layout.addWidget(group_box)
        group_box_layout.addStretch()
        self.layout_home.addLayout(group_box_layout)

        self.stack.addWidget(self.page_home)

        self.layout_home.addStretch()

        # Table Page
        self.page_table = QWidget()
        self.layout_table = QVBoxLayout(self.page_table)

        self.label_current_database = QLabel(f"Current DataBase :   <b>{os.path.basename(file_name)}</b>")
        self.label_current_database.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.layout_table.addWidget(self.label_current_database)

        self.add_button = QPushButton("+")
        self.add_button.setMaximumWidth(80)
        self.layout_table.addWidget(self.add_button)
        self.add_button.clicked.connect(self.new_website)

        self.table = QTableWidget()
        text_reference = "example_email@crro.com"
        font = self.table.font()
        metrics = QFontMetrics(font)
        text_width = metrics.horizontalAdvance(text_reference) + 20
        self.table.setColumnCount(4)
        self.table.setColumnWidth(0, text_width - 20)
        self.table.setColumnWidth(1, text_width)
        self.table.setColumnWidth(3, text_width)
        self.table.setHorizontalHeaderLabels(["Title", "Username", "Password", "Website"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.table.cellDoubleClicked.connect(self.on_row_double_clicked)

        self.layout_table.addWidget(self.table)
        self.stack.addWidget(self.page_table)

        # Form Page
        self.page_form = QWidget()
        self.layout_form = QVBoxLayout(self.page_form)

        self.label_current_database2 = QLabel(f"Current DataBase :   <b>{os.path.basename(file_name)}</b>")
        self.label_current_database2.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.layout_form.addWidget(self.label_current_database2)

        spacer = QLabel("")
        self.layout_form.addWidget(spacer)

        group_box = QGroupBox("New Entry Information")
        group_layout = QVBoxLayout()
        group_box.setLayout(group_layout)

        self.label_title = QLabel("Title: ")
        self.label_title.setAlignment(Qt.AlignmentFlag.AlignTop)
        group_layout.addWidget(self.label_title)
        self.line_title = QLineEdit()
        self.line_title.setAlignment(Qt.AlignmentFlag.AlignTop)
        group_layout.addWidget(self.line_title)

        self.label_username = QLabel("Username: ")
        self.label_username.setAlignment(Qt.AlignmentFlag.AlignTop)
        group_layout.addWidget(self.label_username)
        self.line_username = QLineEdit()
        self.line_username.setAlignment(Qt.AlignmentFlag.AlignTop)
        group_layout.addWidget(self.line_username)

        self.layout_password = QHBoxLayout()

        self.label_Password = QLabel("Password: ")
        self.label_Password.setAlignment(Qt.AlignmentFlag.AlignTop)

        group_layout.addWidget(self.label_Password)
        self.line_password = QPasswordLineEdit(dark_mode=self.dark_mode)
        self.line_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.line_password.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.layout_password.addWidget(self.line_password)

        self.generate_password_button = QPushButton("generate")
        self.generate_password_button.clicked.connect(self.generate_and_put_password)
        self.layout_password.addWidget(self.generate_password_button)

        # group_layout.addWidget(self.line_password)

        group_layout.addLayout(self.layout_password)

        self.label_website = QLabel("website: ")
        self.label_website.setAlignment(Qt.AlignmentFlag.AlignTop)
        group_layout.addWidget(self.label_website)
        self.line_website = QLineEdit()
        self.line_website.setAlignment(Qt.AlignmentFlag.AlignTop)
        group_layout.addWidget(self.line_website)

        self.layout_button = QHBoxLayout()
        self.layout_button.addStretch()
        group_layout.addLayout(self.layout_button)

        self.ok_button = QPushButton("Ok")
        self.ok_button.setMinimumWidth(50)
        self.ok_button.clicked.connect(self.save_new_entry)
        self.layout_button.addWidget(self.ok_button)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setMinimumWidth(50)
        self.cancel_button.clicked.connect(self.cancel)
        self.layout_button.addWidget(self.cancel_button)

        self.layout_form.addWidget(group_box)  # End of the rectangle

        self.stack.addWidget(self.page_form)

        self.layout_form.addStretch()  # too push everythings to the top

        # Set the good page
        self.stack.setCurrentWidget(self.page_home)

        self.read_database_info()

    def generate_crypt_password(self, length=12):

        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = string.punctuation

        password_chars = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]

        all_chars = lowercase + uppercase + digits + special
        password_chars += [secrets.choice(all_chars) for _ in range(length - 4)]

        secrets.SystemRandom().shuffle(password_chars)

        return ''.join(password_chars)

    def delete_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.clear()

    @try_except
    def generate_and_put_password(self, Event=None):
        password = self.generate_crypt_password(22)
        self.line_password.setText(password)


    def read_database_info(self):
        file_name = self.file_path_current_database.removesuffix(".crod")
        self.label_current_database.setText(f"Current DataBase :   <b>{os.path.basename(file_name)}</b>")
        self.label_current_database2.setText(f"Current DataBase :   <b>{os.path.basename(file_name)}</b>")
        self.table.setRowCount(0)

        for user in self.decrypted_data_current_database:
            self.add_row(user.get("title"), user.get("username"), user.get("url"))

    def add_row(self, title, username, website):
        password = "*****************"
        row = self.table.rowCount()
        self.table.insertRow(row)

        icon = QIcon("./img/key_icon.png")

        item_with_icon = QTableWidgetItem(title)
        item_with_icon.setIcon(icon)
        item_with_icon.setFlags(item_with_icon.flags() ^ Qt.ItemFlag.ItemIsEditable)
        self.table.setItem(row, 0, item_with_icon)

        for col, value in enumerate([username, password, website], start=1):
            item = QTableWidgetItem(value)
            item.setFlags(item.flags() ^ Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row, col, item)

    @try_except
    def show_context_menu(self, pos: QPoint):
        item = self.table.itemAt(pos)
        if item is None:
            return

        row = item.row()

        menu = QMenu(self)

        username = self.table.item(row, 1).text()
        password = self.decrypted_data_current_database[row].get("password")
        website = self.table.item(row, 3).text()

        action_copy_pass = QAction("Copy Password", self)
        action_copy_user = QAction("Copy Username", self)
        action_copy_site = QAction("Copy Website", self)

        action_delete = QAction("Delete Entry", self)

        action_copy_user.triggered.connect(lambda: self.copy_to_clipboard(username))
        action_copy_pass.triggered.connect(lambda: self.copy_and_delete_clipboard(password))
        action_copy_site.triggered.connect(lambda: self.copy_to_clipboard(website))
        action_delete.triggered.connect(lambda: self.delete_entry(item.row()))

        menu.addAction(action_copy_pass)
        menu.addAction(action_copy_user)
        menu.addAction(action_copy_site)
        menu.addSeparator()
        menu.addAction(action_delete)

        menu.exec(QCursor.pos())

    def on_row_double_clicked(self, row, column):

        title = self.table.item(row, 0).text()
        username = self.table.item(row, 1).text()
        password = self.table.item(row, 2).text()
        website = self.table.item(row, 3).text()

        QMessageBox.information(
            self, "Informations",
            f"Title: {title}\nUsername: {username}\nPassword: {password}\nWebsite: {website}"
        )


    def delete_entry(self, row):
        title = self.table.item(row, 0).text()
        response = QMessageBox.information(self, "Verification", f"Do you really want to delete {title}"
                                             , QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

        if response == QMessageBox.StandardButton.Yes:
            del self.decrypted_data_current_database[row]
            self.save_database()
            self.read_database_info()
        else:
            return

    def save_database(self):

        encrypted_database = scrro.encrypt(self.password_hash, str(self.decrypted_data_current_database).encode())
        with open(self.file_path_current_database, "wb") as file:
            file.write(encrypted_database)


    def copy_and_delete_clipboard(self, text: str):
        self.copy_to_clipboard(text)
        QTimer.singleShot(10000, self.delete_clipboard)

    def copy_to_clipboard(self, text: str):
        clipboard = QApplication.clipboard()
        clipboard.setText(text)

    @try_except
    def create_new_database(self, Event=None):
        dialog = NewDataBase(self, self.dark_mode)
        if dialog.exec():
            QMessageBox.information(
                self, "Successfully create the Database",
                f"Successfully create the Database: {dialog.database_name}"
            )
        self.open_database(dialog.file_path, dialog.key)

    def open_last_database(self):
        password = self.password_form.text()
        password_hash = password_hashing(password)
        self.open_database(self.last_database, password_hash)

    def ask_and_open_database(self):

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Choose a DataBase",
            "",
            "Crro DataBase (*.crod);;All File (*)"
        )

        if not file_path:
            return

        dialog = AskPassword(self, self.dark_mode)
        dialog.exec()
        password = dialog.password
        self.password_hash = password_hashing(password)

        self.open_database(file_path, self.password_hash)

    @try_except
    def open_database(self, file_path, password_hash, Event=None):
        self.password_hash = password_hash
        self.file_path_current_database = file_path
        self.decrypted_data_current_database = self.decrypt_database(self.password_hash, file_path)

        self.read_database_info()
        self.save_last_database()
        self.table_page()

    def decrypt_database(self, key, file_path):
        with open(file_path, "rb") as file:
            data = file.read()
        decrypted_data = scrro.decrypt(key, data).decode()
        if decrypted_data:
            return eval(decrypted_data)
        return []

    def save_last_database(self):
        with open("./parameters.json", "r", encoding='utf-8') as file:
            data = dict(json.load(file))

        data["last_database"] = self.file_path_current_database

        with open("./parameters.json", "w", encoding='utf-8') as file:
            json.dump(data, file)

    def save_dark_mode(self):
        with open("./parameters.json", "r", encoding='utf-8') as file:
            data = dict(json.load(file))

        data["dark_mode"] = self.dark_mode

        with open("./parameters.json", "w", encoding='utf-8') as file:
            json.dump(data, file)
    @try_except
    def new_website(self, Event=None):
        self.stack.setCurrentWidget(self.page_form)

    def table_page(self, Event=None):
        self.stack.setCurrentWidget(self.page_table)

    def home_page(self, Event=None):
        self.stack.setCurrentWidget(self.page_home)

    @try_except
    def save_new_entry(self, Event=None):

        title = self.line_title.text()
        username = self.line_username.text()
        password = self.line_password.text()
        url = self.line_website.text()

        if not title.strip() or not username.strip() or not password.strip() or not url.strip():
            QMessageBox.warning(self, "Error", "Please fill out all the Forms.")
            return

        new_data = {"title": title, "username": username, "password": password, "url": url}

        self.decrypted_data_current_database.append(new_data)

        encrypted_database = scrro.encrypt(self.password_hash, str(self.decrypted_data_current_database).encode())

        with open(self.file_path_current_database, "wb") as file:
            file.write(encrypted_database)

        self.read_database_info()
        self.cancel()

    def toggle_dark_mode(self):
        if self.dark_mode:
            app.setStyleSheet("")
        else:
            app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt6())
        self.dark_mode = not self.dark_mode
        self.save_dark_mode()

        for widget in self.findChildren(QPasswordLineEdit):
            widget.set_dark_mode(self.dark_mode)


    def cancel(self):
        self.line_title.clear()
        self.line_username.clear()
        self.line_password.clear()
        self.line_website.clear()
        self.table_page()


app = QApplication(sys.argv)
window = MainWindow()
window.show()
app.exec()
