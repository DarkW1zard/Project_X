import sys
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QTabWidget,
    QAction,
    QFileDialog,
    QTextEdit,
    QMessageBox,
    QBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QDialog,
)
import pickle
from hashlib import md5
import configparser
import os
import sys
from cryptography.fernet import Fernet


class PasswordDialog(QDialog):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle("Password Required")
        layout = QVBoxLayout()

        self.password_label = QLabel("Enter Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        self.ok_button = QPushButton("OK")

        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.ok_button)

        self.ok_button.clicked.connect(self.check_password)

        self.setLayout(layout)

    def check_password(self):
        password = self.password_input.text()
        if (
            md5(password.encode("utf-8")).hexdigest()
            == "02cf2584030d5a6d6fb29439b6a6ef2f"
        ):
            self.accept()
        else:
            QMessageBox.warning(
                self, "Invalid Password", "The entered password is incorrect."
            )
            self.password_input.clear()


class NoteTakingApp(QMainWindow):
    def __init__(self):
        super().__init__()

        # Password authentication
        self.password_dialog = PasswordDialog()
        if self.password_dialog.exec_() == QDialog.Accepted:
            self.initUI()
            self.key = generate_or_read_key()
        else:
            sys.exit()

    def initUI(self):
        # Create a menu and toolbar for actions
        menu = self.menuBar()
        file_menu = menu.addMenu("File")
        edit_menu = menu.addMenu("Edit")

        new_note_action = QAction("New Note", self)
        open_note_action = QAction("Open Note", self)
        save_note_action = QAction("Save Note", self)
        save_as_action = QAction("Save Note As", self)

        file_menu.addAction(new_note_action)
        file_menu.addAction(open_note_action)
        file_menu.addAction(save_note_action)
        file_menu.addAction(save_as_action)

        # Create a tab widget to work with multiple notes
        self.tabs = QTabWidget(self)
        self.setCentralWidget(self.tabs)

        # Connect actions to functions

        new_note_action.triggered.connect(self.new_note)
        open_note_action.triggered.connect(self.open_note)
        save_note_action.triggered.connect(self.save_note)
        save_as_action.triggered.connect(self.save_as)

    def new_note(self):
        new_note_widget = QTextEdit()  # Use QTextEdit for rich text formatting
        self.tabs.addTab(new_note_widget, "Untitled Note")
        self.tabs.setCurrentWidget(new_note_widget)

    def open_note(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "Open Note",
            "",
            "Note Files (*.notes);;All Files (*)",
            options=options,
        )
        if file_name:
            with open(file_name, "rb") as file:
                data = pickle.load(file)
                new_note_widget = QTextEdit()
                new_note_widget.setPlainText(data)
                self.tabs.addTab(new_note_widget, file_name)
                self.tabs.setCurrentWidget(new_note_widget)

    def save_note(self):
        current_tab = self.tabs.currentWidget()
        if current_tab:
            if self.tabs.tabText(self.tabs.indexOf(current_tab)) == "Untitled Note":
                self.save_as()
            else:
                file_name = self.tabs.tabText(self.tabs.indexOf(current_tab))
                note_content = current_tab.toPlainText()
                encrypted_data = self.encrypt(note_content, self.key)
                with open(file_name, "wb") as file:
                    pickle.dump(encrypted_data, file)

    def save_as(self):
        current_tab = self.tabs.currentWidget()
        if current_tab:
            options = QFileDialog.Options()
            file_name, _ = QFileDialog.getSaveFileName(
                self,
                "Save Note As",
                "",
                "Note Files (*.notes);;All Files (*)",
                options=options,
            )
            if file_name:
                note_content = current_tab.toPlainText()
                encrypted_data = self.encrypt(note_content, self.key)
                with open(file_name, "wb") as file:
                    pickle.dump(encrypted_data, file)
                self.tabs.setTabText(self.tabs.indexOf(current_tab), file_name)


    def open_note(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(
            self, "Open Note", "", "Note Files (*.notes);;All Files (*)", options=options
        )
        if file_name:
            with open(file_name, "rb") as file:
                encrypted_data = pickle.load(file)
                decrypted_data = self.decrypt(encrypted_data, self.key)
                if decrypted_data is not None:
                    new_note_widget = QTextEdit()
                    new_note_widget.setPlainText(decrypted_data)
                    self.tabs.addTab(new_note_widget, file_name)
                    self.tabs.setCurrentWidget(new_note_widget)
                else:
                    QMessageBox.critical(
                        self,
                        "Erreur de Déchiffrement",
                        "La clé de déchiffrement est incorrecte. Le fichier ne peut pas être déchiffré.",
                        "Vérifiez votre fichier config.cfg",
                )

    def encrypt(self, data, key):
        cipher_suite = Fernet(key)
        encrypted_data = cipher_suite.encrypt(data.encode())
        return encrypted_data

    def decrypt(self, data, key):
        try:
            cipher_suite = Fernet(key)
            decrypted_data = cipher_suite.decrypt(data).decode()
            return decrypted_data
        except Exception as e:
            return None  # Retourne None si la clé est incorrecte


def generate_or_read_key():
    if not os.path.exists("config.cfg"):
        # First run, generate a new key and save it
        key = Fernet.generate_key()
        save_key_to_config_file(key)
    else:
        # Configuration file exists, read the key
        key = read_key_from_config_file()
    return key


def save_key_to_config_file(key):
    config = configparser.ConfigParser()
    config["Encryption"] = {"SecretKey": key.decode()}
    with open("config.cfg", "w") as configfile:
        config.write(configfile)


def read_key_from_config_file():
    config = configparser.ConfigParser()
    config.read("config.cfg")
    return config["Encryption"]["SecretKey"].encode()


def main():
    app = QApplication(sys.argv)
    ex = NoteTakingApp()
    ex.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
