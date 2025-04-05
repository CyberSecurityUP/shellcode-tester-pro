from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLabel, QApplication
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt
import sys

class LanguageSelector(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Choose Language")
        self.setFixedSize(300, 200)
        self.setStyleSheet("background-color: #1e1e1e; color: white;")

        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)

        label = QLabel("Select your language / Selecione o idioma")
        label.setFont(QFont("Arial", 12, QFont.Bold))
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)

        btn_en = QPushButton("🇺🇸 English")
        btn_en.setStyleSheet("padding: 10px; font-weight: bold;")
        btn_en.clicked.connect(self.open_english)
        layout.addWidget(btn_en)

        btn_pt = QPushButton("🇧🇷 Português")
        btn_pt.setStyleSheet("padding: 10px; font-weight: bold;")
        btn_pt.clicked.connect(self.open_portuguese)
        layout.addWidget(btn_pt)

        self.setLayout(layout)

    def open_english(self):
        from main_gui_en import ShellcodeTesterPro
        self.main = ShellcodeTesterPro()
        self.main.show()
        self.close()

    def open_portuguese(self):
        from main_gui_pt_br import ShellcodeTesterPro
        self.main = ShellcodeTesterPro()
        self.main.show()
        self.close()
