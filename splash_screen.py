from PyQt5.QtWidgets import QWidget, QLabel, QVBoxLayout, QApplication, QProgressBar
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont, QColor, QPalette

class SplashScreen(QWidget):
    def __init__(self):
        super().__init__()
        self.setFixedSize(500, 300)
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAutoFillBackground(True)

        # Dark theme
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(20, 20, 20))
        self.setPalette(palette)

        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)

        self.title = QLabel("💉 Shellcode Tester Pro")
        self.title.setFont(QFont("Arial", 20, QFont.Bold))
        self.title.setStyleSheet("color: #00ffff;")
        layout.addWidget(self.title)

        self.status = QLabel("Loading modules...")
        self.status.setStyleSheet("color: white; font-size: 12px;")
        layout.addWidget(self.status)

        self.progress = QProgressBar()
        self.progress.setMaximum(100)
        self.progress.setTextVisible(False)
        self.progress.setStyleSheet("""
            QProgressBar {
                background-color: #222;
                border: 1px solid #555;
                height: 12px;
            }
            QProgressBar::chunk {
                background-color: #00ffaa;
            }
        """)
        layout.addWidget(self.progress)

        # Footer credits
        self.credits = QLabel("Created by Joas Antonio dos Santos © 2025")
        self.credits.setStyleSheet("color: #888; font-size: 10px;")
        self.credits.setAlignment(Qt.AlignRight)
        layout.addWidget(self.credits)

        self.setLayout(layout)

        self.counter = 0
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_progress)
        self.timer.start(50)

    def update_progress(self):
        self.counter += 2
        self.progress.setValue(self.counter)
        if self.counter > 100:
            self.timer.stop()
            self.close()
            self.launch_main_app()

    def launch_main_app(self):
        from language_selector import LanguageSelector
        self.selector = LanguageSelector()
        self.selector.show()
