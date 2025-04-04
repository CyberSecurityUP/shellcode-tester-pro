# plugins/hello_plugin.py

def register(app):
    from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QPushButton, QLabel

    tab = QWidget()
    layout = QVBoxLayout()

    output = QTextEdit()
    output.setReadOnly(True)

    btn = QPushButton("Executar Plugin de Exemplo")
    btn.clicked.connect(lambda: output.setText("🎉 Plugin funcionando!"))

    layout.addWidget(QLabel("Plugin de exemplo: Hello Plugin"))
    layout.addWidget(btn)
    layout.addWidget(output)

    tab.setLayout(layout)
    app.tabs.addTab(tab, "Hello Plugin")
