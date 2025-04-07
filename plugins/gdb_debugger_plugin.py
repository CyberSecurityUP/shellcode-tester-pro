from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QPushButton, QLabel, QFileDialog, QHBoxLayout
from PyQt5.QtCore import QProcess
import os

def register(app):
    tab = QWidget()
    layout = QVBoxLayout()

    terminal_label = QLabel("🔧 GDB Debugger Shell (ELF, BIN, EXE)")
    terminal_label.setStyleSheet("color: cyan; font-weight: bold;")
    layout.addWidget(terminal_label)

    gdb_output = QTextEdit()
    gdb_output.setReadOnly(True)
    gdb_output.setStyleSheet("background-color: black; color: #00FF00; font-family: monospace;")
    layout.addWidget(gdb_output)

    gdb_input = QTextEdit()
    gdb_input.setPlaceholderText("Digite comandos GDB aqui e pressione Enter ou use os botões abaixo...")
    gdb_input.setStyleSheet("background-color: #111; color: white; font-family: monospace;")
    gdb_input.setFixedHeight(60)
    layout.addWidget(gdb_input)

    command_layout = QHBoxLayout()
    load_btn = QPushButton("📂 Carregar Executável")
    run_btn = QPushButton("▶️ run")
    info_btn = QPushButton("ℹ️ info functions")
    disas_btn = QPushButton("🧠 disassemble main")
    break_btn = QPushButton("⛔ break main")

    for btn in [run_btn, info_btn, disas_btn, break_btn]:
        command_layout.addWidget(btn)

    layout.addWidget(load_btn)
    layout.addLayout(command_layout)

    tab.setLayout(layout)
    app.tabs.addTab(tab, "🛠 GDB Debugger")

    process = QProcess()
    binary_loaded = {'path': None}

    def run_gdb_command(command):
        if not binary_loaded['path']:
            gdb_output.append("[!] Nenhum arquivo carregado.")
            return
        gdb_output.append(f">>> {command}")
        process.write((command + "\n").encode())

    def load_executable():
        file, _ = QFileDialog.getOpenFileName(None, "Selecionar binário", "", "Executáveis (*.elf *.bin *.exe *.out)")
        if file:
            binary_loaded['path'] = file
            gdb_output.append(f"[+] Carregado: {file}")
            process.start("gdb", [file])
            process.readyReadStandardOutput.connect(lambda: gdb_output.append(process.readAllStandardOutput().data().decode()))
            process.readyReadStandardError.connect(lambda: gdb_output.append(process.readAllStandardError().data().decode()))

    def execute_input():
        command = gdb_input.toPlainText().strip()
        if command:
            run_gdb_command(command)
            gdb_input.clear()

    load_btn.clicked.connect(load_executable)
    run_btn.clicked.connect(lambda: run_gdb_command("run"))
    info_btn.clicked.connect(lambda: run_gdb_command("info functions"))
    disas_btn.clicked.connect(lambda: run_gdb_command("disassemble main"))
    break_btn.clicked.connect(lambda: run_gdb_command("break main"))
    gdb_input.textChanged.connect(lambda: execute_input() if "\n" in gdb_input.toPlainText() else None)