import os
import subprocess
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QTextEdit, QPushButton, QLabel, QFileDialog, QHBoxLayout
)

class NASMShellPlugin(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("NASM Shell Plugin")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.asm_input = QTextEdit()
        self.asm_input.setPlaceholderText("Escreva seu shellcode em NASM (x86 ou x64)")
        layout.addWidget(QLabel("Código Assembly:"))
        layout.addWidget(self.asm_input)

        button_layout = QHBoxLayout()

        self.compile_btn = QPushButton("Montar com NASM")
        self.compile_btn.clicked.connect(self.compile_asm)
        button_layout.addWidget(self.compile_btn)

        self.export_btn = QPushButton("Exportar .bin")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self.export_bin)
        button_layout.addWidget(self.export_btn)

        layout.addLayout(button_layout)

        self.asm_output = QTextEdit()
        self.asm_output.setReadOnly(True)
        layout.addWidget(QLabel("Shellcode em formato hexadecimal:"))
        layout.addWidget(self.asm_output)

        self.setLayout(layout)
        self.compiled_path = ""

    def compile_asm(self):
        asm_code = self.asm_input.toPlainText().strip()
        if not asm_code:
            self.asm_output.setText("[!] Nenhum código fornecido.")
            return

        try:
            temp_asm = "temp_shell.asm"
            temp_bin = "temp_shell.bin"

            with open(temp_asm, "w") as f:
                f.write(asm_code)

            result = subprocess.run(
                ["nasm", "-f", "bin", "-o", temp_bin, temp_asm],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if result.returncode != 0:
                self.asm_output.setText(f"[!] Erro de montagem: {result.stderr}")
                return

            with open(temp_bin, "rb") as f:
                raw = f.read()
                hex_shell = ''.join(f"\\x{b:02x}" for b in raw)
                self.asm_output.setText(hex_shell)

            self.compiled_path = os.path.abspath(temp_bin)
            self.export_btn.setEnabled(True)

        except Exception as e:
            self.asm_output.setText(f"[!] Erro: {str(e)}")

    def export_bin(self):
        if not os.path.exists(self.compiled_path):
            self.asm_output.setText("[!] Nenhum arquivo compilado para exportar.")
            return

        out_path, _ = QFileDialog.getSaveFileName(self, "Salvar shellcode compilado", "shellcode.bin", "Binário (*.bin)")
        if out_path:
            try:
                with open(self.compiled_path, "rb") as src, open(out_path, "wb") as dst:
                    dst.write(src.read())
                self.asm_output.append(f"[+] Shellcode exportado para: {out_path}")
            except Exception as e:
                self.asm_output.append(f"[!] Erro ao exportar: {str(e)}")


def register(main_app):
    tab = NASMShellPlugin()
    main_app.tabs.addTab(tab, "NASM Shell")
    return tab
