import os
import requests
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QPushButton, QFileDialog,
    QLineEdit, QTextEdit, QMessageBox
)
from PyQt5.QtCore import QTimer

class VirusTotalPlugin(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Integração VirusTotal")
        self.api_key = ""
        self.file_path = ""
        self.analysis_id = ""
        self.timer = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.api_input = QLineEdit()
        self.api_input.setPlaceholderText("Insira sua API Key do VirusTotal")
        layout.addWidget(QLabel("API Key:"))
        layout.addWidget(self.api_input)

        self.select_file_btn = QPushButton("Selecionar Arquivo")
        self.select_file_btn.clicked.connect(self.select_file)
        layout.addWidget(self.select_file_btn)

        self.send_btn = QPushButton("Enviar para Análise")
        self.send_btn.clicked.connect(self.send_to_virustotal)
        layout.addWidget(self.send_btn)

        self.result_output = QTextEdit()
        self.result_output.setReadOnly(True)
        layout.addWidget(QLabel("Resultado da Análise:"))
        layout.addWidget(self.result_output)

        self.setLayout(layout)

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Selecionar arquivo",
            "",
            "Arquivos Executáveis (*.bin *.exe *.dll *.elf *.out)"
        )
        if file_path:
            self.file_path = file_path
            self.result_output.append(f"[+] Arquivo selecionado: {file_path}")

    def send_to_virustotal(self):
        self.api_key = self.api_input.text().strip()
        if not self.api_key:
            self.result_output.setText("[!] API Key não fornecida.")
            return

        if not os.path.isfile(self.file_path):
            self.result_output.setText("[!] Nenhum arquivo selecionado ou caminho inválido.")
            return

        try:
            self.result_output.append("[*] Enviando arquivo para o VirusTotal...")
            url = "https://www.virustotal.com/api/v3/files"
            headers = {"x-apikey": self.api_key}
            with open(self.file_path, "rb") as f:
                files = {"file": f}
                response = requests.post(url, headers=headers, files=files)

            if response.status_code == 200:
                json_data = response.json()
                self.analysis_id = json_data.get("data", {}).get("id")
                self.result_output.append(f"[+] Envio bem-sucedido. ID da Análise: {self.analysis_id}")
                self.result_output.append("[*] Aguardando resultado da análise...")
                self.start_timer()
            else:
                self.result_output.append(f"[!] Falha no envio: {response.status_code} {response.text}")
        except Exception as e:
            self.result_output.append(f"[!] Erro ao enviar para o VirusTotal: {str(e)}")

    def start_timer(self):
        if self.timer:
            self.timer.stop()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.poll_analysis)
        self.timer.start(4000)  # a cada 4 segundos

    def poll_analysis(self):
        if not self.analysis_id:
            self.result_output.append("[!] ID de análise não disponível.")
            self.timer.stop()
            return

        url = f"https://www.virustotal.com/api/v3/analyses/{self.analysis_id}"
        headers = {"x-apikey": self.api_key}

        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                json_data = response.json()
                status = json_data.get("data", {}).get("attributes", {}).get("status")

                if status == "completed":
                    self.timer.stop()
                    stats = json_data["data"]["attributes"].get("stats", {})
                    self.result_output.append("\n[+] Análise Concluída:")
                    self.result_output.append(f"  ✅ Harmless: {stats.get('harmless', 0)}")
                    self.result_output.append(f"  ⚠️ Suspicious: {stats.get('suspicious', 0)}")
                    self.result_output.append(f"  ❌ Malicious: {stats.get('malicious', 0)}")
                else:
                    self.result_output.append("[*] Ainda processando...")

            else:
                self.timer.stop()
                self.result_output.append(f"[!] Erro ao verificar análise: {response.status_code}")

        except Exception as e:
            self.timer.stop()
            self.result_output.append(f"[!] Erro durante verificação: {str(e)}")

def register(main_app):
    tab = VirusTotalPlugin()
    main_app.tabs.addTab(tab, "VirusTotal")
