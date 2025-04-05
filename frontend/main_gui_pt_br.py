import sys
import ctypes
import platform
import requests
from fpdf import FPDF
from PyQt5.QtWidgets import (
    QApplication, QWidget, QTabWidget, QVBoxLayout, QTextEdit, QPushButton,
    QLabel, QHBoxLayout, QFileDialog, QMessageBox, QLineEdit, QComboBox
)
from PyQt5.QtGui import QFont, QColor, QPalette
from PyQt5.QtCore import Qt
from unicorn import *
from unicorn.x86_const import *
from capstone import *  
import tempfile
import subprocess
import os
import importlib.util
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from plugins import plugin_manager_portuguese
import json
import re



class ShellcodeTesterProBr(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Shellcode Tester Pro")
        self.setGeometry(100, 100, 900, 700)
        self.set_dark_theme()
        self.dark_mode = True 
        self.init_ui()
        self.plugin_refs = {}  # Plugins carregados dinamicamente
        self.loaded_plugins = []  # Plugins já ativos
        self.suspect_shellcode = b""



    def set_dark_theme(self):
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(20, 20, 20))
        palette.setColor(QPalette.WindowText, Qt.white)
        palette.setColor(QPalette.Base, QColor(30, 30, 30))
        palette.setColor(QPalette.AlternateBase, QColor(45, 45, 45))
        palette.setColor(QPalette.ToolTipBase, Qt.white)
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, Qt.white)
        palette.setColor(QPalette.Button, QColor(53, 53, 53))
        palette.setColor(QPalette.ButtonText, Qt.white)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Highlight, QColor(142, 45, 197).lighter())
        palette.setColor(QPalette.HighlightedText, Qt.black)
        self.setPalette(palette)

    def init_ui(self):
        layout = QVBoxLayout()
        tabs = QTabWidget()

        toggle_theme_btn = QPushButton("Alternar Modo Claro/Escuro")
        toggle_theme_btn.clicked.connect(self.toggle_theme)
        layout.addWidget(toggle_theme_btn)

        # Botão de créditos (ícone de interrogação)
        credit_btn = QPushButton("❓")
        credit_btn.setFixedSize(30, 30)
        credit_btn.setToolTip("Sobre o Shellcode Tester Pro")
        credit_btn.clicked.connect(self.show_credits)

        header_layout = QHBoxLayout()
        header_layout.addWidget(toggle_theme_btn)
        header_layout.addStretch()
        header_layout.addWidget(credit_btn)
        layout.addLayout(header_layout)

        # Criar abas
        self.execution_tab = self.create_execution_tab()
        self.unicorn_tab = self.create_unicorn_tab()
        self.sandbox_tab = self.create_sandbox_tab()
        self.deobfuscation_tab = self.create_deobfuscation_tab()
        self.memory_tab = self.create_memory_tab()
        self.step_tab = self.create_step_tab()
        self.remote_tab = self.create_remote_tab()
   #     self.pdf_tab = self.create_pdf_tab()
        self.capstone_tab = self.create_analysis_tab()
        self.info_tab = self.create_info_tab()
        self.loaded_plugins = []
        self.tabs = tabs 
        self.load_plugins()
        self.evasion_tab = self.create_evasion_tab()
        self.binary_tab = self.create_binary_tab()




        # Adiciona abas
        tabs.addTab(self.execution_tab, "Importação e Execução")
        tabs.addTab(self.unicorn_tab, "Emulador Unicorn")
        tabs.addTab(self.sandbox_tab, "Sandbox Heurística")
        tabs.addTab(self.deobfuscation_tab, "Desofuscação e Criptografia")
        tabs.addTab(self.memory_tab, "Dump de Memória Hex")
        tabs.addTab(self.step_tab, "Execução Passo a Passo")
        tabs.addTab(self.remote_tab, "Shellcode Remoto")
      #  tabs.addTab(self.pdf_tab, "Exportar PDF")
        tabs.addTab(self.capstone_tab, "Disassembly")
        tabs.addTab(self.info_tab, "Fingerprint")
        tabs.addTab(self.evasion_tab, "Análise de Evasão")
        tabs.addTab(self.binary_tab, "Análise de Binário")
        layout.addWidget(tabs)
        self.setLayout(layout)

    def set_light_theme(self):
        self.dark_mode = False
        self.setPalette(QApplication.style().standardPalette())

    def toggle_theme(self):
        if self.dark_mode:
            self.set_light_theme()
            self.dark_mode = False
        else:
            self.set_dark_theme()
            self.dark_mode = True


    def load_plugins(self):
        plugins_path = os.path.abspath(os.path.join(os.path.dirname(__file__),"..", "plugins"))
        if not os.path.exists(plugins_path):
            os.makedirs(plugins_path)

        enabled_path = os.path.join(plugins_path, "enabled_plugins.json")
        if os.path.exists(enabled_path):
            with open(enabled_path, "r") as f:
                enabled_plugins = json.load(f)
        else:
            enabled_plugins = {}

        for filename in os.listdir(plugins_path):
            if filename.endswith(".py") and filename:
                if enabled_plugins.get(filename, True):  # Habilitado por padrão
                    try:
                        path = os.path.join(plugins_path, filename)
                        spec = importlib.util.spec_from_file_location("plugin", path)
                        plugin = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(plugin)
                        plugin.register(self)
                        self.loaded_plugins.append(filename)
                        print(f"[+] Plugin carregado: {filename}")
                    except Exception as e:
                        print(f"[!] Erro ao carregar {filename}: {e}")

    def create_binary_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.binary_output = QTextEdit()
        self.binary_output.setReadOnly(True)

        self.load_binary_btn = QPushButton("Carregar ELF ou EXE")
        self.load_binary_btn.clicked.connect(self.analyze_binary_file)

        self.export_shellcode_btn = QPushButton("Exportar Shellcode Suspeito")
        self.export_shellcode_btn.setEnabled(False)
        self.export_shellcode_btn.clicked.connect(self.export_extracted_shellcode)

        layout.addWidget(QLabel("Análise de Binários ELF / EXE"))
        layout.addWidget(self.load_binary_btn)
        layout.addWidget(self.export_shellcode_btn)
        layout.addWidget(self.binary_output)
        tab.setLayout(layout)

        return tab

    def analyze_binary_file(self):
        self.binary_output.clear()
        self.suspect_shellcodes = []

        file_path, _ = QFileDialog.getOpenFileName(self, "Abrir arquivo ELF ou EXE", "", "Executáveis (*.exe *.bin *.elf *.out)")
        if not file_path:
            self.binary_output.setText("[!] Nenhum arquivo selecionado.")
            return

        try:
            with open(file_path, "rb") as f:
                data = f.read()

            self.binary_output.append(f"[+] Arquivo carregado: {file_path}")
            self.binary_output.append(f"[+] Tamanho: {len(data)} bytes")

            findings = []

            if b"VirtualAlloc" in data or b"CreateThread" in data:
                findings.append("[!] API Windows detectada (possível shellcode)")
            if b"/bin/sh" in data:
                findings.append("[!] String '/bin/sh' detectada")
            if b"mmap" in data:
                findings.append("[!] mmap detectado")
            if data.count(b"\x90") > 50:
                findings.append("[!] NOP sled detectado (> 50 bytes)")

            hex_patterns = re.findall(rb'(?:\\x[0-9a-fA-F]{2}){10,}', data)
            if hex_patterns:
                findings.append(f"[!] {len(hex_patterns)} buffer(s) hex inline encontrados")

            blocks = re.findall(rb'([\x90-\xff]{30,})', data)
            for idx, block in enumerate(blocks):
                self.suspect_shellcodes.append(block)

            if blocks:
                findings.append(f"[!] {len(blocks)} bloco(s) binários suspeitos encontrados")
                for i, b in enumerate(blocks[:3]):  # Mostra até 3 previews
                    preview = ' '.join(f"{byte:02x}" for byte in b[:32])
                    self.binary_output.append(f"[+] Bloco {i+1} ({len(b)} bytes): {preview}...")

            if not findings:
                self.binary_output.append("[*] Nenhum padrão suspeito encontrado.")
            else:
                self.binary_output.append("\n".join(findings))

            if self.suspect_shellcodes:
                self.export_shellcode_btn.setEnabled(True)

        except Exception as e:
            self.binary_output.setText(f"[!] Erro ao analisar: {str(e)}")


    def export_extracted_shellcode(self):
        try:
            base_path, _ = QFileDialog.getSaveFileName(self, "Salvar Shellcode", "shellcode_extraido", "Arquivos binários (*.bin)")
            if base_path:
                for i, blob in enumerate(self.suspect_shellcodes):
                    filename = f"{base_path}_part{i+1}.bin"
                    with open(filename, "wb") as f:
                        f.write(blob)
                self.binary_output.append(f"[+] {len(self.suspect_shellcodes)} shellcodes exportados para arquivos!")
        except Exception as e:
            self.binary_output.append(f"[!] Erro ao salvar shellcodes: {str(e)}")


    def create_analysis_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.analysis_input = QTextEdit()
        self.analysis_output = QTextEdit()
        self.analysis_output.setReadOnly(True)

        analyze_btn = QPushButton("Analisar com Capstone")
        analyze_btn.clicked.connect(self.analyze_capstone)

        export_btn = QPushButton("Exportar Resultado da Análise")
        export_btn.clicked.connect(self.export_analysis_result)

        layout.addWidget(QLabel("Shellcode para Análise:"))
        layout.addWidget(self.analysis_input)
        layout.addWidget(analyze_btn)
        layout.addWidget(export_btn)
        layout.addWidget(QLabel("Resultado Capstone:"))
        layout.addWidget(self.analysis_output)

        tab.setLayout(layout)
        return tab

    def detect_arch_and_mode(self, data: bytes):
        if b"\x0f\x05" in data or b"\x48" in data:
            return CS_ARCH_X86, CS_MODE_64
        elif b"\xcd\x80" in data:
            return CS_ARCH_X86, CS_MODE_32
        elif b"\x00\xf0\x20\xe3" in data or b"\x01\x00\xa0\xe3" in data:
            return CS_ARCH_ARM, CS_MODE_ARM
        elif b"\x20\x00\x80\xd2" in data:  # mov x0, #0 (aarch64)
            return CS_ARCH_ARM64, CS_MODE_ARM
        else:
            return CS_ARCH_X86, CS_MODE_64  # fallback

    def analyze_capstone(self):
        self.analysis_output.clear()
        raw = self.analysis_input.toPlainText().strip()

        if not raw:
            self.analysis_output.setText("[!] Nenhum shellcode fornecido.")
            return

        try:
            # Tratamento igual ao parser global
            import re
            cleaned = raw.replace('"', '').replace("'", "").replace(';', '')
            cleaned = re.sub(r"[\n\r\t,]", "", cleaned)

            if "\\x" in cleaned:
                hex_str = cleaned.replace("\\x", "")
            else:
                hex_str = re.sub(r"[^0-9a-fA-F]", "", cleaned)

            if not re.fullmatch(r"[0-9a-fA-F]+", hex_str):
                self.analysis_output.setText("[!] Shellcode contém caracteres inválidos.")
                return

            if len(hex_str) % 2 != 0:
                hex_str = "0" + hex_str

            data = bytes.fromhex(hex_str)

            arch, mode = self.detect_arch_and_mode(data)
            md = Cs(arch, mode)
            md.detail = True

            result = []
            suspicious = []

            for i in md.disasm(data, 0x1000):
                line = f"0x{i.address:08x}: {i.bytes.hex():<20} {i.mnemonic:<7} {i.op_str}"
                result.append(line)
                if i.mnemonic in ["syscall", "int", "call"] or "exec" in i.op_str.lower():
                    suspicious.append(line)

            self.analysis_output.append(f"[+] Arquitetura detectada: {arch} | Modo: {mode}")
            self.analysis_output.append(f"[+] Total de instruções: {len(result)}\n")

            if suspicious:
                self.analysis_output.append("[!] Instruções suspeitas:")
                self.analysis_output.append("\n".join(suspicious))
                self.analysis_output.append("")

            self.analysis_output.append("[+] Disassembly completo:")
            self.analysis_output.append("\n".join(result))

        except Exception as e:
            self.analysis_output.setText(f"[!] Erro: {str(e)}")


    def export_analysis_result(self):
        try:
            content = self.analysis_output.toPlainText()
            if not content:
                QMessageBox.warning(self, "Aviso", "Nenhum resultado para exportar.")
                return
            path, _ = QFileDialog.getSaveFileName(self, "Salvar Resultado", "analysis.txt", "Text Files (*.txt)")
            if path:
                with open(path, "w") as f:
                    f.write(content)
                QMessageBox.information(self, "Salvo", f"Análise salva em: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Erro", str(e))

    def load_shellcode_bin(self):
        try:
            file, _ = QFileDialog.getOpenFileName(self, "Abrir Arquivo Binário", "", "Arquivos Binários (*.bin *.exe *.elf)")
            if not file:
                self.exec_output.append("[!] Nenhum arquivo selecionado.")
                return

            with open(file, "rb") as f:
                data = f.read()
                hexcode = ''.join(f'\\x{b:02x}' for b in data)
                self.shellcode_input.setPlainText(hexcode)
                self.exec_output.append(f"[+] Arquivo carregado: {file} ({len(data)} bytes)")

        except Exception as e:
            self.exec_output.append(f"[!] Erro ao carregar arquivo: {str(e)}")
    
  #  def create_pdf_tab(self):
   #     tab = QWidget()
    #    layout = QVBoxLayout()
#
 #       self.pdf_output = QTextEdit()
  #      self.pdf_output.setReadOnly(True)

#        export_btn = QPushButton("Exportar Shellcode e Análises para PDF")
 #       export_btn.clicked.connect(self.export_to_pdf)
#
 #       layout.addWidget(QLabel("Exportação de Relatório em PDF"))
  #      layout.addWidget(export_btn)
   #     layout.addWidget(self.pdf_output)
    #    tab.setLayout(layout)
     #   return tab ###
    #
    #def export_to_pdf(self):
     #   try:
      #      shellcode = self.shellcode_input.toPlainText().strip()
       #     pdf = FPDF()
        #    pdf.add_page()
         #   pdf.set_font("Arial", size=12)
          #  pdf.cell(200, 10, txt="Shellcode Tester Pro - Relatório", ln=True, align="C")
           # pdf.ln(10)
#
 #           pdf.multi_cell(0, 10, txt=f"Shellcode:")
  #          pdf.set_font("Courier", size=10)
   #         pdf.multi_cell(0, 10, txt=shellcode)
#
 #           pdf.ln(5)
  #          pdf.set_font("Arial", size=12)
   #         pdf.multi_cell(0, 10, txt="--- Análise Heurística ---")
    #        pdf.set_font("Courier", size=10)
     #       pdf.multi_cell(0, 10, txt=self.sandbox_output.toPlainText())
#
 #           pdf.ln(5)
  #          pdf.set_font("Arial", size=12)
   #         pdf.multi_cell(0, 10, txt="--- Desofuscação ---")
    #        pdf.set_font("Courier", size=10)
     #       pdf.multi_cell(0, 10, txt=self.deob_output.toPlainText())
#
 #           pdf.ln(5)
  #          pdf.set_font("Arial", size=12)
   #         pdf.multi_cell(0, 10, txt="--- Memória Hex ---")
    #        pdf.set_font("Courier", size=10)
     #       pdf.multi_cell(0, 10, txt=self.mem_output.toPlainText())

      #      file_path, _ = QFileDialog.getSaveFileName(self, "Salvar PDF", "shellcode_report.pdf", "PDF Files (*.pdf)")
       #     if file_path:
        #        pdf.output(file_path)
         #       self.pdf_output.setText(f"[+] Relatório PDF salvo com sucesso: {file_path}")
          #  else:
           #     self.pdf_output.setText("[!] Caminho de arquivo não escolhido.")
#
 #       except Exception as e:
  #          self.pdf_output.setText(f"[!] Erro ao gerar PDF: {str(e)}")

    def create_step_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.step_output = QTextEdit()
        self.step_output.setReadOnly(True)

        step_btn = QPushButton("Executar Instrução por Instrução")
        step_btn.clicked.connect(self.step_by_step_unicorn)

        layout.addWidget(QLabel("Execução com Unicorn (Step-by-Step):"))
        layout.addWidget(step_btn)
        layout.addWidget(self.step_output)
        tab.setLayout(layout)
        return tab

    def create_execution_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.shellcode_input = QTextEdit()
        self.shellcode_input.setPlaceholderText("Cole seu shellcode em hexadecimal ou \\x.. aqui")
        self.shellcode_input.setStyleSheet("color: white; background-color: #1e1e1e;")
        layout.addWidget(QLabel("Shellcode:"))
        layout.addWidget(self.shellcode_input)

        # Botões de ação
        button_layout = QHBoxLayout()

        run_btn = QPushButton("Executar (Simulado)")
        run_btn.clicked.connect(self.simulate_execution)
        button_layout.addWidget(run_btn)

        load_btn = QPushButton("Carregar Arquivo .bin")
        load_btn.clicked.connect(self.load_shellcode_bin)
        button_layout.addWidget(load_btn)

        layout.addLayout(button_layout)

        self.exec_output = QTextEdit()
        self.exec_output.setReadOnly(True)
        layout.addWidget(QLabel("Log de Execução:"))
        layout.addWidget(self.exec_output)

        tab.setLayout(layout)
        return tab


    def create_remote_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com/shellcode.txt ou .bin")

        self.import_mode = QComboBox()
        self.import_mode.addItems(["\\x formatado", "Hex puro", "Binário RAW"])

        fetch_btn = QPushButton("Carregar Shellcode da URL")
        fetch_btn.clicked.connect(self.fetch_remote_shellcode)

        self.remote_output = QTextEdit()
        self.remote_output.setReadOnly(True)

        layout.addWidget(QLabel("URL do Shellcode:"))
        layout.addWidget(self.url_input)
        layout.addWidget(QLabel("Modo de Importação:"))
        layout.addWidget(self.import_mode)
        layout.addWidget(fetch_btn)
        layout.addWidget(QLabel("Log de Shellcode Remoto:"))
        layout.addWidget(self.remote_output)

        tab.setLayout(layout)
        return tab

    def fetch_remote_shellcode(self):
        import hashlib, os

        self.remote_output.clear()
        url = self.url_input.text().strip()
        if not url:
            self.remote_output.setText("[!] URL não fornecida.")
            return

        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            content = response.content

            sha256 = hashlib.sha256(content).hexdigest()
            self.remote_output.append(f"[+] SHA256: {sha256}")
            self.remote_output.append(f"[+] MIME: {response.headers.get('Content-Type', 'desconhecido')}")
            self.remote_output.append(f"[+] Tamanho: {len(content)} bytes\n")

            mode = self.import_mode.currentText()

            if mode == "\\x formatado":
                if all(32 <= b <= 126 or b in (9, 10, 13) for b in content):
                    content_str = content.decode(errors="ignore").strip()
                    if "\\x" in content_str:
                        self.shellcode_input.setPlainText(content_str)
                    else:
                        hexed = content_str.replace(" ", "").replace("\n", "")
                        formatted = ''.join(f"\\x{hexed[i:i+2]}" for i in range(0, len(hexed), 2))
                        self.shellcode_input.setPlainText(formatted)
                else:
                    formatted = ''.join(f"\\x{b:02x}" for b in content)
                    self.shellcode_input.setPlainText(formatted)

            elif mode == "Hex puro":
                hexed = ''.join(f"{b:02x}" for b in content)
                self.shellcode_input.setPlainText(hexed)

            elif mode == "Binário RAW":
                path = os.path.join("downloads", os.path.basename(url) or "shellcode_raw.bin")
                os.makedirs("downloads", exist_ok=True)
                with open(path, "wb") as f:
                    f.write(content)
                self.shellcode_input.setPlainText("")  # não exibe no campo
                self.remote_output.append(f"[✓] Shellcode salvo como: {path}")

            self.remote_output.append("[✓] Shellcode carregado com sucesso!")

        except Exception as e:
            self.remote_output.setText(f"[!] Erro ao buscar shellcode: {str(e)}")

    def step_by_step_unicorn(self):
        self.step_output.clear()
        try:
            code = self.shellcode_input.toPlainText().strip().replace("\\x", "").replace(" ", "")
            shellcode = bytes.fromhex(code)
            ADDRESS = 0x1000000
            STACK_ADDR = 0x200000
            STACK_SIZE = 2 * 1024 * 1024

            mu = Uc(UC_ARCH_X86, UC_MODE_64)
            mu.mem_map(ADDRESS, 2 * 1024 * 1024)
            mu.mem_write(ADDRESS, shellcode)
            mu.mem_map(STACK_ADDR, STACK_SIZE)
            mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE // 2)

            self.step_output.append("[*] Iniciando execução passo a passo...")

            rip = ADDRESS
            end = ADDRESS + len(shellcode)

            while rip < end:
                mu.emu_start(rip, rip + 1, timeout=0, count=1)
                rax = mu.reg_read(UC_X86_REG_RAX)
                rsp = mu.reg_read(UC_X86_REG_RSP)
                rip = mu.reg_read(UC_X86_REG_RIP)

                self.step_output.append(f"[STEP] RIP: 0x{rip:x}, RAX: 0x{rax:x}, RSP: 0x{rsp:x}")

        except UcError as e:
            self.step_output.append(f"[!] Unicorn Exception: {e}")
        except Exception as e:
            self.step_output.append(f"[!] Erro na execução passo a passo: {str(e)}")


    def analyze_shellcode_fingerprint(self):
        self.info_output.clear()
        data, error = self.get_shellcode_bytes()
        if error:
            self.info_output.setText(error)
            return
        self.info_output.clear()
        try:
            code = self.shellcode_input.toPlainText().strip().replace("\\x", "").replace(" ", "")
            data = bytes.fromhex(code)

            arch = "Desconhecida"
            os_target = "Desconhecido"
            indicators = []
            fingerprint = "Desconhecido"

            self.info_output.append(f"[*] Tamanho do shellcode: {len(data)} bytes\n")

            # Sistema operacional e arquitetura
            if b"/bin/sh" in data:
                os_target = "Linux"
                indicators.append("[*] String '/bin/sh' detectada (Linux)")
            if b"cmd.exe" in data or b"powershell" in data:
                os_target = "Windows"
                indicators.append("[*] String 'cmd.exe' ou 'powershell' detectada (Windows)")

            # Arquitetura por instruções
            if b"\x0f\x05" in data:
                indicators.append("[*] Instrução 'syscall' detectada (Linux x64)")
            if b"\xcd\x80" in data:
                indicators.append("[*] Instrução 'int 0x80' detectada (Linux x86)")
            if b"\x0f\x34" in data:
                indicators.append("[*] Instrução 'sysenter' detectada (Windows x86)")
            if b"\x48" in data or b"\x49" in data:
                arch = "x86_64"
                indicators.append("[*] Uso de prefixo REX (64 bits)")
            elif b"\x66" in data or b"\xb8" in data:
                arch = "x86"
                indicators.append("[*] Instruções típicas de 32 bits")

            # WinAPI
            for api in [b"VirtualAlloc", b"LoadLibrary", b"GetProcAddress", b"WinExec"]:
                if api in data:
                    indicators.append(f"[+] API do Windows detectada: {api.decode()}")

            # Verificação de NOP sled
            nop_count = data.count(b"\x90")
            if nop_count > 8:
                indicators.append(f"[+] NOP sled detectado ({nop_count} bytes de 0x90)")

            # Fingerprints
            if b"EXITFUNC" in data or b"Metasploit" in data:
                fingerprint = "msfvenom"
                indicators.append("[+] Assinatura textual do Metasploit encontrada")
            elif nop_count > 10:
                fingerprint = "Possivelmente msfvenom"
                indicators.append("[+] NOP sled longa (padrão msfvenom)")

            if b"Donut" in data or b".text" in data or b"mscoree.dll" in data:
                fingerprint = "Donut"
                indicators.append("[+] Assinaturas de payload Donut detectadas")

            if b"powershell -nop" in data or b"DownloadString" in data:
                fingerprint = "Empire / Powershell"
                indicators.append("[+] Assinatura Empire/powershell detectada")

            if b"beacon" in data or b"ReflectiveLoader" in data:
                fingerprint = "Cobalt Strike"
                indicators.append("[+] Possível shellcode Cobalt Strike")

            if b"sliver" in data or b"rpc" in data:
                fingerprint = "Sliver"
                indicators.append("[+] Possível shellcode do Sliver C2")

            if b"Meterpreter" in data or b"reverse_tcp" in data:
                fingerprint = "Meterpreter"
                indicators.append("[+] Indícios de shellcode Meterpreter")

            if b"Shellter" in data:
                fingerprint = "Shellter"
                indicators.append("[+] Shellcode possivelmente gerado com Shellter")

            if fingerprint == "Desconhecido" and len(data) < 100:
                fingerprint = "Possivelmente shellcode custom ou stage 1"

            # Resultado
            self.info_output.append(f"Arquitetura provável: {arch}")
            self.info_output.append(f"Sistema Operacional: {os_target}")
            self.info_output.append(f"Gerador Possível: {fingerprint}")
            self.info_output.append("\nHeurísticas encontradas:")
            self.info_output.append("\n".join(indicators) or "[*] Nenhuma heurística forte detectada.")

        except Exception as e:
            self.info_output.setText(f"[!] Erro na análise: {str(e)}")

    def create_evasion_tab(self):
        from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QPushButton, QLabel

        tab = QWidget()
        layout = QVBoxLayout()

        self.evasion_output = QTextEdit()
        self.evasion_output.setReadOnly(True)

        btn = QPushButton("Executar Análise de Evasão")
        btn.clicked.connect(self.run_evasion_analysis)

        layout.addWidget(QLabel("Análise de Técnicas de Evasão:"))
        layout.addWidget(btn)
        layout.addWidget(self.evasion_output)

        tab.setLayout(layout)
        return tab

    def run_evasion_analysis(self):
        self.evasion_output.clear()
        try:
            code = self.shellcode_input.toPlainText().strip().replace("\\x", "").replace(" ", "")
            data = bytes.fromhex(code)

            findings = self.check_evasion_techniques(data)
            if findings:
                self.evasion_output.append("\n".join(findings))
            else:
                self.evasion_output.append("[*] Nenhuma técnica de evasão identificada.")
        except Exception as e:
            self.evasion_output.setText(f"[!] Erro: {str(e)}")


    def check_evasion_techniques(self, data: bytes):
        findings = []

        # 1. Anti-sandbox strings
        sandbox_indicators = [b"vbox", b"vmware", b"qemu", b"sandbox", b"VBoxService", b"virtualbox"]
        for s in sandbox_indicators:
            if s in data:
                findings.append(f"[!] Indicador de sandbox detectado: {s.decode(errors='ignore')}")

        # 2. Anti-debugging e temporização
        apis = [b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent", b"NtQueryInformationProcess",
                b"GetTickCount", b"QueryPerformanceCounter", b"Sleep", b"rdtsc", b"cpuid"]
        for api in apis:
            if api in data:
                findings.append(f"[!] Uso de API de evasão/debug/sandbox: {api.decode(errors='ignore')}")

        # 3. Tentativas de matar segurança
        targets = [b"avp.exe", b"defender", b"MsMpEng.exe", b"taskkill", b"firewall", b"securityhealthservice"]
        for t in targets:
            if t in data:
                findings.append(f"[!] Tentativa de desativar segurança: {t.decode(errors='ignore')}")

        return findings



    def run_unicorn(self):
        self.unicorn_output.clear()
        try:
            code = self.shellcode_input.toPlainText().strip().replace("\\x", "").replace(" ", "")
            shellcode = bytes.fromhex(code)

            ADDRESS = 0x1000000           # Onde o shellcode será carregado
            CODE_SIZE = 2 * 1024 * 1024   # 2MB para o shellcode
            STACK_ADDR = 0x200000         # Endereço da stack
            STACK_SIZE = 2 * 1024 * 1024  # 2MB

            mu = Uc(UC_ARCH_X86, UC_MODE_64)

            # Mapear memória para shellcode
            mu.mem_map(ADDRESS, CODE_SIZE)
            mu.mem_write(ADDRESS, shellcode)

            # Mapear memória para stack
            mu.mem_map(STACK_ADDR, STACK_SIZE)
            mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE // 2)

            # Opcional: hook para debug de memória
            def hook_mem_invalid(uc, access, address, size, value, user_data):
                if access == UC_MEM_WRITE_UNMAPPED:
                    self.unicorn_output.append(f"[!] WRITE inválido em 0x{address:x}")
                elif access == UC_MEM_READ_UNMAPPED:
                    self.unicorn_output.append(f"[!] READ inválido em 0x{address:x}")
                elif access == UC_MEM_FETCH_UNMAPPED:
                    self.unicorn_output.append(f"[!] FETCH inválido em 0x{address:x}")
                return False  # não tentar continuar

            mu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)

            self.unicorn_output.append("[*] Iniciando emulação com Unicorn...")
            mu.emu_start(ADDRESS, ADDRESS + len(shellcode))
            self.unicorn_output.append("[+] Shellcode emulado com sucesso!")

            rax = mu.reg_read(UC_X86_REG_RAX)
            rip = mu.reg_read(UC_X86_REG_RIP)
            self.unicorn_output.append(f"[*] RAX: 0x{rax:x} | RIP: 0x{rip:x}")

        except UcError as ue:
            self.unicorn_output.append(f"[!] Unicorn Exception: {ue}")
        except Exception as e:
            self.unicorn_output.append(f"[!] Erro na emulação: {str(e)}")

    def create_info_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.info_output = QTextEdit()
        self.info_output.setReadOnly(True)

        analyze_btn = QPushButton("Analisar Fingerprint")
        analyze_btn.clicked.connect(self.analyze_shellcode_fingerprint)

        layout.addWidget(analyze_btn)
        layout.addWidget(QLabel("Resultado da Análise Heurística de Fingerprinting:"))
        layout.addWidget(self.info_output)
        tab.setLayout(layout)
        return tab


    def create_unicorn_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.unicorn_output = QTextEdit()
        self.unicorn_output.setReadOnly(True)

        run_btn = QPushButton("Emular com Unicorn")
        run_btn.clicked.connect(self.run_unicorn)

        layout.addWidget(QLabel("Resultado da Emulação:"))
        layout.addWidget(run_btn)
        layout.addWidget(self.unicorn_output)
        tab.setLayout(layout)
        return tab

    def create_sandbox_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.sandbox_output = QTextEdit()
        self.sandbox_output.setReadOnly(True)
        analyze_btn = QPushButton("Analisar Comportamento")
        analyze_btn.clicked.connect(self.heuristic_analysis)

        layout.addWidget(QLabel("Sandbox / Detecção de comportamento:"))
        layout.addWidget(analyze_btn)
        layout.addWidget(self.sandbox_output)
        tab.setLayout(layout)
        return tab

    def create_deobfuscation_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.deob_output = QTextEdit()
        self.deob_output.setReadOnly(True)

        deob_btn = QPushButton("Analisar e Desofuscar")
        deob_btn.clicked.connect(self.analyze_and_deobfuscate)

        layout.addWidget(QLabel("Desofuscação / Normalização:"))
        layout.addWidget(deob_btn)
        layout.addWidget(self.deob_output)
        tab.setLayout(layout)
        return tab

    def create_memory_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.mem_output = QTextEdit()
        self.mem_output.setReadOnly(True)
        dump_btn = QPushButton("Visualizar Shellcode Formatado")
        dump_btn.clicked.connect(self.dump_memory_style)

        layout.addWidget(QLabel("Visualizador de Memória (Hex + ASCII):"))
        layout.addWidget(dump_btn)
        layout.addWidget(self.mem_output)
        tab.setLayout(layout)
        return tab
        
    def get_shellcode_bytes(self):
        raw_input = self.shellcode_input.toPlainText().strip()

        if not raw_input:
            return b'', "[!] Nenhum shellcode fornecido."

        try:
            # Remove aspas, ponto e vírgula
            cleaned = raw_input.replace('"', '').replace("'", "").replace(';', '')

            # Remove vírgulas, quebras de linha, tabs, etc
            cleaned = re.sub(r"[\n\r\t,]", "", cleaned)

            # Trata entrada com \x
            if "\\x" in cleaned:
                hex_str = cleaned.replace("\\x", "")
            else:
                hex_str = re.sub(r"[^0-9a-fA-F]", "", cleaned)

            if not re.fullmatch(r"[0-9a-fA-F]+", hex_str):
                return b'', "[!] Shellcode contém caracteres inválidos."

            if len(hex_str) % 2 != 0:
                hex_str = "0" + hex_str

            return bytes.fromhex(hex_str), ""

        except Exception as e:
            return b'', f"[!] Erro ao processar shellcode: {str(e)}"

    def simulate_execution(self):
        self.exec_output.clear()

        shellcode_bytes, error = self.get_shellcode_bytes()
        if error:
            self.exec_output.append(error)
            return

        try:
            self.exec_output.append(f"[+] Shellcode formatado com sucesso ({len(shellcode_bytes)} bytes).")

            with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
                tmp.write(shellcode_bytes)
                tmp_path = tmp.name

            self.exec_output.append(f"[+] Shellcode salvo em: {tmp_path}")

            # Caminho absoluto para o runner_portuguese.py na pasta backend
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            runner_path = os.path.join(base_dir, "backend", "runner_portuguese.py")

            if not os.path.isfile(runner_path):
                self.exec_output.append(f"[!] runner_portuguese.py não encontrado em: {runner_path}")
                return

            self.exec_output.append("[*] Executando runner_portuguese.py em terminal externo...")

            if os.system("which gnome-terminal") == 0:
                term_cmd = ["gnome-terminal", "--", "python3", runner_path, tmp_path]
            elif os.system("which xterm") == 0:
                term_cmd = ["xterm", "-e", f"python3 {runner_path} {tmp_path}; bash"]
            elif os.system("which konsole") == 0:
                term_cmd = ["konsole", "-e", f"python3 {runner_path} {tmp_path}; bash"]
            else:
                self.exec_output.append("[!] Nenhum terminal compatível encontrado.")
                return

            subprocess.Popen(term_cmd)
            self.exec_output.append("[+] Shellcode sendo executado em outro terminal.")

        except Exception as e:
            self.exec_output.append(f"[!] Erro: {str(e)}")




    def run_unicorn(self):
        self.unicorn_output.clear()
        data, error = self.get_shellcode_bytes()
        if error:
            self.unicorn_output.setText(error)
            return
        self.unicorn_output.clear()
        try:
            code = self.shellcode_input.toPlainText().strip().replace("\\x", "").replace(" ", "")
            shellcode = bytes.fromhex(code)
            ADDRESS = 0x1000000  # endereço base do shellcode
            STACK_ADDR = 0x200000  # endereço da stack
            STACK_SIZE = 2 * 1024 * 1024  # 2MB

            mu = Uc(UC_ARCH_X86, UC_MODE_64)

            # Mapeia memória para shellcode e stack
            mu.mem_map(ADDRESS, 2 * 1024 * 1024)
            mu.mem_write(ADDRESS, shellcode)
            mu.mem_map(STACK_ADDR, STACK_SIZE)

            # Define registrador de stack
            mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE // 2)

            self.unicorn_output.append("[*] Iniciando emulação com Unicorn...")
            mu.emu_start(ADDRESS, ADDRESS + len(shellcode))
            self.unicorn_output.append("[+] Shellcode emulado com sucesso!")

            rax = mu.reg_read(UC_X86_REG_RAX)
            rip = mu.reg_read(UC_X86_REG_RIP)
            self.unicorn_output.append(f"[*] RAX: 0x{rax:x} | RIP: 0x{rip:x}")

        except Exception as e:
            self.unicorn_output.append(f"[!] Erro na emulação: {str(e)}")


    def heuristic_analysis(self):
        self.sandbox_output.clear()
        data, error = self.get_shellcode_bytes()
        if error:
            self.sandbox_output.setText(error)
            return
        self.sandbox_output.clear()
        try:
            code = self.shellcode_input.toPlainText().strip().replace("\\x", "").replace(" ", "")
            shellcode = bytes.fromhex(code)
            alerts = []

            if b"/bin/sh" in shellcode:
                alerts.append("[⚠️] Detecção: /bin/sh encontrado (possível shell reversa Linux)")
            if b"cmd.exe" in shellcode:
                alerts.append("[⚠️] Detecção: cmd.exe encontrado (possível shell reversa Windows)")
            if b"socket" in shellcode or b"connect" in shellcode:
                alerts.append("[⚠️] Detecção: uso de socket/connect")
            if b"WinExec" in shellcode or b"ShellExecute" in shellcode:
                alerts.append("[⚠️] Detecção: API Windows encontrada (execução remota)")
            if not alerts:
                self.sandbox_output.append("[*] Nenhum comportamento suspeito identificado.")
            else:
                self.sandbox_output.append("[*] Heurísticas ativadas:\n")
                for alert in alerts:
                    self.sandbox_output.append(alert)
        except Exception as e:
            self.sandbox_output.append(f"[!] Erro na análise heurística: {str(e)}")

    def analyze_and_deobfuscate(self):
        self.deob_output.clear()
        data, error = self.get_shellcode_bytes()
        if error:
            self.deob_output.setText(error)
            return
        self.deob_output.clear()
        try:
            code = self.shellcode_input.toPlainText().strip().replace("\\x", "").replace(" ", "")
            data = bytearray.fromhex(code)

            def calc_entropy(blob):
                from math import log2
                if not blob:
                    return 0
                freq = {b: blob.count(b) for b in set(blob)}
                total = len(blob)
                entropy = -sum((f / total) * log2(f / total) for f in freq.values())
                return entropy

            # 1. Detectar possível XOR
            xor_detected = False
            for key in range(1, 256):
                decoded = bytearray([b ^ key for b in data])
                if all(32 <= c <= 126 or c == 0 for c in decoded[:40]):  # ascii legível
                    self.deob_output.append(f"[+] Possível XOR detectado com chave: 0x{key:02x}")
                    self.deob_output.append(f"[*] Shellcode normalizado:\n{decoded.hex()}")
                    xor_detected = True
                    break

            # 2. Detectar NOP sled
            if not xor_detected:
                nop_free = [b for b in data if b != 0x90]
                if len(nop_free) < len(data):
                    self.deob_output.append("[+] NOP sled detectado e removido.")
                    self.deob_output.append(f"[*] Shellcode limpo:\n{bytes(nop_free).hex()}")

            # 3. Detectar AES por blocos repetidos (16 bytes)
            blocks = [data[i:i+16] for i in range(0, len(data)-15, 16)]
            block_set = set(bytes(b) for b in blocks)
            if len(block_set) < len(blocks) * 0.8 and len(blocks) >= 3:
                self.deob_output.append("[!] Padrão semelhante ao AES detectado (blocos de 16 bytes repetidos)")

            # 4. Detectar RC4 ou criptografia com alta entropia
            entropy = calc_entropy(data)
            self.deob_output.append(f"[*] Entropia: {entropy:.2f}")
            if entropy > 7.5:
                self.deob_output.append("[!] Alta entropia detectada — possível uso de RC4, AES ou outro algoritmo.")

            if not xor_detected and entropy < 5:
                self.deob_output.append("[*] Shellcode parece não estar criptografado.")
            elif not xor_detected:
                self.deob_output.append("[*] Não foi possível desofuscar automaticamente, mas há indícios de criptografia.")

        except Exception as e:
            self.deob_output.append(f"[!] Erro na análise de ofuscação: {str(e)}")

    def dump_memory_style(self):
        self.mem_output.clear()
        try:
            code = self.shellcode_input.toPlainText().strip().replace("\\x", "").replace(" ", "")
            data = bytes.fromhex(code)
            result = ""
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_part = " ".join(f"{b:02x}" for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                result += f"{i:08x}  {hex_part:<48}  {ascii_part}\n"
            self.mem_output.setPlainText(result)
        except Exception as e:
            self.mem_output.setPlainText(f"[!] Erro ao gerar dump de memória: {str(e)}")
   
    def show_credits(self):
        QMessageBox.information(self, "Sobre o Shellcode Tester Pro",
            "🔐 Shellcode Tester Pro\n\n"
            "👨‍💻 Criado por: Joas Antonio dos Santos\n"
            "🌐 GitHub: https://github.com/CyberSecurityUP/Shellcode-Tester-Pro\n"
            "📖 Documentação: https://github.com/CyberSecurityUP/Shellcode-Tester-Pro/docs/\n"
            "🐦 Twitter: @C0d3Cr4zy\n"
            "🔗 LinkedIn: https://www.linkedin.com/in/joas-antonio-dos-santos/\n\n"
            "🧠 Projeto open-source para análise segura de shellcodes\n"
            "💥 Cuidado: execução de código real pode ser perigosa.\n\n"
            "© 2025 - Todos os direitos reservados."
        )
if __name__ == '__main__':
    app = QApplication(sys.argv)
    from splash_screen import SplashScreen
    splash = SplashScreen()
    splash.show()
    sys.exit(app.exec_())
