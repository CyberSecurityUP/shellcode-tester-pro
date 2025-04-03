import sys
import ctypes
import platform
import requests
from fpdf import FPDF
from PyQt5.QtWidgets import (
    QApplication, QWidget, QTabWidget, QVBoxLayout, QTextEdit, QPushButton,
    QLabel, QHBoxLayout, QFileDialog, QMessageBox, QLineEdit
)
from PyQt5.QtGui import QFont, QColor, QPalette
from PyQt5.QtCore import Qt
from unicorn import *
from unicorn.x86_const import *
from capstone import *  
import tempfile
import subprocess
import os


class ShellcodeTesterPro(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Shellcode Tester Pro")
        self.setGeometry(100, 100, 900, 700)
        self.set_dark_theme()
        self.dark_mode = True 
        self.init_ui()

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

        # Criar abas
        self.execution_tab = self.create_execution_tab()
        self.unicorn_tab = self.create_unicorn_tab()
        self.sandbox_tab = self.create_sandbox_tab()
        self.deobfuscation_tab = self.create_deobfuscation_tab()
        self.memory_tab = self.create_memory_tab()
        self.step_tab = self.create_step_tab()
        self.remote_tab = self.create_remote_tab()
        self.pdf_tab = self.create_pdf_tab()
        self.capstone_tab = self.create_analysis_tab()
        self.info_tab = self.create_info_tab()


        # Adiciona abas
        tabs.addTab(self.execution_tab, "Execução")
        tabs.addTab(self.unicorn_tab, "Emulador Unicorn")
        tabs.addTab(self.sandbox_tab, "Sandbox Heurística")
        tabs.addTab(self.deobfuscation_tab, "Desofuscação")
        tabs.addTab(self.memory_tab, "Memória Hex")
        tabs.addTab(self.step_tab, "Execução Passo a Passo")
        tabs.addTab(self.remote_tab, "Shellcode Remoto")
        tabs.addTab(self.pdf_tab, "Exportar PDF")
        tabs.addTab(self.capstone_tab, "Análise Capstone")
        tabs.addTab(self.info_tab, "Fingerprint")

        layout.addWidget(tabs)
        self.setLayout(layout)

    def set_light_theme(self):
        self.dark_mode = False
        self.setPalette(QApplication.style().standardPalette())

    def toggle_theme(self):
        if self.dark_mode:
            self.set_light_theme()
        else:
            self.set_dark_theme()

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

    def analyze_capstone(self):
        try:
            code = self.analysis_input.toPlainText().replace("\\x", "").replace(" ", "")
            shellcode = bytes.fromhex(code)
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            result = "\n".join(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}" for i in md.disasm(shellcode, 0x1000))
            self.analysis_output.setPlainText(result)
        except Exception as e:
            self.analysis_output.setPlainText(f"[!] Erro: {str(e)}")

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

    def load_bin(self):
        try:
            file_path, _ = QFileDialog.getOpenFileName(self, "Abrir Arquivo .bin", "", "Arquivos Binários (*.bin)")
            if file_path:
                with open(file_path, "rb") as f:
                    data = f.read()
                    hexcode = " ".join(f"{b:02x}" for b in data)
                    self.shellcode_input.setPlainText(hexcode.replace(" ", ""))
                    self.load_bin_output.setPlainText(hexcode)
        except Exception as e:
            self.load_bin_output.setPlainText(f"[!] Erro: {str(e)}")

    def create_pdf_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.pdf_output = QTextEdit()
        self.pdf_output.setReadOnly(True)

        export_btn = QPushButton("Exportar Shellcode e Análises para PDF")
        export_btn.clicked.connect(self.export_to_pdf)

        layout.addWidget(QLabel("Exportação de Relatório em PDF"))
        layout.addWidget(export_btn)
        layout.addWidget(self.pdf_output)
        tab.setLayout(layout)
        return tab

    def export_to_pdf(self):
        try:
            shellcode = self.shellcode_input.toPlainText().strip()
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            pdf.cell(200, 10, txt="Shellcode Tester Pro - Relatório", ln=True, align="C")
            pdf.ln(10)

            pdf.multi_cell(0, 10, txt=f"Shellcode:")
            pdf.set_font("Courier", size=10)
            pdf.multi_cell(0, 10, txt=shellcode)

            pdf.ln(5)
            pdf.set_font("Arial", size=12)
            pdf.multi_cell(0, 10, txt="--- Análise Heurística ---")
            pdf.set_font("Courier", size=10)
            pdf.multi_cell(0, 10, txt=self.sandbox_output.toPlainText())

            pdf.ln(5)
            pdf.set_font("Arial", size=12)
            pdf.multi_cell(0, 10, txt="--- Desofuscação ---")
            pdf.set_font("Courier", size=10)
            pdf.multi_cell(0, 10, txt=self.deob_output.toPlainText())

            pdf.ln(5)
            pdf.set_font("Arial", size=12)
            pdf.multi_cell(0, 10, txt="--- Memória Hex ---")
            pdf.set_font("Courier", size=10)
            pdf.multi_cell(0, 10, txt=self.mem_output.toPlainText())

            file_path, _ = QFileDialog.getSaveFileName(self, "Salvar PDF", "shellcode_report.pdf", "PDF Files (*.pdf)")
            if file_path:
                pdf.output(file_path)
                self.pdf_output.setText(f"[+] Relatório PDF salvo com sucesso: {file_path}")
            else:
                self.pdf_output.setText("[!] Caminho de arquivo não escolhido.")

        except Exception as e:
            self.pdf_output.setText(f"[!] Erro ao gerar PDF: {str(e)}")

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

        layout.addWidget(QLabel("Shellcode:"))
        layout.addWidget(self.shellcode_input)

        button_layout = QHBoxLayout()

        run_btn = QPushButton("Executar (Simulado)")
        run_btn.clicked.connect(self.simulate_execution)
        button_layout.addWidget(run_btn)

        load_bin_btn = QPushButton("Carregar Arquivo .bin")
        load_bin_btn.clicked.connect(self.load_bin)
        button_layout.addWidget(load_bin_btn)

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

        fetch_btn = QPushButton("Carregar Shellcode da URL")
        fetch_btn.clicked.connect(self.fetch_remote_shellcode)

        self.remote_output = QTextEdit()
        self.remote_output.setReadOnly(True)

        layout.addWidget(QLabel("URL do Shellcode:"))
        layout.addWidget(self.url_input)
        layout.addWidget(fetch_btn)
        layout.addWidget(QLabel("Log de Shellcode Remoto:"))
        layout.addWidget(self.remote_output)
        tab.setLayout(layout)
        return tab

    def fetch_remote_shellcode(self):
        self.remote_output.clear()
        url = self.url_input.text().strip()
        if not url:
            self.remote_output.setText("[!] URL não fornecida.")
            return

        try:
            response = requests.get(url)
            response.raise_for_status()
            content = response.content

            # Verifica se é texto legível
            if all(32 <= b <= 126 or b in (9, 10, 13) for b in content):
                content_str = content.decode(errors="ignore").strip()
                if "\\x" in content_str:
                    self.shellcode_input.setPlainText(content_str)
                    self.remote_output.setText("[+] Shellcode com \\x detectado e mantido.")
                else:
                    hexed = content_str.replace(" ", "").replace("\n", "")
                    formatted = ''.join(f"\\x{hexed[i:i+2]}" for i in range(0, len(hexed), 2))
                    self.shellcode_input.setPlainText(formatted)
                    self.remote_output.setText("[+] Shellcode em hex convertido para formato \\x.")
            else:
                # Conteúdo binário puro
                formatted = ''.join(f"\\x{b:02x}" for b in content)
                self.shellcode_input.setPlainText(formatted)
                self.remote_output.setText("[+] Shellcode binário convertido para formato \\x.")

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
        try:
            code = self.shellcode_input.toPlainText().strip().replace("\\x", "").replace(" ", "")
            data = bytes.fromhex(code)

            arch = "Desconhecida"
            os_target = "Desconhecido"
            indicators = []
            fingerprint = "Desconhecido"

            # SO/Arquitetura
            if b"/bin/sh" in data:
                os_target = "Linux"
                indicators.append("[*] String '/bin/sh' detectada (Linux)")
            if b"cmd.exe" in data or b"powershell" in data:
                os_target = "Windows"
                indicators.append("[*] String 'cmd.exe' ou 'powershell' detectada (Windows)")
            if b"\x0f\x05" in data:
                indicators.append("[*] Instrução 'syscall' detectada (Linux x64)")
            if b"\xcd\x80" in data:
                indicators.append("[*] Instrução 'int 0x80' detectada (Linux x86)")
            if b"\x48" in data or b"\x49" in data:
                arch = "x86_64"
                indicators.append("[*] Uso de prefixo REX (modo 64 bits)")

            # Fingerprints msfvenom
            if data.count(b"\x90") > 10:
                fingerprint = "Possivelmente msfvenom"
                indicators.append("[+] Detecção de NOP sled longa (padrão msfvenom)")
            if b"EXITFUNC" in data or b"Metasploit" in data:
                fingerprint = "msfvenom"
                indicators.append("[+] Assinatura textual do Metasploit encontrada")

            # Donut
            if b"Donut" in data or b".text" in data or b"mscoree.dll" in data:
                fingerprint = "Donut"
                indicators.append("[+] Assinaturas de payload Donut detectadas")

            # Empire
            if b"powershell -nop" in data or b"DownloadString" in data:
                fingerprint = "Empire / Powershell"
                indicators.append("[+] Assinatura Empire/powershell detectada")

            # Cobalt Strike
            if b"beacon" in data or b"ReflectiveLoader" in data:
                fingerprint = "Cobalt Strike"
                indicators.append("[+] Possível shellcode Cobalt Strike")

            # Genérico
            if fingerprint == "Desconhecido" and len(data) < 100:
                fingerprint = "Possivelmente shellcode custom ou stage 1"

            self.info_output.append(f"Arquitetura provável: {arch}")
            self.info_output.append(f"Sistema Operacional: {os_target}")
            self.info_output.append(f"Gerador Possível: {fingerprint}")
            self.info_output.append("Heurísticas encontradas:")
            self.info_output.append("\n".join(indicators) or "[*] Nenhuma heurística forte detectada.")

        except Exception as e:
            self.info_output.setText(f"[!] Erro na análise: {str(e)}")



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

    def simulate_execution(self):
        hex_input = self.shellcode_input.toPlainText().strip()
        if not hex_input:
            self.exec_output.append("[!] Nenhum shellcode fornecido.")
            return

        try:
            self.exec_output.append("[*] Salvando shellcode em arquivo temporário...")
            shellcode_bytes = bytes.fromhex(hex_input.replace("\\x", "").replace(" ", ""))

            with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
                tmp.write(shellcode_bytes)
                tmp_path = tmp.name

            self.exec_output.append(f"[+] Shellcode salvo em: {tmp_path}")

            # Caminho absoluto do runner.py
            runner_path = os.path.abspath("runner.py")
            if not os.path.isfile(runner_path):
                self.exec_output.append(f"[!] runner.py não encontrado em: {runner_path}")
                return

            self.exec_output.append("[*] Executando runner.py em terminal externo...")

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
        try:
            code = self.shellcode_input.toPlainText().strip().replace("\\x", "").replace(" ", "")
            data = bytearray.fromhex(code)

            if all((b ^ data[0]) < 128 for b in data):
                key = data[0]
                decoded = bytearray([b ^ key for b in data])
                self.deob_output.append(f"[+] Possível XOR detectado com chave: 0x{key:02x}")
                self.deob_output.append(f"[*] Shellcode normalizado:\n{decoded.hex()}")
            else:
                nop_free = [b for b in data if b != 0x90]
                if len(nop_free) < len(data):
                    self.deob_output.append("[+] NOP sled detectado e removido.")
                    self.deob_output.append(f"[*] Shellcode limpo:\n{bytes(nop_free).hex()}")
                else:
                    self.deob_output.append("[*] Nenhum padrão de ofuscação comum identificado.")
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

if __name__ == '__main__':
    app = QApplication(sys.argv)
    tester = ShellcodeTesterPro()
    tester.show()
    sys.exit(app.exec_())