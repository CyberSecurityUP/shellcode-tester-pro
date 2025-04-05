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
from plugins import plugin_manager
import json
import re
import hashlib



class ShellcodeTesterPro(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Shellcode Tester Pro")
        self.setGeometry(100, 100, 900, 700)
        self.set_dark_theme()
        self.dark_mode = True 
        self.init_ui()
        self.plugin_refs = {}  
        self.loaded_plugins = []  
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
    
        toggle_theme_btn = QPushButton("Toggle Light/Dark Mode")
        toggle_theme_btn.clicked.connect(self.toggle_theme)
        layout.addWidget(toggle_theme_btn)
    
        credit_btn = QPushButton("❓")
        credit_btn.setFixedSize(30, 30)
        credit_btn.setToolTip("About Shellcode Tester Pro")
        credit_btn.clicked.connect(self.show_credits)
    
        header_layout = QHBoxLayout()
        header_layout.addWidget(toggle_theme_btn)
        header_layout.addStretch()
        header_layout.addWidget(credit_btn)
        layout.addLayout(header_layout)
    
        # Create tabs
        self.execution_tab = self.create_execution_tab()
        self.unicorn_tab = self.create_unicorn_tab()
        self.sandbox_tab = self.create_sandbox_tab()
        self.deobfuscation_tab = self.create_deobfuscation_tab()
        self.memory_tab = self.create_memory_tab()
        self.step_tab = self.create_step_tab()
        self.remote_tab = self.create_remote_tab()
        # self.pdf_tab = self.create_pdf_tab()
        self.capstone_tab = self.create_analysis_tab()
        self.info_tab = self.create_info_tab()
        self.loaded_plugins = []
        self.tabs = tabs 
        self.load_plugins()
        self.evasion_tab = self.create_evasion_tab()
        self.binary_tab = self.create_binary_tab()
    
        # Add tabs
        tabs.addTab(self.execution_tab, "Import and Execute")
        tabs.addTab(self.unicorn_tab, "Unicorn Emulator")
        tabs.addTab(self.sandbox_tab, "Heuristic Sandbox")
        tabs.addTab(self.deobfuscation_tab, "Deobfuscation and Cryptography")
        tabs.addTab(self.memory_tab, "Hex Memory Dump")
        tabs.addTab(self.step_tab, "Step-by-Step Execution")
        tabs.addTab(self.remote_tab, "Remote Shellcode")
        # tabs.addTab(self.pdf_tab, "Export PDF")
        tabs.addTab(self.capstone_tab, "Disassembly")
        tabs.addTab(self.info_tab, "Fingerprint")
        tabs.addTab(self.evasion_tab, "Evasion Analysis")
        tabs.addTab(self.binary_tab, "Binary Analysis")
        
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
        plugins_path = os.path.join(os.path.dirname(__file__), "plugins")
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
    
        self.load_binary_btn = QPushButton("Load ELF or EXE")
        self.load_binary_btn.clicked.connect(self.analyze_binary_file)
    
        self.export_shellcode_btn = QPushButton("Export Suspicious Shellcode")
        self.export_shellcode_btn.setEnabled(False)
        self.export_shellcode_btn.clicked.connect(self.export_extracted_shellcode)
    
        layout.addWidget(QLabel("ELF / EXE Binary Analysis"))
        layout.addWidget(self.load_binary_btn)
        layout.addWidget(self.export_shellcode_btn)
        layout.addWidget(self.binary_output)
        tab.setLayout(layout)
    
        return tab


    def analyze_binary_file(self):
        self.binary_output.clear()
        self.suspect_shellcodes = []
    
        file_path, _ = QFileDialog.getOpenFileName(self, "Open ELF or EXE file", "", "Executables (*.exe *.bin *.elf *.out)")
        if not file_path:
            self.binary_output.setText("[!] No file selected.")
            return
    
        try:
            with open(file_path, "rb") as f:
                data = f.read()
    
            self.binary_output.append(f"[+] File loaded: {file_path}")
            self.binary_output.append(f"[+] Size: {len(data)} bytes")
    
            findings = []
    
            if b"VirtualAlloc" in data or b"CreateThread" in data:
                findings.append("[!] Windows API detected (possible shellcode)")
            if b"/bin/sh" in data:
                findings.append("[!] String '/bin/sh' detected")
            if b"mmap" in data:
                findings.append("[!] mmap detected")
            if data.count(b"\x90") > 50:
                findings.append("[!] NOP sled detected (> 50 bytes)")
    
            hex_patterns = re.findall(rb'(?:\\x[0-9a-fA-F]{2}){10,}', data)
            if hex_patterns:
                findings.append(f"[!] {len(hex_patterns)} inline hex buffer(s) found")
    
            blocks = re.findall(rb'([\x90-\xff]{30,})', data)
            for idx, block in enumerate(blocks):
                self.suspect_shellcodes.append(block)
    
            if blocks:
                findings.append(f"[!] {len(blocks)} suspicious binary block(s) found")
                for i, b in enumerate(blocks[:3]):  # Show up to 3 previews
                    preview = ' '.join(f"{byte:02x}" for byte in b[:32])
                    self.binary_output.append(f"[+] Block {i+1} ({len(b)} bytes): {preview}...")
    
            if not findings:
                self.binary_output.append("[*] No suspicious patterns found.")
            else:
                self.binary_output.append("\n".join(findings))
    
            if self.suspect_shellcodes:
                self.export_shellcode_btn.setEnabled(True)
    
        except Exception as e:
            self.binary_output.setText(f"[!] Error analyzing file: {str(e)}")



    def export_extracted_shellcode(self):
        try:
            base_path, _ = QFileDialog.getSaveFileName(self, "Save Shellcode", "extracted_shellcode", "Binary Files (*.bin)")
            if base_path:
                for i, blob in enumerate(self.suspect_shellcodes):
                    filename = f"{base_path}_part{i+1}.bin"
                    with open(filename, "wb") as f:
                        f.write(blob)
                self.binary_output.append(f"[+] {len(self.suspect_shellcodes)} shellcode(s) exported to files!")
        except Exception as e:
            self.binary_output.append(f"[!] Error saving shellcodes: {str(e)}")


    def create_analysis_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
    
        self.analysis_input = QTextEdit()
        self.analysis_output = QTextEdit()
        self.analysis_output.setReadOnly(True)
    
        analyze_btn = QPushButton("Analyze with Capstone")
        analyze_btn.clicked.connect(self.analyze_capstone)
    
        export_btn = QPushButton("Export Analysis Result")
        export_btn.clicked.connect(self.export_analysis_result)
    
        layout.addWidget(QLabel("Shellcode for Analysis:"))
        layout.addWidget(self.analysis_input)
        layout.addWidget(analyze_btn)
        layout.addWidget(export_btn)
        layout.addWidget(QLabel("Capstone Result:"))
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
            self.analysis_output.setText("[!] No shellcode provided.")
            return
    
        try:
            # Same handling as the global parser
            cleaned = raw.replace('"', '').replace("'", "").replace(';', '')
            cleaned = re.sub(r"[\n\r\t,]", "", cleaned)
    
            if "\\x" in cleaned:
                hex_str = cleaned.replace("\\x", "")
            else:
                hex_str = re.sub(r"[^0-9a-fA-F]", "", cleaned)
    
            if not re.fullmatch(r"[0-9a-fA-F]+", hex_str):
                self.analysis_output.setText("[!] Shellcode contains invalid characters.")
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
    
            self.analysis_output.append(f"[+] Detected architecture: {arch} | Mode: {mode}")
            self.analysis_output.append(f"[+] Total instructions: {len(result)}\n")
    
            if suspicious:
                self.analysis_output.append("[!] Suspicious instructions:")
                self.analysis_output.append("\n".join(suspicious))
                self.analysis_output.append("")
    
            self.analysis_output.append("[+] Full disassembly:")
            self.analysis_output.append("\n".join(result))
    
        except Exception as e:
            self.analysis_output.setText(f"[!] Error: {str(e)}")


    def export_analysis_result(self):
        try:
            content = self.analysis_output.toPlainText()
            if not content:
                QMessageBox.warning(self, "Warning", "No result to export.")
                return
            path, _ = QFileDialog.getSaveFileName(self, "Save Result", "analysis.txt", "Text Files (*.txt)")
            if path:
                with open(path, "w") as f:
                    f.write(content)
                QMessageBox.information(self, "Saved", f"Analysis saved to: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def load_shellcode_bin(self):
        try:
            file, _ = QFileDialog.getOpenFileName(self, "Open Binary File", "", "Binary Files (*.bin *.exe *.elf)")
            if not file:
                self.exec_output.append("[!] No file selected.")
                return
    
            with open(file, "rb") as f:
                data = f.read()
                hexcode = ''.join(f'\\x{b:02x}' for b in data)
                self.shellcode_input.setPlainText(hexcode)
                self.exec_output.append(f"[+] File loaded: {file} ({len(data)} bytes)")
    
        except Exception as e:
            self.exec_output.append(f"[!] Error loading file: {str(e)}")

    def create_step_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
    
        self.step_output = QTextEdit()
        self.step_output.setReadOnly(True)
    
        step_btn = QPushButton("Execute Step by Step")
        step_btn.clicked.connect(self.step_by_step_unicorn)
    
        layout.addWidget(QLabel("Execution with Unicorn (Step-by-Step):"))
        layout.addWidget(step_btn)
        layout.addWidget(self.step_output)
        tab.setLayout(layout)
        return tab


    def create_execution_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
    
        self.shellcode_input = QTextEdit()
        self.shellcode_input.setPlaceholderText("Paste your shellcode in hexadecimal or \\x.. format here")
        self.shellcode_input.setStyleSheet("color: white; background-color: #1e1e1e;")
        layout.addWidget(QLabel("Shellcode:"))
        layout.addWidget(self.shellcode_input)
    
        # Action buttons
        button_layout = QHBoxLayout()
    
        run_btn = QPushButton("Execute (Simulated)")
        run_btn.clicked.connect(self.simulate_execution)
        button_layout.addWidget(run_btn)
    
        load_btn = QPushButton("Load .bin File")
        load_btn.clicked.connect(self.load_shellcode_bin)
        button_layout.addWidget(load_btn)
    
        layout.addLayout(button_layout)
    
        self.exec_output = QTextEdit()
        self.exec_output.setReadOnly(True)
        layout.addWidget(QLabel("Execution Log:"))
        layout.addWidget(self.exec_output)
    
        tab.setLayout(layout)
        return tab


    def create_remote_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
    
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com/shellcode.txt or .bin")
    
        self.import_mode = QComboBox()
        self.import_mode.addItems(["\\x formatted", "Raw Hex", "RAW Binary"])
    
        fetch_btn = QPushButton("Load Shellcode from URL")
        fetch_btn.clicked.connect(self.fetch_remote_shellcode)
    
        self.remote_output = QTextEdit()
        self.remote_output.setReadOnly(True)
    
        layout.addWidget(QLabel("Shellcode URL:"))
        layout.addWidget(self.url_input)
        layout.addWidget(QLabel("Import Mode:"))
        layout.addWidget(self.import_mode)
        layout.addWidget(fetch_btn)
        layout.addWidget(QLabel("Remote Shellcode Log:"))
        layout.addWidget(self.remote_output)
    
        tab.setLayout(layout)
        return tab


    def fetch_remote_shellcode(self):
    
        self.remote_output.clear()
        url = self.url_input.text().strip()
        if not url:
            self.remote_output.setText("[!] No URL provided.")
            return
    
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            content = response.content
    
            sha256 = hashlib.sha256(content).hexdigest()
            self.remote_output.append(f"[+] SHA256: {sha256}")
            self.remote_output.append(f"[+] MIME: {response.headers.get('Content-Type', 'unknown')}")
            self.remote_output.append(f"[+] Size: {len(content)} bytes\n")
    
            mode = self.import_mode.currentText()
    
            if mode == "\\x formatted":
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
    
            elif mode == "Raw Hex":
                hexed = ''.join(f"{b:02x}" for b in content)
                self.shellcode_input.setPlainText(hexed)
    
            elif mode == "RAW Binary":
                path = os.path.join("downloads", os.path.basename(url) or "shellcode_raw.bin")
                os.makedirs("downloads", exist_ok=True)
                with open(path, "wb") as f:
                    f.write(content)
                self.shellcode_input.setPlainText("")  # don't display in input field
                self.remote_output.append(f"[✓] Shellcode saved as: {path}")
    
            self.remote_output.append("[✓] Shellcode loaded successfully!")
    
        except Exception as e:
            self.remote_output.setText(f"[!] Error fetching shellcode: {str(e)}")


    def step_by_step_unicorn(self):
        self.step_output.clear()
        try:
            code = self.shellcode_input.toPlainText().strip().replace("\\x", "").replace(" ", "")
            shellcode = bytes.fromhex(code)
            ADDRESS = 0x1000000
            STACK_ADDR = 0x200000
            STACK_SIZE = 2 * 2048 * 2048
    
            mu = Uc(UC_ARCH_X86, UC_MODE_64)
            mu.mem_map(ADDRESS, 2 * 1024 * 1024)
            mu.mem_write(ADDRESS, shellcode)
            mu.mem_map(STACK_ADDR, STACK_SIZE)
            mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE // 2)
    
            self.step_output.append("[*] Starting step-by-step execution...")
    
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
            self.step_output.append(f"[!] Error during step-by-step execution: {str(e)}")

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
    
            arch = "Unknown"
            os_target = "Unknown"
            indicators = []
            fingerprint = "Unknown"
    
            self.info_output.append(f"[*] Shellcode size: {len(data)} bytes\n")
    
            # OS and architecture detection
            if b"/bin/sh" in data:
                os_target = "Linux"
                indicators.append("[*] String '/bin/sh' detected (Linux)")
            if b"cmd.exe" in data or b"powershell" in data:
                os_target = "Windows"
                indicators.append("[*] String 'cmd.exe' or 'powershell' detected (Windows)")
    
            # Architecture based on instruction patterns
            if b"\x0f\x05" in data:
                indicators.append("[*] 'syscall' instruction detected (Linux x64)")
            if b"\xcd\x80" in data:
                indicators.append("[*] 'int 0x80' instruction detected (Linux x86)")
            if b"\x0f\x34" in data:
                indicators.append("[*] 'sysenter' instruction detected (Windows x86)")
            if b"\x48" in data or b"\x49" in data:
                arch = "x86_64"
                indicators.append("[*] REX prefix usage detected (64-bit)")
            elif b"\x66" in data or b"\xb8" in data:
                arch = "x86"
                indicators.append("[*] Typical 32-bit instructions detected")
    
            # Windows API detection
            for api in [b"VirtualAlloc", b"LoadLibrary", b"GetProcAddress", b"WinExec"]:
                if api in data:
                    indicators.append(f"[+] Windows API detected: {api.decode()}")
    
            # NOP sled detection
            nop_count = data.count(b"\x90")
            if nop_count > 8:
                indicators.append(f"[+] NOP sled detected ({nop_count} bytes of 0x90)")
    
            # Tool/Generator fingerprinting
            if b"EXITFUNC" in data or b"Metasploit" in data:
                fingerprint = "msfvenom"
                indicators.append("[+] Metasploit textual signature found")
            elif nop_count > 10:
                fingerprint = "Possibly msfvenom"
                indicators.append("[+] Long NOP sled (typical of msfvenom)")
    
            if b"Donut" in data or b".text" in data or b"mscoree.dll" in data:
                fingerprint = "Donut"
                indicators.append("[+] Donut payload signatures detected")
    
            if b"powershell -nop" in data or b"DownloadString" in data:
                fingerprint = "Empire / PowerShell"
                indicators.append("[+] Empire / PowerShell signature detected")
    
            if b"beacon" in data or b"ReflectiveLoader" in data:
                fingerprint = "Cobalt Strike"
                indicators.append("[+] Possible Cobalt Strike shellcode")
    
            if b"sliver" in data or b"rpc" in data:
                fingerprint = "Sliver"
                indicators.append("[+] Possible Sliver C2 shellcode")
    
            if b"Meterpreter" in data or b"reverse_tcp" in data:
                fingerprint = "Meterpreter"
                indicators.append("[+] Signs of Meterpreter shellcode")
    
            if b"Shellter" in data:
                fingerprint = "Shellter"
                indicators.append("[+] Possibly generated with Shellter")
    
            if fingerprint == "Unknown" and len(data) < 100:
                fingerprint = "Possibly custom or stage 1 shellcode"
    
            # Final result
            self.info_output.append(f"Likely Architecture: {arch}")
            self.info_output.append(f"Target Operating System: {os_target}")
            self.info_output.append(f"Possible Generator: {fingerprint}")
            self.info_output.append("\nDetected Heuristics:")
            self.info_output.append("\n".join(indicators) or "[*] No strong heuristics detected.")
    
        except Exception as e:
            self.info_output.setText(f"[!] Error during analysis: {str(e)}")

    def create_evasion_tab(self):
        from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QPushButton, QLabel
    
        tab = QWidget()
        layout = QVBoxLayout()
    
        self.evasion_output = QTextEdit()
        self.evasion_output.setReadOnly(True)
    
        btn = QPushButton("Run Evasion Analysis")
        btn.clicked.connect(self.run_evasion_analysis)
    
        layout.addWidget(QLabel("Evasion Technique Analysis:"))
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
                self.evasion_output.append("[*] No evasion techniques identified.")
        except Exception as e:
            self.evasion_output.setText(f"[!] Error: {str(e)}")



    def check_evasion_techniques(self, data: bytes):
        findings = []
    
        # 1. Anti-sandbox strings
        sandbox_indicators = [b"vbox", b"vmware", b"qemu", b"sandbox", b"VBoxService", b"virtualbox"]
        for s in sandbox_indicators:
            if s in data:
                findings.append(f"[!] Sandbox indicator detected: {s.decode(errors='ignore')}")
    
        # 2. Anti-debugging and timing checks
        apis = [b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent", b"NtQueryInformationProcess",
                b"GetTickCount", b"QueryPerformanceCounter", b"Sleep", b"rdtsc", b"cpuid"]
        for api in apis:
            if api in data:
                findings.append(f"[!] Use of evasion/debugging/sandbox API: {api.decode(errors='ignore')}")
    
        # 3. Security disabling attempts
        targets = [b"avp.exe", b"defender", b"MsMpEng.exe", b"taskkill", b"firewall", b"securityhealthservice"]
        for t in targets:
            if t in data:
                findings.append(f"[!] Attempt to disable security software: {t.decode(errors='ignore')}")
    
        return findings


    def run_unicorn(self):
        self.unicorn_output.clear()
        try:
            code = self.shellcode_input.toPlainText().strip().replace("\\x", "").replace(" ", "")
            shellcode = bytes.fromhex(code)
    
            ADDRESS = 0x1000000           # Where the shellcode will be loaded
            CODE_SIZE = 2 * 1024 * 1024   # 2MB for the shellcode
            STACK_ADDR = 0x200000         # Stack address
            STACK_SIZE = 2 * 1024 * 1024  # 2MB stack size
    
            mu = Uc(UC_ARCH_X86, UC_MODE_64)
    
            # Map memory for shellcode
            mu.mem_map(ADDRESS, CODE_SIZE)
            mu.mem_write(ADDRESS, shellcode)
    
            # Map memory for stack
            mu.mem_map(STACK_ADDR, STACK_SIZE)
            mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE // 2)
    
            # Optional: hook for memory debug
            def hook_mem_invalid(uc, access, address, size, value, user_data):
                if access == UC_MEM_WRITE_UNMAPPED:
                    self.unicorn_output.append(f"[!] Invalid WRITE at 0x{address:x}")
                elif access == UC_MEM_READ_UNMAPPED:
                    self.unicorn_output.append(f"[!] Invalid READ at 0x{address:x}")
                elif access == UC_MEM_FETCH_UNMAPPED:
                    self.unicorn_output.append(f"[!] Invalid FETCH at 0x{address:x}")
                return False  # don't try to continue
    
            mu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)
    
            self.unicorn_output.append("[*] Starting emulation with Unicorn...")
            mu.emu_start(ADDRESS, ADDRESS + len(shellcode))
            self.unicorn_output.append("[+] Shellcode emulated successfully!")
    
            rax = mu.reg_read(UC_X86_REG_RAX)
            rip = mu.reg_read(UC_X86_REG_RIP)
            self.unicorn_output.append(f"[*] RAX: 0x{rax:x} | RIP: 0x{rip:x}")
    
        except UcError as ue:
            self.unicorn_output.append(f"[!] Unicorn Exception: {ue}")
        except Exception as e:
            self.unicorn_output.append(f"[!] Emulation error: {str(e)}")


    def create_info_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
    
        self.info_output = QTextEdit()
        self.info_output.setReadOnly(True)
    
        analyze_btn = QPushButton("Analyze Fingerprint")
        analyze_btn.clicked.connect(self.analyze_shellcode_fingerprint)
    
        layout.addWidget(analyze_btn)
        layout.addWidget(QLabel("Heuristic Fingerprint Analysis Result:"))
        layout.addWidget(self.info_output)
        tab.setLayout(layout)
        return tab

    def create_unicorn_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
    
        self.unicorn_output = QTextEdit()
        self.unicorn_output.setReadOnly(True)
    
        run_btn = QPushButton("Emulate with Unicorn")
        run_btn.clicked.connect(self.run_unicorn)
    
        layout.addWidget(QLabel("Emulation Result:"))
        layout.addWidget(run_btn)
        layout.addWidget(self.unicorn_output)
        tab.setLayout(layout)
        return tab


    def create_sandbox_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
    
        self.sandbox_output = QTextEdit()
        self.sandbox_output.setReadOnly(True)
    
        analyze_btn = QPushButton("Analyze Behavior")
        analyze_btn.clicked.connect(self.heuristic_analysis)
    
        layout.addWidget(QLabel("Sandbox / Behavior Detection:"))
        layout.addWidget(analyze_btn)
        layout.addWidget(self.sandbox_output)
    
        tab.setLayout(layout)
        return tab

    def create_deobfuscation_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
    
        self.deob_output = QTextEdit()
        self.deob_output.setReadOnly(True)
    
        deob_btn = QPushButton("Analyze and Deobfuscate")
        deob_btn.clicked.connect(self.analyze_and_deobfuscate)
    
        layout.addWidget(QLabel("Deobfuscation / Normalization:"))
        layout.addWidget(deob_btn)
        layout.addWidget(self.deob_output)
    
        tab.setLayout(layout)
        return tab


    def create_memory_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
    
        self.mem_output = QTextEdit()
        self.mem_output.setReadOnly(True)
        
        dump_btn = QPushButton("View Formatted Shellcode")
        dump_btn.clicked.connect(self.dump_memory_style)
    
        layout.addWidget(QLabel("Memory Viewer (Hex + ASCII):"))
        layout.addWidget(dump_btn)
        layout.addWidget(self.mem_output)
    
        tab.setLayout(layout)
        return tab

        
    def get_shellcode_bytes(self):
        raw_input = self.shellcode_input.toPlainText().strip()
    
        if not raw_input:
            return b'', "[!] No shellcode provided."
    
        try:
            # Remove quotes and semicolons
            cleaned = raw_input.replace('"', '').replace("'", "").replace(';', '')
    
            # Remove commas, newlines, tabs, etc.
            cleaned = re.sub(r"[\n\r\t,]", "", cleaned)
    
            # Handle \x format
            if "\\x" in cleaned:
                hex_str = cleaned.replace("\\x", "")
            else:
                hex_str = re.sub(r"[^0-9a-fA-F]", "", cleaned)
    
            if not re.fullmatch(r"[0-9a-fA-F]+", hex_str):
                return b'', "[!] Shellcode contains invalid characters."
    
            if len(hex_str) % 2 != 0:
                hex_str = "0" + hex_str
    
            return bytes.fromhex(hex_str), ""
    
        except Exception as e:
            return b'', f"[!] Error processing shellcode: {str(e)}"
    

    def simulate_execution(self):
        self.exec_output.clear()
    
        shellcode_bytes, error = self.get_shellcode_bytes()
        if error:
            self.exec_output.append(error)
            return
    
        try:
            self.exec_output.append(f"[+] Shellcode successfully formatted ({len(shellcode_bytes)} bytes).")
    
            with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
                tmp.write(shellcode_bytes)
                tmp_path = tmp.name
    
            self.exec_output.append(f"[+] Shellcode saved to: {tmp_path}")
    
            runner_path = os.path.abspath("runner.py")
            if not os.path.isfile(runner_path):
                self.exec_output.append(f"[!] runner.py not found at: {runner_path}")
                return
    
            self.exec_output.append("[*] Launching runner.py in external terminal...")
    
            if os.system("which gnome-terminal") == 0:
                term_cmd = ["gnome-terminal", "--", "python3", runner_path, tmp_path]
            elif os.system("which xterm") == 0:
                term_cmd = ["xterm", "-e", f"python3 {runner_path} {tmp_path}; bash"]
            elif os.system("which konsole") == 0:
                term_cmd = ["konsole", "-e", f"python3 {runner_path} {tmp_path}; bash"]
            else:
                self.exec_output.append("[!] No compatible terminal found.")
                return
    
            subprocess.Popen(term_cmd)
            self.exec_output.append("[+] Shellcode is running in another terminal.")
    
        except Exception as e:
            self.exec_output.append(f"[!] Error: {str(e)}")



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
    
            ADDRESS = 0x1000000       # base address for shellcode
            STACK_ADDR = 0x200000     # stack address
            STACK_SIZE = 2 * 1024 * 1024  # 2MB stack size
    
            mu = Uc(UC_ARCH_X86, UC_MODE_64)
    
            # Map memory for shellcode and stack
            mu.mem_map(ADDRESS, 2 * 1024 * 1024)
            mu.mem_write(ADDRESS, shellcode)
            mu.mem_map(STACK_ADDR, STACK_SIZE)
    
            # Set stack register
            mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE // 2)
    
            self.unicorn_output.append("[*] Starting emulation with Unicorn...")
            mu.emu_start(ADDRESS, ADDRESS + len(shellcode))
            self.unicorn_output.append("[+] Shellcode emulated successfully!")
    
            rax = mu.reg_read(UC_X86_REG_RAX)
            rip = mu.reg_read(UC_X86_REG_RIP)
            self.unicorn_output.append(f"[*] RAX: 0x{rax:x} | RIP: 0x{rip:x}")
    
        except Exception as e:
            self.unicorn_output.append(f"[!] Emulation error: {str(e)}")



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
                alerts.append("[⚠️] Detection: '/bin/sh' found (possible Linux reverse shell)")
            if b"cmd.exe" in shellcode:
                alerts.append("[⚠️] Detection: 'cmd.exe' found (possible Windows reverse shell)")
            if b"socket" in shellcode or b"connect" in shellcode:
                alerts.append("[⚠️] Detection: use of 'socket' or 'connect'")
            if b"WinExec" in shellcode or b"ShellExecute" in shellcode:
                alerts.append("[⚠️] Detection: Windows API found (remote execution)")
    
            if not alerts:
                self.sandbox_output.append("[*] No suspicious behavior identified.")
            else:
                self.sandbox_output.append("[*] Triggered Heuristics:\n")
                for alert in alerts:
                    self.sandbox_output.append(alert)
    
        except Exception as e:
            self.sandbox_output.append(f"[!] Heuristic analysis error: {str(e)}")

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
    
            # 1. Detect possible XOR obfuscation
            xor_detected = False
            for key in range(1, 256):
                decoded = bytearray([b ^ key for b in data])
                if all(32 <= c <= 126 or c == 0 for c in decoded[:40]):  # readable ASCII
                    self.deob_output.append(f"[+] Possible XOR detected with key: 0x{key:02x}")
                    self.deob_output.append(f"[*] Normalized shellcode:\n{decoded.hex()}")
                    xor_detected = True
                    break
    
            # 2. Detect NOP sled
            if not xor_detected:
                nop_free = [b for b in data if b != 0x90]
                if len(nop_free) < len(data):
                    self.deob_output.append("[+] NOP sled detected and removed.")
                    self.deob_output.append(f"[*] Clean shellcode:\n{bytes(nop_free).hex()}")
    
            # 3. Detect AES-like patterns by repeated 16-byte blocks
            blocks = [data[i:i+16] for i in range(0, len(data)-15, 16)]
            block_set = set(bytes(b) for b in blocks)
            if len(block_set) < len(blocks) * 0.8 and len(blocks) >= 3:
                self.deob_output.append("[!] AES-like pattern detected (repeated 16-byte blocks)")
    
            # 4. Detect RC4 or high-entropy encryption
            entropy = calc_entropy(data)
            self.deob_output.append(f"[*] Entropy: {entropy:.2f}")
            if entropy > 7.5:
                self.deob_output.append("[!] High entropy detected — possible RC4, AES, or other encryption.")
    
            if not xor_detected and entropy < 5:
                self.deob_output.append("[*] Shellcode does not appear to be encrypted.")
            elif not xor_detected:
                self.deob_output.append("[*] Could not automatically deobfuscate, but encryption is suspected.")
    
        except Exception as e:
            self.deob_output.append(f"[!] Error during deobfuscation analysis: {str(e)}")


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
            self.mem_output.setPlainText(f"[!] Error generating memory dump: {str(e)}")

   
    def show_credits(self):
        QMessageBox.information(self, "About Shellcode Tester Pro",
            "🔐 Shellcode Tester Pro\n\n"
            "👨‍💻 Created by: Joas Antonio dos Santos\n"
            "🌐 GitHub: https://github.com/CyberSecurityUP/Shellcode-Tester-Pro\n"
            "📖 Documentation: https://github.com/CyberSecurityUP/Shellcode-Tester-Pro/docs/\n"
            "🐦 Twitter: @C0d3Cr4zy\n"
            "🔗 LinkedIn: https://www.linkedin.com/in/joas-antonio-dos-santos/\n\n"
            "🧠 Open-source project for safe shellcode analysis\n"
            "💥 Warning: Running real code can be dangerous.\n\n"
            "© 2025 - All rights reserved."
        )

if __name__ == '__main__':
    app = QApplication(sys.argv)
    tester = ShellcodeTesterPro()
    tester.show()
    sys.exit(app.exec_())
