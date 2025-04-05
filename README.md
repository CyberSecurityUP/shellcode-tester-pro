# Shellcode Tester Pro - English

**Shellcode Tester Pro** is a graphical interface tool for analysis, simulated execution, and reverse engineering of malicious shellcodes.
![image](https://github.com/user-attachments/assets/13d60413-2e05-461c-a249-106902424e42)


## Features

- Import shellcode in `\x` format, raw hex, or binary files (.bin/.exe/.elf)
- Emulate execution using the Unicorn Engine
- Run simulated execution in an external terminal
- Detects fingerprints from tools like **msfvenom**, **Cobalt Strike**, **Sliver**, **Empire**, etc.
- Performs heuristic behavior analysis
- Extracts shellcodes from binaries
- Generates disassembly with Capstone
- Detects NOP sleds, encryption, and obfuscation
- Deobfuscates shellcodes using XOR, dumps memory, and exports to PDF
- Plugin system for custom extensions

## Installation

```bash
sudo apt update && sudo apt install nasm python3 python3-pyqt5 xterm gnome-terminal
pip install -r requirements.txt
```

## Usage

```bash
python3 main_gui.py
```

## Developing Plugins

See [docs/plugins.md](docs/plugins.md) to create your own plugin and extend the tool's functionalities.

---

**Author:** Joas Antonio dos Santos  
**GitHub:** [@CyberSecurityUP](https://github.com/CyberSecurityUP)  
**Documentation:** [docs/](docs/)

# Shellcode Tester Pro - Portuguese

Shellcode Tester Pro é uma ferramenta com interface gráfica para análise, execução simulada e engenharia reversa de shellcodes maliciosos.

![image](https://github.com/user-attachments/assets/8893c547-4cd0-465b-88b9-e38a7378a4c4)

## Funcionalidades

- Importa shellcode em \x, hex puro ou binário (.bin/.exe/.elf)
- Emula execução com Unicorn Engine
- Executa simulação com terminal externo
- Detecta fingerprint de ferramentas como msfvenom, Cobalt Strike, Sliver, Empire, etc.
- Realiza análise heurística de comportamento
- Extrai shellcodes de binários
- Gera desassembly com Capstone
- Detecta NOP sled, criptografia e ofuscação
- Desofusca shellcodes com XOR, dumpa memória, gera PDF
- Sistema de plugins customizados

## Instalação

```bash
sudo apt update && sudo apt install nasm python3 python3-pyqt5 xterm gnome-terminal
pip install -r requirements.txt
```

## Execução

```bash
python3 main_gui.py
```

## Desenvolvendo Plugins
Veja [docs/plugins.md](docs/plugins.md) para criar seu próprio plugin e estender as funcionalidades da ferramenta.

---

**Autor:** Joas Antonio dos Santos  
**GitHub:** [@CyberSecurityUP](https://github.com/CyberSecurityUP)  
**Documentação:** [docs/](docs/)

