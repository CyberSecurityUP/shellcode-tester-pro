## 📁 `shellcode_execution.md`

### 🇧🇷 Execução de Shellcode

A aba **"Importação e Execução"** permite colar ou importar arquivos `.bin` contendo shellcode.

#### Funcionalidades:
- **Entrada direta:** Cole shellcode no formato `\x90\x90\xcc...` ou hex puro.
- **Carregar arquivo:** Importa um `.bin` e converte para shellcode.
- **Executar (Simulado):** Simula a execução real em um terminal separado, usando chamadas nativas via `ctypes`.

⚠️ **Atenção:** A execução real pode causar danos ao sistema se o shellcode for malicioso.

---

### 🇺🇸 Shellcode Execution

The **"Import & Execution"** tab allows pasting or importing `.bin` shellcode files.

#### Features:
- **Direct input:** Paste shellcode in `\x90\x90\xcc...` or raw hex format.
- **Load file:** Imports a `.bin` and converts it to shellcode format.
- **Run (Simulated):** Simulates real execution in a separate terminal using native `ctypes` calls.

⚠️ **Warning:** Real execution can harm your system if the shellcode is malicious.

