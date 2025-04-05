### 🇧🇷 Sandbox / Análise Heurística

A aba **"Sandbox Heurística"** realiza uma análise estática de comportamentos maliciosos com base em padrões conhecidos.

#### Detecta:
- Shell reverso (`/bin/sh`, `cmd.exe`)
- APIs sensíveis (`WinExec`, `socket`)
- Conexões suspeitas (uso de `connect`, `ShellExecute`, etc.)

Não executa o código, apenas analisa padrões no shellcode para avaliar riscos.

---

### 🇺🇸 Sandbox / Heuristic Analysis

The **"Heuristic Sandbox"** tab performs static behavior analysis based on known malicious patterns.

#### Detects:
- Reverse shells (`/bin/sh`, `cmd.exe`)
- Suspicious APIs (`WinExec`, `socket`)
- Potential C2 behavior (`connect`, `ShellExecute`, etc.)

Does **not** execute the shellcode, only analyzes byte patterns for risk assessment.

