## 📁 `deobfuscation.md`

### 🇧🇷 Desofuscação e Criptografia

A aba **"Desofuscação / Normalização"** realiza análise para detectar técnicas de ofuscação e criptografia em shellcodes.

#### Recursos:
- Detecção de XOR simples (com brute-force de chaves)
- Identificação de **NOP sleds** e remoção
- Cálculo de **entropia** para indicar criptografia (RC4, AES, etc.)
- Padrões típicos de criptografia de payloads

Ideal para shellcodes protegidos com camadas de encoding/obfuscation.

---

### 🇺🇸 Deobfuscation and Encryption

The **"Deobfuscation / Normalization"** tab analyzes shellcodes to detect obfuscation and encryption techniques.

#### Features:
- XOR detection (with brute-force key guess)
- **NOP sled** detection and cleanup
- **Entropy** calculation to detect possible encryption (RC4, AES, etc.)
- Typical payload encryption patterns

Perfect for analyzing encoded or protected shellcode layers.

