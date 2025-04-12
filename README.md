# Riot C2

> **Riot C2** is a lightweight, modular Command & Control framework built for stealth, persistence, and advanced post-exploitation. Designed to evade detection, scale across large environments, and remain operational under pressure, it is ideal for adversary emulation, red team training, and advanced security research.

---

## ✨ Features

- 🥷 **Stealth-First Architecture**
  - Anti-VM & sandbox evasion via advanced Kerpy-based module
  - Minimal process footprint, no obvious child-process trees
  - No suspicious persistence artifacts left behind

- 🔍 **System Reconnaissance**
  - Intelligent scanning for AV, system info, user privileges
  - Uses `psutil`, `subprocess`, and low-level Windows APIs

- 🔒 **AV & EDR Awareness**
  - Actively detects installed security software
  - Can disable or evade certain AV mechanisms on demand

- 🧠 **Modular Command Execution**
  - Supports custom scripts for aggressive actions (e.g. ransomware deployment, information theft, privilege escalation)
  - Dynamically adapts commands based on host intelligence

- 🌐 **Minimal Network Signature**
  - Sends no data unless explicitly commanded
  - Supports HTTP/DNS/Named Pipe transport (customizable)

- 🔁 **Persistence Ready**
  - Includes optional persistence routines using native Windows features
  - Executes at startup without triggering common detection rules

---

## 🛠️ Setup

### Requirements
- Python 3.10+
- `psutil`, `ctypes`, `requests`, etc.  
(Install via `requirements.txt`)

### Installation
```bash
git clone https://github.com/JancoNel/Riot-C2.git
cd Riot-C2
pip install -r requirements.txt
python riot.py
```

> ☠️ For testing in a safe environment only. Never run Riot C2 on unauthorized systems.

---

## 💡 Use Cases

| Use Case       | Description                                                   |
|----------------|---------------------------------------------------------------|
| 🛡️ Red Teaming | Simulate stealthy threat actors for blue team training        |
| 🧪 Research     | Analyze AV evasion and forensic evasion methods               |
| 🧰 Security Labs | Test real-world post-exploitation scenarios in safe, legal environments |

---

## ⚠️ Legal Notice

This tool is intended **for educational, research, and red teaming use only**.  
Unauthorized use on networks you do not own or have permission to test is **illegal** and unethical.

---

## 👨‍💻 Author

**JancoNel**  

[GitHub](https://github.com/JancoNel)

---
