# 🛡️ SnARPof: Advanced Network Auditor

**SnARPof** is a comprehensive network auditing and Man-in-the-Middle (MitM) testing suite built with a modern Python GUI for Windows environment. It allows security researchers to intercept, analyze, and manipulate network traffic in real-time using ARP spoofing and mitmproxy integration.

---

## ✨ Key Features

### 🖥️ GUI-Driven Interception
* **Modern Interface:** Built with `customtkinter` to manage network interfaces and monitor traffic effortlessly.
* **Live Interface Selection:** Auto-detects active network adapters for instant deployment.

### 🔍 Live Packet Analysis
* **Real-time Logging:** A packet tree that logs IP versions, protocols, header lengths, and payloads.
* **Sensitive Data Tagging:** Automatically scans payloads for keywords (e.g., "login", "password", "auth") and highlights them.

### 🎭 Traffic Manipulation (Mitmproxy Engine)
* **DNS Spoofing:** Redirect specific domains to custom IP addresses.
* **URL Responding:** Intercept specific URLs and return custom responses.
* **HTML Injection:** Inject custom scripts or replace HTML content on-the-fly in unencrypted traffic.

### 👁️ Advanced Audit Tools
* **BrowserSpy:** Leverage `html2canvas.min.js` to gain a live visual preview of a target's browser DOM.
* **Certificate Portal:** A built-in portal to facilitate the installation of root CA certificates for HTTPS inspection testing.

---

## 🚀 Installation & Setup

### Prerequisites
* **Windows 10 or 11** with **Administrator permissions**
* **Python 3.10** or higher.
### Quick Start
1. **Clone the Repository:**
   ```cmd
   git clone https://github.com/arslanbekcanov20-hash/SnARPof.git
   cd SnARPof
   ```
2. **Install Dependencies:**
   ```cmd
   curl -L -o npcap-1.87.exe https://npcap.com/dist/npcap-1.87.exe
   curl -L -o mitmproxy-12-2-1.exe https://downloads.mitmproxy.org/12.2.1/mitmproxy-12.2.1-windows-x86_64-installer.exe
   pip install -r requirements.txt
   ```
3. **Run the Application:**
   ```cmd
   python snarpof.py
   ```

---

## 🛠️ Building the Executable
To generate a standalone `.exe` file, ensure Nuitka is installed and run:
```cmd
chcp 65001 >nul
exe_compiler.bat
```

---

## ⚠️ Disclaimer (FOR EDUCATIONAL PURPOSES ONLY)

> **IMPORTANT: READ CAREFULLY BEFORE USE**

This tool is designed for educational purposes and authorized security auditing only. 
* **Authorization:** Unauthorized access to a computer system or network is illegal. Use only with explicit, written permission.
* **Liability:** The developer assumes no liability for any damage, loss of data, or legal consequences resulting from the misuse of this tool.
* **Responsibility:** By using this software, you agree that you are solely responsible for your actions and will comply with all local, state, and federal laws.

**Never use this tool on a public network or any network you do not own/manage.**

---

## 📄 License

**Copyright © 2026 Arslan Bekchanov. All rights reserved.**

This software is provided for private use and research. Redistribution or commercial use of this code, or any derivative works, requires explicit written permission from the copyright holder.
