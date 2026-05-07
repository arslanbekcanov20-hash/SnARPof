# 🛡️ SnARPof: Advanced Network Auditor

**SnARPof** is a comprehensive network auditing and Man-in-the-Middle (MitM) testing suite built with a modern Python GUI for Windows environment. It allows security researchers to intercept, analyze, and manipulate network traffic in real-time.

---

## ✨ Key Features

### 🌐 Network Traffic Manipulation
* **DNSpoof (DNS Poisoning):** Intercepts DNS queries and redirects targets to authorized IP addresses by manipulating resolution logic.
* **URLresp (URL Response Control):** Monitors protocol-level requests to deliver customized responses, block access, or perform redirection for specific URL patterns.
* **HTMLinj (HTML/JS Injection):** Enables the insertion of custom HTML or JavaScript code into the <body> of web responses to execute client-side scripts.
* **HTMLrep (Content Replacer):** A real-time content modification engine that searches for specific text or images within a website’s code and replaces them before delivery.

### 🕵️ Advanced Monitoring & Auditing
* **BrowserSpy (Visual & Input Tracking):** * **Visual Monitoring:** Captures high-fidelity visual states of the target's web browser using remote rendering.
    * **Input Telemetry:** Tracks and logs interactive inputs including keystrokes (**Keylogging**) and **mouse clicks** for behavior analysis.
* **SNI Inspection:** Identifies target domains during the TLS handshake, allowing for site identification even during encrypted HTTPS sessions.

### 📶 Wireless Security
* **WIFIbrute (Credential Auditing):** An active brute-force module designed to audit the strength of WPA/WPA2 passwords through automated credential testing.

### 📊 Forensics & Data Analysis
* **Detailed Protocol Analysis:** Provides real-time data on IP versions, protocols (TCP/UDP/ICMP), and header specifications via a multi-threaded GUI.
* **Industry-Standard File Support:** Full compatibility for opening, analyzing, and saving traffic in **.cap, .pcap, and .pcapng** formats.
* **Granular Filtering:** Advanced search system allowing users to filter live traffic by IP, port, protocol, or specific keywords in the data payload.

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
To generate a standalone `.exe` file, run:
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
