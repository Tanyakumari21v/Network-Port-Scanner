# 🔍 Network Port Scanner

A comprehensive Python-based **Network Port Scanner** that detects open ports, identifies running services, grabs service banners, assesses security risk levels, and generates detailed reports — all from the terminal.

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

---

## 🎯 Features

- **Fast Multi-threaded Scanning** — Scan hundreds of ports simultaneously
- **Service Detection** — Identifies 60+ common services by port number
- **Banner Grabbing** — Retrieves live service banners for fingerprinting
- **Risk Assessment** — Flags ports as 🔴 HIGH / 🟡 MEDIUM / 🟢 LOW risk
- **Smart Recommendations** — Context-aware security advice based on findings
- **Flexible Port Selection** — Scan common ports, full range, or custom sets
- **Export Reports** — Save results as JSON or CSV for further analysis
- **Cross-platform** — Works on Linux, macOS, and Windows

---

## 📋 Prerequisites

- Python 3.7 or higher
- No third-party libraries required (pure standard library)

---

## 🚀 Installation

```bash
# 1. Clone the repository
git clone https://github.com/Coding-with-Mayank/network-port-scanner.git
cd network-port-scanner

# 2. (Optional) Install extras
pip install -r requirements.txt

# 3. Make executable (Linux/macOS)
chmod +x port_scanner.py
```

---

## 💻 Usage

### Basic Scan (common ports)
```bash
python3 port_scanner.py -t 192.168.1.1
```

### Scan a hostname
```bash
python3 port_scanner.py -t example.com -p common
```

### Scan a custom port range
```bash
python3 port_scanner.py -t 10.0.0.1 -p 1-1024 --threads 200
```

### Scan specific ports
```bash
python3 port_scanner.py -t 192.168.1.1 -p 22,80,443,3306,5432
```

### Scan ALL 65535 ports
```bash
python3 port_scanner.py -t 192.168.1.1 -p all --timeout 0.5
```

### Save report to JSON + CSV
```bash
python3 port_scanner.py -t 192.168.1.1 --json report.json --csv report.csv
```

### Verbose mode (show closed ports too)
```bash
python3 port_scanner.py -t 192.168.1.1 -v
```

---

## ⚙️ Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t`, `--target` | Target hostname or IP address | *(required)* |
| `-p`, `--ports` | Ports: `common`, `all`, `80`, `1-1024`, `22,80,443` | `common` |
| `--threads` | Number of concurrent threads | `100` |
| `--timeout` | Connection timeout in seconds | `1.0` |
| `--json FILE` | Save report as JSON | — |
| `--csv FILE` | Save report as CSV | — |
| `-v`, `--verbose` | Show closed ports | `False` |

---

## 📊 Example Output

```
╔══════════════════════════════════════════════════════════════╗
║              Network Port Scanner  v1.0                      ║
║         Scan. Detect. Secure. — by Coding-with-Mayank        ║
╚══════════════════════════════════════════════════════════════╝

⚠️  LEGAL DISCLAIMER: Only scan systems you own or have explicit permission to test.

[*] Target   : 192.168.1.1 (192.168.1.1)
[*] Ports    : 63 ports queued
[*] Threads  : 100
[*] Timeout  : 1.0s per port
[*] Started  : 2025-06-01 14:22:10

────────────────────────────────────────────────────────────────
  PORT     STATE    SERVICE              RISK     BANNER
────────────────────────────────────────────────────────────────
  22       open     SSH                  LOW      SSH-2.0-OpenSSH_8.9p1
  80       open     HTTP                 LOW
  443      open     HTTPS                LOW
  3306     open     MySQL                HIGH
  3389     open     RDP                  HIGH

════════════════════════════════════════════════════════════════
                  SECURITY SCAN REPORT
════════════════════════════════════════════════════════════════
  Target         : 192.168.1.1 (192.168.1.1)
  Scan Duration  : 3.42s
  Ports Scanned  : 63
  Open Ports     : 5
  Closed Ports   : 56
  Filtered Ports : 2
────────────────────────────────────────────────────────────────

  📋 OPEN PORTS SUMMARY

  🟢 22     SSH                    [LOW]
  🟢 80     HTTP                   [LOW]
  🟢 443    HTTPS                  [LOW]
  🔴 3306   MySQL                  [HIGH]
  🔴 3389   RDP                    [HIGH]

────────────────────────────────────────────────────────────────
  🔐 RISK SUMMARY

  🔴 HIGH risk ports   : 2
     └─ 3306, 3389
  🟡 MEDIUM risk ports : 0
  🟢 LOW risk ports    : 3

────────────────────────────────────────────────────────────────
  💡 RECOMMENDATIONS

  ⚠️  Port 3389 (RDP) is exposed — restrict to VPN access only.
  ⚠️  HTTP is open but HTTPS is not — consider enabling TLS.
════════════════════════════════════════════════════════════════
```

---

## 🔐 Risk Levels

| Level | Color | Description |
|-------|-------|-------------|
| HIGH | 🔴 | Dangerous if exposed — often exploited (RDP, Telnet, Redis, etc.) |
| MEDIUM | 🟡 | Context-dependent — review if exposed to the internet |
| LOW | 🟢 | Expected and generally safe (HTTP, HTTPS, SSH) |

---

## 🛡️ Security Checks

- ✅ Detects dangerous services (Telnet, FTP, RDP, VNC)
- ✅ Flags unencrypted database ports (MySQL, MongoDB, Redis)
- ✅ Identifies Metasploit default ports
- ✅ Detects HTTP without HTTPS
- ✅ Flags SMB exposure (EternalBlue risk)
- ✅ Grabs service banners for fingerprinting

---

## 📁 Project Structure

```
network-port-scanner/
│
├── port_scanner.py      # Main scanner script
├── requirements.txt     # Dependencies (none required)
├── README.md            # Documentation
├── CONTRIBUTING.md      # Contribution guide
├── LICENSE              # MIT License
└── .gitignore           # Git ignore rules
```

---

## 📝 TODO

- [ ] UDP port scanning
- [ ] OS fingerprinting (TTL analysis)
- [ ] CVE lookup per detected service
- [ ] HTML report export
- [ ] GUI interface (Tkinter / web-based)
- [ ] Subnet / CIDR range scanning
- [ ] IPv6 support
- [ ] Ping sweep before port scan

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## ⚠️ Legal Disclaimer

**This tool is for EDUCATIONAL and AUTHORIZED TESTING purposes only.**

- ⚖️ Only scan networks and systems you own or have explicit written permission to test
- ⚖️ Unauthorized port scanning may violate laws in your jurisdiction (e.g. Computer Fraud and Abuse Act)
- ⚖️ The author assumes no liability for misuse of this tool
- ⚖️ Always comply with local laws and regulations

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Mayank**
- GitHub: [@Coding-with-Mayank](https://github.com/Coding-with-Mayank)

---

## 🙏 Acknowledgments

- Python `socket` and `concurrent.futures` standard library teams
- The open-source cybersecurity community
- Nmap project for inspiration on service fingerprinting

---

**⭐ If this project helped you, please give it a star!**

**Remember: Scan responsibly. Use ethically. 🛡️**
