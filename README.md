# ⚔️ VulnHunter

> **Automated Web Application Vulnerability Scanner — OWASP Top 10**

VulnHunter is an asynchronous web vulnerability scanner built with **Python 3.11** and **FastAPI**. It features an async crawling engine, multiple security analysis modules, and a professional web dashboard with real-time logging and PDF/Markdown reporting.

---

## ✨ Key Features

- **🚀 Async Engine**: High-performance crawling and scanning using `httpx` and `asyncio`.
- **🛡️ Security Modules**: Specialized detectors for SQL Injection, XSS, CSRF, SSRF, and Path Traversal.
- **🖥️ Cyber-Style Dashboard**: A premium, real-time terminal-style GUI for monitoring scans.
- **📄 Professional Reports**: Generate structured Markdown or design-heavy PDF reports automatically.
- **🔌 REST API**: Fully documented API endpoints for integration into CI/CD pipelines.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Docker Network                        │
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  Dashboard   │───▶│  FastAPI     │───▶│  Scan Engine │  │
│  │  (HTML/JS)   │    │  REST API    │    │  (AsyncIO)   │  │
│  └──────────────┘    └──────────────┘    └──────┬───────┘  │
│                                                  │          │
│                                         ┌────────▼────────┐ │
│                                         │  Modules        │ │
│                                         │  sqli / xss /   │ │
│                                         │  csrf / ssrf /  │ │
│                                         │  path_traversal │ │
│                                         └────────┬────────┘ │
│                                                  │          │
│                                         ┌────────▼────────┐ │
│                                         │  Reporter       │ │
│                                         │  Markdown / PDF │ │
│                                         └─────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Installation

### 🐳 Option 1: Docker (Recommended)
The quickest way to start VulnHunter along with test targets (**DVWA** and **Juice Shop**).

```bash
# Clone the repository and navigate to the root
git clone https://github.com/matxsu/VulnHunter.git
cd VulnHunter

# Start all services
docker compose up --build
```
- **Dashboard**: [http://localhost:8000](http://localhost:8000)
- **REST API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **DVWA (Test Target)**: [http://localhost:8080](http://localhost:8080)
- **Juice Shop (Test Target)**: [http://localhost:3000](http://localhost:3000)

### 🐍 Option 2: Local Python Execution
Requires Python 3.11+.

```bash
# Install dependencies
pip install -r requirements.txt

# Start the FastAPI server
uvicorn app.main:app --reload --port 8000
```

---

## 📖 Usage Guide

### 1️⃣ Web Dashboard
1. Open **[http://localhost:8000](http://localhost:8000)** in your browser.
2. Enter the **Target URL** (e.g., `http://localhost:8080` for DVWA).
3. Select the **Scan Modules** you want to run.
4. Adjust **Crawl Depth** (how many levels of links to follow) and **Timeout**.
5. Click **⚡ Launch Scan**.
6. Monitor findings and logs in real-time. Once finished, download the reports via the buttons at the bottom.

### 2️⃣ CLI Scanner
Run a scan directly from your terminal without the web interface.

```bash
# Basic scan
python -m app.scanner.cli --url http://localhost:8080

# Advanced options
python -m app.scanner.cli --url http://localhost:8080 --modules sqli xss --depth 3 --output report.pdf --verbose
```
- `--url`: Target URL to scan.
- `--modules`: space-separated list (`sqli`, `xss`, `csrf`, `ssrf`, `traversal`).
- `--depth`: Crawl recursion depth (default: 2).
- `--output`: File path to save the report (.md or .pdf).
- `--verbose`: Print detailed vulnerability findings to terminal.

### 3️⃣ REST API
VulnHunter exposes a clean API for automated workflows.

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/v1/scans` | `POST` | Start a new scan. |
| `/api/v1/scans` | `GET` | List all recent scans stored in memory. |
| `/api/v1/scans/{id}` | `GET` | Get status and findings for a specific scan. |
| `/api/v1/scans/{id}` | `DELETE` | Remove a scan from results. |
| `/api/v1/scans/{id}/report/pdf` | `GET` | Download a PDF report. |
| `/api/v1/health` | `GET` | Check system status. |

---

## 🛡️ Vulnerability Modules

| Module | Description | Detection Techniques |
| :--- | :--- | :--- |
| **SQL Injection** | Detects database query manipulation. | Error-based, Boolean-based, Time-based delays. |
| **XSS** | Cross-Site Scripting (Reflected & DOM). | Script reflection checks, DOM sink analysis. |
| **CSRF** | Cross-Site Request Forgery. | Token presence check, `SameSite` cookie policy check. |
| **SSRF** | Server-Side Request Forgery. | Metadata endpoint probing, internal redirect checks. |
| **Path Traversal** | Local File Inclusion / Directory Traversal. | Encoded path sequences, system file access attempts. |

---

## 🧪 Testing and Development

To run the full test suite and ensure everything is working correctly:

```bash
# Run unit and integration tests
python -m pytest tests/test_vulnerability.py -v
```

---

## ⚠️ Disclaimer
VulnHunter is designed for **authorized security testing only**. Only scan systems you own or have explicit permission to test. Running this tool against unauthorized systems is illegal and unethical.

---
*VulnHunter v1.0 — ESGI DevSecOps Project, 2025*