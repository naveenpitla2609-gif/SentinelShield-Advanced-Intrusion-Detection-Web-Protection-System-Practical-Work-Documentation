# SentinelShield: Advanced Intrusion Detection & Web Protection System 🛡️

**Detect • Inspect • Protect • Monitor**

A Python and Flask-based web security project designed to inspect HTTP requests, detect common web attack patterns, enforce rate limiting, and maintain structured security event logs. SentinelShield demonstrates practical web application security concepts through a modular, rule-based intrusion detection and protection framework.

![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-black?logo=flask)
![Security](https://img.shields.io/badge/Security-Rule--Based-00b894)
![Testing](https://img.shields.io/badge/Testing-pytest-blueviolet?logo=pytest)
![License](https://img.shields.io/badge/License-MIT-green.svg)

---

## 📌 Project Overview

Web applications face security threats such as SQL injection, Cross-Site Scripting (XSS), path traversal, command injection, and excessive request traffic. SentinelShield brings together request inspection, attack detection, protective controls, and security event logging within a single Python-based application.

The system is designed to inspect incoming HTTP requests, identify suspicious patterns using predefined detection rules, apply configurable rate limits, and record security events for investigation. The modular architecture supports testing, maintenance, and future expansion into a visual security monitoring interface.

## 🏗️ System Architecture

The architecture illustrates how incoming HTTP requests move through inspection, attack detection, protection, and security event logging.

![SentinelShield System Architecture](docs/sentinelshield-architecture.png)

**Request Flow:** Client Request → Request Inspection → Attack Detection → Protection & Rate Limiting → Security Event Logging.

---

## 🚀 Core Modules & Features

### 1. Attack Detection Engine 🛡️

- Detects suspicious inputs using rule-based inspection.
- Covers SQL Injection, Cross-Site Scripting (XSS), Path Traversal, and Command Injection.
- Organizes attack signatures and detection rules into dedicated components.
- Supports controlled testing with normal requests and known attack-pattern samples.

### 2. Request Inspection Engine 🔍

- Inspects incoming HTTP requests and relevant request data.
- Analyzes request paths, query parameters, headers, and supported request bodies.
- Extracts relevant data for attack detection.
- Produces structured inspection results for security decisions and logging.

### 3. Protection & Rate Limiting 🚦

- Applies configurable request limits within a defined time window.
- Helps control excessive request traffic.
- Returns HTTP `429 Too Many Requests` when the configured limit is exceeded.
- Supports controlled validation of rate-limiting behavior.

### 4. Security Logging & Alerts 📋

- Records security events for monitoring and investigation.
- Captures available timestamps, source information, request paths, detection categories, severity, and actions.
- Stores security events in structured JSON Lines format.
- Provides a foundation for future alerting and event analysis.

### 5. Web Dashboard & Monitoring 📊

The planned dashboard will provide a visual overview of the system's security activity. Its intended capabilities include:

- System health and protection status.
- Request activity and blocked-request statistics.
- Attack category summaries.
- Security event monitoring.
- Future filtering and report-generation capabilities.

**Dashboard Preview — Planned Interface**

![SentinelShield Dashboard Mockup](docs/sentinelshield-dashboard.png)

*The image above is intended as a visual design reference. It does not represent a functioning dashboard unless these features have been implemented in the application.*

---

## 🛠️ Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application and detection logic |
| Flask | Web application and HTTP endpoints |
| pytest | Automated testing |
| requests | HTTP request testing |
| JSON Lines | Structured security event storage |
| Git & GitHub | Version control and project documentation |

---

## ⚙️ Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/naveenpitla2609-gif/SentinelShield-Advanced-Intrusion-Detection-Web-Protection-System-Practical-Work-Documentation.git
```

### 2. Navigate to the Project Directory

```bash
cd SentinelShield-Advanced-Intrusion-Detection-Web-Protection-System-Practical-Work-Documentation
```

### 3. Create a Virtual Environment

**Windows PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Start the Application

```bash
python app.py
```

Open the local URL displayed in the terminal after the application starts successfully.

---

## 🧪 Testing & Validation

Execute the automated test suite using:

```bash
python -m pytest -q
```

Recommended validation areas:

- Application health and endpoint availability.
- Normal HTTP request handling.
- Detection of supported attack patterns.
- Rate-limit enforcement and HTTP response codes.
- Security event creation and log-file validation.
- Handling of malformed or unexpected requests.

Document the actual test results from the current version of the project.

---

## 📸 Screenshots & Execution Evidence

### 🖥️ 1. Application Startup

Shows the SentinelShield startup banner, enabled protection components, request limits, and local server information.

![Application Startup](Screenshots/application-startup.png)

### 🛡️ 2. Attack Detection

Demonstrates a controlled test request flagged by the detection engine, including the detected category and resulting response.

![Attack Detection](Screenshots/attack-detection.png)

### 🚦 3. Rate Limiting

Shows request-limit enforcement and the HTTP `429 Too Many Requests` response when the configured threshold is exceeded.

![Rate Limiting](Screenshots/rate-limiting.png)

### 📋 4. Security Event Logging

Displays structured security event records containing available timestamps, detection categories, severity, and actions.

![Security Event Logging](Screenshots/security-event-logging.png)

### ✅ 5. Automated Test Results

Shows the actual pytest execution output for the project's automated validation suite.

![Automated Test Results](Screenshots/test-results.png)

*Replace these image paths with the actual screenshot filenames uploaded to the repository.*

---

## 🛡️ Security Recommendations

- **Parameterized Queries:** Use parameterized database queries to mitigate SQL injection.
- **Input Validation:** Validate and normalize untrusted input.
- **Output Encoding:** Apply context-aware encoding to reduce XSS risks.
- **Least Privilege:** Restrict application permissions to the minimum required.
- **Rate Limiting:** Configure suitable request limits and authentication protections.
- **HTTPS:** Use properly configured TLS in deployed environments.
- **Continuous Monitoring:** Review security logs and investigate repeated suspicious activity.
- **Automated Testing:** Regularly validate detection and protection behavior using authorized test cases.

---

## 🔭 Future Enhancements

- Interactive web-based security dashboard.
- Expanded attack detection rules.
- Security event filtering and visualization.
- Additional automated test coverage.
- Exportable security summaries and reports.
- Improved monitoring and alerting capabilities.

---

## ⚠️ Authorization Notice & Disclaimer

SentinelShield is intended for educational purposes, defensive security development, and authorized testing in controlled environments. Test only systems you own or have explicit permission to assess.

Detection rules may produce false positives or false negatives. This project is a practical security learning tool and is not a substitute for a comprehensive production security solution.

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.
