# CyberGuard: Password Strength Analyzer & Secure Authentication System

An enterprise-grade cybersecurity web application built with **Python, Flask, SQLite, bcrypt, Regex, and Bootstrap 5** to evaluate credential resilience and defend user identities against common authentication attacks.

---

## 🛡️ Key Features & Capabilities

### 1. Password Strength & Entropy Analysis
* **Mathematical Shannon & Pool Entropy**: Computes both theoretical character pool bits ($H = L \log_2 N$) and character distribution frequency entropy ($-\sum p \log_2 p$). It calculates an **effective entropy** score by penalizing repetitive sequences and wordlist hits.
* **Algorithmic Pattern & Keyboard Walk Detection (Regex)**:
  * **Numerical Sequences**: Detects ascending and descending runs (e.g. `1234`, `9876`).
  * **Alphabetical Sequences**: Detects forward and reverse letter runs (e.g. `abc`, `xyz`, `cba`).
  * **QWERTY Keyboard Walks**: Detects adjacent keywalks across top, home, bottom, and number rows (e.g. `qwerty`, `asdfgh`, `zxcvbn`).
  * **Repeated Characters**: Detects triple or higher consecutive repeats (e.g. `aaaa`, `1111`).
  * **Calendar Dates & Years**: Detects 4-digit years (1900–2035) common in credential stuffing.
  * **Predictable Formatting**: Flags the common corporate formula `[Capital] + [word] + [number/symbol]`.
* **Dictionary Blacklist & Leetspeak De-obfuscation**:
  * Cross-references credentials against curated lists of top leaked and common passwords.
  * Translates leetspeak substitutions (e.g., `@` &rarr; `a`, `3` &rarr; `e`, `0` &rarr; `o`, `$` &rarr; `s`, `1` &rarr; `i`) to detect evasion attempts (e.g., `P@$$w0rd` &rarr; `password`).
* **Multi-Scenario Crack-Time Matrix**:
  * **Offline GPU Cluster on Fast Hash** (MD5/SHA-256 @ $10^{11}$ guesses/sec).
  * **Offline Multi-GPU on Slow Hash** (bcrypt cost 12 @ $10^4$ guesses/sec).
  * **Online Web Attack** (No rate limiting @ 1,000 attempts/sec).
  * **Online Attack Protected by Lockout** (100 attempts/hour).

---

### 2. Secure User Authentication & Brute-Force Shield
* **Bcrypt Hashing with Per-User Cryptographic Salt**: Utilizes `bcrypt` with 12 computational cost rounds, rendering pre-computed rainbow table attacks impossible.
* **Login Attempt Monitoring & Progressive Lockout**:
  * Tracks every login attempt (Timestamp, Target Username, Source IP, User-Agent, Outcome, Failure Reason).
  * Enforces automatic **15-minute temporary lockout** upon reaching 5 consecutive failed attempts.
  * Displays remaining attempt countdowns and lockout expiration timers.
  * Automatic counter reset upon successful authentication.
* **Role-Based Access Control (RBAC)**: Distinguishes between standard users and Security Administrators.

---

### 3. Interactive Dashboards & SOC Analytics
* **User Security Dashboard**:
  * Personal password security score (0–100) and calculated entropy.
  * Visual account protection status badge.
  * Personal login activity audit trail with IP address and timestamp.
  * Built-in **Cryptographic Password Generator** using Python's `secrets` module.
* **Security Operations Center (SOC) Admin Console**:
  * **Telemetry Counters**: Total Monitored Accounts, Locked Accounts, Total Attempts, Brute-Force Alerts.
  * **Interactive Chart.js Visualizations**:
    1. Authentication Volume Over Time (Success vs Failed/Attacks).
    2. Attempt Status Breakdown (Success, Failed, Blocked).
    3. User Password Strength Distribution across tiers.
  * **Live Incident Feed**: Severity-ranked alerts (`CRITICAL`, `HIGH`, `MEDIUM`).
  * **Account Administration**: One-click manual account Lock / Unlock toggle.
  * **Searchable Audit Logs & CSV Export**: Real-time log search and compliance export.

---

## 🛠️ Technology Stack

| Layer | Technologies |
|---|---|
| **Backend** | Python 3.12, Flask, Jinja2 |
| **Security & Hashing** | bcrypt (Cost 12), Python `secrets`, `re` (Regular Expressions) |
| **Database** | SQLite3 (Parameterized queries, Foreign keys, Indexed timestamps & IPs) |
| **Frontend** | HTML5, Bootstrap 5.3, Bootstrap Icons, Custom Cybersecurity Dark Theme (Glassmorphism) |
| **Data Visualization** | Chart.js 4.4 |
| **Testing** | Python `unittest` (Analyzer, Authentication, API & Route suites) |

---

## 🚀 Quick Start Guide

### 1. Prerequisites
Ensure Python 3.9+ is installed:
```bash
python --version
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Seed Demo Data (Optional but Recommended)
Populates demo users, simulated brute-force attacks, and audit logs:
```bash
python seed_data.py
```

### 4. Run Application
```bash
python app.py
```
Open your browser and navigate to:
**`http://127.0.0.1:5000`**

---

## 🔑 Pre-Configured Demo Credentials

| Role | Username | Password | Status / Purpose |
|---|---|---|---|
| **Admin (SOC)** | `admin` | `AdminSecOps#2026!🛡️` | Access to Security Operations Center & Charts |
| **Standard User** | `alice_sec` | `Al!ceCyber#9921$Pro` | Clean user dashboard with high-strength score |
| **Standard User** | `sarah_analyst`| `S@rahEntropy!888#` | Clean user dashboard with strong password |
| **Locked Account**| `bob_weak` | `password1234` | Demonstrates account lockout prevention |

*(Note: On the login page, you can also click the demo buttons to autofill credentials instantly!)*

---

## 🧪 Running Automated Tests

Run the complete test suite:
```bash
python -m unittest discover tests
```

To run individual test modules:
```bash
# Password entropy, regex patterns, and dictionary tests
python -m unittest tests/test_analyzer.py

# Bcrypt hashing, lockout thresholds, and auth logic
python -m unittest tests/test_auth.py

# Flask HTTP routes, access control, and REST APIs
python -m unittest tests/test_routes.py
```

---

## 📁 Project Structure

```
├── app.py                     # Main Flask web application & REST APIs
├── config.py                  # Application settings & security thresholds
├── database.py                # SQLite connection, schema, audit logs & metrics
├── seed_data.py               # Database seeder with realistic test telemetry
├── requirements.txt           # Python dependencies
├── README.md                  # Documentation
├── security/
│   ├── __init__.py
│   ├── analyzer.py            # Shannon entropy, pattern checks, crack times, generator
│   ├── auth.py                # Bcrypt hashing, lockout monitoring, authentication
│   └── dictionary.py          # Blacklist wordlists & leetspeak de-obfuscation
├── static/
│   ├── css/
│   │   └── style.css          # Cybersecurity dark theme & glassmorphism
│   └── js/
│       ├── analyzer.js        # Real-time keystroke evaluation & generator UI
│       ├── dashboard.js       # Chart.js visual charts & live audit log filter
│       └── main.js            # General UI helpers & toast notifications
├── templates/
│   ├── base.html              # Responsive layout with cyber navigation
│   ├── index.html             # Landing page with interactive live analyzer preview
│   ├── analyzer.html          # Full-suite standalone Password Strength Analyzer
│   ├── login.html             # Secure login with lockout notifications & autofill
│   ├── register.html          # Registration with live password strength checklist
│   ├── dashboard.html         # User dashboard with security score & personal logs
│   ├── admin.html             # SOC Admin Console with charts, alerts & user controls
│   ├── change_password.html   # Secure password update with real-time feedback
│   └── 404.html               # 404 security boundary page
└── tests/
    ├── __init__.py
    ├── test_analyzer.py       # Unit tests for entropy and patterns
    ├── test_auth.py           # Unit tests for bcrypt and lockout
    └── test_routes.py         # End-to-end HTTP route and API tests
```

---

## 🔒 Security Design Highlights
1. **Parameterized Queries**: All database queries use SQLite parameter bindings (`?`) to prevent SQL injection.
2. **Timing-Attack Resistance**: Authentication uses `bcrypt.checkpw`, which executes constant-time comparisons.
3. **Adaptive Work Factor**: Bcrypt cost factor of 12 ensures hash computation is slow enough to render offline hardware cracking infeasible.
4. **Brute-Force Lockout Defense**: Progressive monitoring detects automated dictionary sprays and temporarily locks the targeted account.
5. **Effective Entropy Model**: Penalizes predictable structure so that a 12-character password like `Password123!` is correctly scored as weak rather than artificially strong.
