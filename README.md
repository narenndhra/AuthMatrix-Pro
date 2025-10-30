# AuthMatrix Pro – Role-Based Authorization Testing for Burp Suite

**AuthMatrix Pro** is a **Burp Suite Jython extension** that automates **authorization testing** across multiple captured user roles.  
It systematically replays requests from a **baseline (privileged)** role using other **lower-privilege roles**, detecting **broken access control** vulnerabilities and presenting results in an interactive dashboard.

---

## 🚀 Why This Tool Exists

Manual role-based testing is time-consuming — capturing requests for each role, replaying them with different cookies or tokens, and manually comparing responses.

**AuthMatrix Pro** streamlines this workflow:
- Capture and manage multiple **user roles** directly within Burp.
- Automatically **replay all baseline requests** as other roles.
- Detect and flag **unauthorized access** or **improper privilege enforcement**.
- Visualize results with a modern **Results Dashboard** including built-in **Request/Response viewer**.

---

## ✨ Key Highlights

- **Multi-Role Authorization Testing**
  - Capture HTTP traffic for each authenticated role.
  - Designate a **baseline (highest privilege)** role.
  - Automatically replay baseline requests using all other captured roles.

- **Smart Static Filtering**
  - Optionally ignore static assets like `.js`, `.css`, `.png`, etc.
  - Supports **regex-based exclusions** for specific URLs.

- **Request Deduplication**
  - Avoids redundant captures using **MD5 hashing** of (method + URL + body).

- **Thread-Safe, Lock-Based Design**
  - Ensures safe concurrent captures and test result updates.

- **Detailed Verdict System**
  - `VULNERABLE` – Unauthorized access detected  
  - `SAFE` – Properly blocked (401/403)  
  - `SUSPICIOUS` – Redirects or abnormal behavior  
  - `ERROR` – Request failed or timed out

- **Modern GUI (3 Tabs)**
  1. **Capture Roles** – Record requests per role  
  2. **Configuration & Testing** – Set baseline, configure filters, start tests  
  3. **Results Dashboard** – Review, filter, and export findings

- **Rich Dashboard**
  - Filter by method, role, status, and verdict.
  - Inline **Request/Response viewer**.
  - **Export results** (JSON) with verdict summaries.

---

## ⚙️ How It Works

1. **Capture Roles**  
   - Enter a role name (e.g., `Admin`, `User`, `Guest`).  
   - Start capture → browse the application → stop capture.  
   - The extension automatically records unique requests, cookies, and headers.

2. **Set Baseline & Configure Options**  
   - Choose the **highest privilege** role as the baseline.  
   - Add optional URL regex exclusions or toggle static filtering.

3. **Run Authorization Tests**  
   - The extension replays every baseline request using each lower-privilege role.  
   - For each replay, responses are compared, and a **verdict** is assigned.

4. **Analyze Results**  
   - Open the **Results Dashboard**.  
   - View summaries, filter by verdict, inspect request/response pairs, and export results.

---

## 📊 UI Overview

### 1️⃣ Capture Roles
- Start/Stop role-based capture.
- Displays the count of captured requests, cookies, and headers per role.

### 2️⃣ Configuration & Testing
- Manage URL filters, static file exclusions, and message storage.
- Set **baseline role** and launch tests.
- Real-time progress tracking and test status indicators.

### 3️⃣ Results Dashboard
- Interactive table with filters (method, role, status, verdict).
- Real-time statistics cards for **Total / Vulnerable / Safe / Suspicious**.
- **Request/Response** split viewer for each result.
- Export and clear results directly from the UI.

---

## 🧮 Verdict Logic

| Verdict       | Meaning                                                                 |
|----------------|--------------------------------------------------------------------------|
| **VULNERABLE** | Lower privilege role accessed restricted endpoint (2xx/201/204).        |
| **SAFE**       | Access correctly blocked (401/403/405).                                 |
| **SUSPICIOUS** | Redirect or unexpected behavior (redirects not to login, or 4xx).       |
| **ERROR**      | Request failed or timed out.                                            |

---

## 📥 Installation

1. **Install Jython**  
   - Download `jython-standalone-2.7.x.jar`.  
   - In Burp → `Extender → Options → Python Environment` → Select the JAR.

2. **Load the Extension**
   - Save the file as `BAC.py` (or rename to `authmatrix_pro.py`).
   - In Burp → `Extender → Extensions → Add`:
     - Extension type: **Python**
     - Extension file: `BAC.py`

3. **Verify**
   - A new tab **“AuthMatrix Pro”** appears in Burp.

---

## 📤 Exporting Results

- **Export All / Filtered Results** in JSON format.  
- JSON output includes:
  - Endpoint, method, role, status, verdict, details  
  - Summary: total tests, vulnerability count, baseline role  
- Exports are displayed within Burp in a scrollable text view.

---

## 🧪 Use Cases

- **Role-Based Access Testing**
  - Quickly validate role isolation in multi-user applications.
- **Least Privilege Validation**
  - Confirm low-privilege users cannot access high-privilege endpoints.
- **Regression & CI Integration**
  - Export JSON reports to integrate with pipelines or dashboards.

---

## 🪪 Requirements

- **Burp Suite (Community or Pro)**  
- **Jython 2.7.x**  
- No external dependencies required.

---

## 👤 Author

**Narendra Reddy (Entersoft Security)**  
Version: **AuthMatrix Pro v1.1**  
Includes bug fixes, request deduplication, and UI enhancements.
