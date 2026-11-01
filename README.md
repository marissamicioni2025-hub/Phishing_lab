Phishing Email Analysis Lab

A local, beginner-friendly SOC investigation demo built with Python, HTML, CSS, and JavaScript. Seven fictional cases let an analyst inspect email metadata, explain indicators, review a weighted risk score, save a decision, and export an investigation report. 
**Training only:** this is a demo heuristic, not a validated detection model. A score is a triage aid, not a phishing verdict. All identities are fictional and use reserved example domains or the documentation IP `192.0.2.10`. Nothing sends email, collects credentials, opens message URLs, or retrieves external content.

## Quick start

Python 3.10+ recommended; tested with Python 3.12.

```bash
cd Phishing_lab
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

On Windows, activate with `.venv\Scripts\activate` and use `python` instead of `python3` if necessary. Open the loopback address printed by Flask on your own machine (port 5000). Keep the server bound to loopback. Debug mode is off. Stop with Ctrl+C.

```bash
python -m pytest -q
```



## Synthetic cases

| Case | Scenario | Expected score |
| --- | --- | --- |
| 001 | Legitimate maintenance | 0, Low |
| 002 | Impersonation, Reply-To mismatch, credential pressure, URL user-info, failed authentication | 100, High |
| 003 | Legitimate partner registration; intentionally demonstrates false positives | 25, Medium |
| 004 | Suspicious deep-subdomain credential lure despite authentication passing | 45, Medium |
| 005 | Legitimate urgent facilities notice | 5, Low |
| 006 | Numeric-host invoice URL and unknown authentication | 30, Medium |
| 007 | Payroll impersonation, credential pressure, failures, literal HTML rendering test | 65, High |

