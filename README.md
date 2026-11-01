Phishing Email Analysis Lab

A local, beginner-friendly SOC investigation demo built with Python, HTML, CSS, and JavaScript. Seven fictional cases let an analyst inspect email metadata, explain indicators, review a weighted risk score, save a decision, and export an investigation report. 



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

