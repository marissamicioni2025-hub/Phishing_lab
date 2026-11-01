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

In the prepared cloud workspace, dependencies are in `/workspace/.venvs/phishing-lab`; run `/workspace/.venvs/phishing-lab/bin/python app.py` from `/workspace/Phishing_lab`. The cloud onboarding UI does not expose a web preview. Local browser access on your own machine is the simplest interview demo.

## Two-minute walkthrough

1. **0:00–0:20:** Explain the dashboard: seven synthetic messages, risk counts, queue statuses, and a clear heuristic disclaimer. Initial counts: 2 Low, 3 Medium, 2 High; all cases New.
2. **0:20–0:55:** Select **CASE-002**. Compare `Northstar IT` with `support@example.net`, the expected directory domain `example.com`, and a Reply-To at `example.org`. Explain the URL `https://example.com@access.example.net/verify`: the actual host is **access.example.net**, not the name before `@`. Show the 100-point score and its evidence. Nothing is clicked or fetched.
3. **0:55–1:15:** Select **CASE-005**: urgency alone produces **5/100, Low**. Then show **CASE-004**, a suspicious credential lure with passing authentication (**45/100, Medium**). Authentication is not a safety guarantee.
4. **1:15–1:40:** Return to CASE-002, set Investigating, and write: “Suspected impersonation. Verify through a known IT contact; report and consider quarantine. No credentials entered; no automatic reset recommended.” Save and observe the dashboard update.
5. **1:40–2:00:** Copy the IOC evidence, export JSON or text, and explain the conditional response steps. Reset credentials and revoke sessions only if exposure or compromise warrants it. Exports include saved notes only.

## How it works, step by step

1. At startup, Flask loads and validates the bounded synthetic JSON dataset. There is deliberately no public import endpoint.
2. The browser requests the queue. Each case receives a deterministic analysis; saved records supply its workflow status.
3. Selecting a case retrieves its body, headers, declared URLs, synthetic authentication results, findings, IOCs, and response suggestions.
4. The analyzer compares domains and applies the rules below. Each rule fires at most once per message. Repeated words or URLs do not multiply its weight.
5. The browser displays everything using `textContent`, including literal email HTML. Message URLs remain text, never anchors. IOC copying copies text only and makes no request.
6. Saving notes validates a session-bound CSRF token, status, and a 5,000-character notes limit. The server serializes writes in its single process and atomically replaces the local JSON file.
7. Export retrieves a fresh saved record and downloads a text or JSON report with evidence, findings, score, recommendations, and analyst rationale.

## Architecture and important files

```text
Browser (static HTML/CSS/JS)
   │ same-origin JSON requests
Flask routes (app.py)
   ├── analysis.py → deterministic rules, explanations, IOC evidence
   ├── storage.py → schema/size validation, atomic JSON writes
   ├── data/emails.json → seven synthetic cases (read only)
   └── data/investigations.json → local analyst records (generated, gitignored)
```

| File | Purpose |
| --- | --- |
| `app.py` | Application factory, API routes, security headers, notes validation, report generation; starts loopback server. |
| `phishing_lab/analysis.py` | Weights, thresholds, fictional trusted-name directory, rule explanations, IOC grouping, and response guidance. Pure logic with no network calls. |
| `phishing_lab/storage.py` | Validates sample shape, lengths, unique IDs, reserved addresses/URLs, and authentication enums. Reads size-limited JSON and writes records atomically. |
| `data/emails.json` | Seven explicit synthetic scenarios, difficulty labels, and teaching context. Modify this file to add cases, then restart; malformed entries fail validation. |
| `templates/index.html` | Dashboard shell and case detail template; Jinja autoescaping remains enabled. |
| `static/app.js` | Fetches case data, renders inert text, filters cases, copies IOCs, saves notes, and warns before discarding unsaved edits. |
| `static/style.css` | Responsive dark SOC layout, risk badges, keyboard focus styles, desktop/mobile layouts. |
| `tests/test_lab.py` | Scoring, IOC host parsing, unsafe data rejection, notes persistence, export content, CSRF, and request limits. Uses temporary records rather than changing demo data. |
| `requirements.txt` | Pinned direct Flask and pytest dependencies. No third-party frontend dependencies. |
| `.gitignore` | Keeps virtual environments, cache files, and local investigation records out of Git. |

## Defensible rule logic

| Rule | Weight | Why it matters and where it can be wrong |
| --- | ---: | --- |
| Display-name/domain mismatch | 20 | An exact known fictional organization name uses a different From domain from the small explicit directory. Names are spoofable; this is not a generic identity inference. |
| Reply-To domain mismatch | 15 | Replies route to another domain. Legitimate partners and ticket systems can also do this. Different local parts on the same domain do not trigger it. |
| Suspicious URL structure | 20 | User-info before `@`, the configured documentation IP, punycode, or four or more dots in the host. Legitimate internationalized domains and subdomains exist. |
| URL domain differs | 10 | A URL host is neither the From domain nor its subdomain. Third-party links are common. This uses exact host/suffix comparisons, not public-suffix or ownership intelligence. |
| Urgency | 5 | A small explicit phrase list finds time pressure. Weak evidence alone; not a maliciousness verdict. |
| Credential-related request | 15 | A small phrase list finds account/credential wording. Legitimate account notices can trigger it; wording and negation are not deeply understood. |
| Any SPF/DKIM/DMARC failure | 25 | At least one supplied result is `fail`. Counted once to avoid treating correlated failures as independent. Forwarding and configuration can cause failures. |

`score = min(100, sum(matched rule weights))`. **Low: 0–24; Medium: 25–59; High: 60–100.** The maximum uncapped sum is 110. No rule uses a suspicious TLD alone. Unknown authentication adds no points and is displayed explicitly. Passing authentication neither subtracts points nor guarantees safety. Thresholds and weights are pedagogical choices, not empirically calibrated probabilities.

The IOC panel groups From/Reply-To addresses, their domains, parsed URL hostnames, and the declared message URLs. It labels these as observables rather than proven malicious IOCs. It does not crawl links or extract live intelligence. In this MVP the explicit `urls` array is the source for URL analysis; there is no raw `.eml`/MIME parser, HTML link extraction, attachment analysis, or automatic arbitrary-body URL discovery.

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

These scenario explanations are visible for teaching; this is not a blind scored assessment.

## API and data boundaries

- `GET /api/emails`: queue summaries and status.
- `GET /api/emails/<id>`: full case, analysis, saved investigation.
- `POST /api/emails/<id>/investigation`: JSON `{ "status": "Investigating", "notes": "..." }`; requires the page session and `X-CSRF-Token`.
- `GET /api/emails/<id>/export?format=json` (or `txt`): attachment download, no state change.

Requests are limited to 20 KB, sample JSON to 1 MB, and record JSON to 2 MB. There are at most 100 samples, 20 URLs per message, 10,000 characters per body, and 2,000 characters per URL. Email addresses must use reserved example domains. Structured URLs allow only HTTP(S), reserved example domains or the one documentation IP, and standard ports. Nothing treats these URLs as destinations to visit.

CSRF protection, SameSite cookies, CSP (`connect-src 'self'`, no inline scripts), no-referrer policy, and text rendering reduce browser-side risks. They do not make this a production service. Local users with file access can read records. No authentication, encryption at rest, audit log, multi-process write locking, or production deployment is included. The random session key changes on restart: reload the page before saving after a restart.

To reset the lab, stop the app and delete **only** generated `data/investigations.json`, then restart. Keep `data/emails.json`. Invalid/corrupt records are reported rather than silently overwritten; preserve a backup and repair or reset them. Don't put sensitive information into notes.

## Validation and limits

- 26 pytest cases exercise actual API and analysis behavior, including JSON/text exports and persistence across app instances.
- A Chromium smoke check exercised seven cases, safe literal HTML, inert URLs, note save/reload, a JSON report download, risk filtering, and a 390-pixel layout; no browser script errors or external requests were observed in that run.
- Authentication values are **simulated**, not DNS queries, signature verification, or independently calculated SPF/DKIM/DMARC alignment.
- Keyword rules have false positives/negatives; display names outside the small fictional directory are not evaluated for impersonation.
- A low score is not a safe-email verdict. A real investigation needs original headers, business context, approved tooling, and escalation policies.
- The local Flask development server is for this single-user demo. Do not expose it publicly or use it for real email triage.

## Five likely interview questions and understandable answers

**1. How do you decide an email is phishing?**  
“I combine indicators: sender identity, Reply-To, actual link host, language, authentication, and business context. One odd feature is rarely enough. This lab shows a transparent triage score, and I verify through a known channel before making a final decision.”

**2. What do SPF, DKIM, and DMARC tell you?**  
“SPF checks whether a sending server is authorized for an envelope domain. DKIM verifies a signed message against a domain's public key. DMARC checks alignment of the visible From domain with passing SPF or DKIM and publishes policy. A pass doesn't prove the sender's intent is good; a compromised authorized account can send harmful messages. This lab displays simulated results, not actual verification.”

**3. Why is `https://example.com@access.example.net/verify` suspicious?**  
“The host is `access.example.net`. The text before `@` is URL user-info, which can distract a reader into trusting `example.com`. I parse the URL to identify its real host and leave it inert rather than clicking it.”

**4. What would you do if someone entered their password?**  
“Escalate according to the incident-response process, preserve evidence, reset the affected password through a trusted channel, revoke sessions, and review MFA and account activity. If there was no credential exposure, I would not automatically recommend a reset just because an email looks suspicious.”

**5. What are the weaknesses of your scoring approach?**  
“It's deterministic and easy to explain, but the weights aren't validated probabilities. Keywords miss context, partners can trigger domain mismatches, and authentication failures can be benign. I'd improve it with labeled evaluation data, measured false positives and negatives, better header parsing, and analyst feedback before using it operationally.”

## Portfolio attribution

This project was generated with coding-assistant help. Review the implementation, run the demo, and edit these explanations into your own words before presenting it. Describe only the parts you understand and have personally reviewed or modified. A defensible description is: “I used an assistant to scaffold a SOC email-analysis lab, then reviewed its rule logic and tested the investigation workflow” **after** you have actually done that review and testing. Do not imply deployment, production detection efficacy, or independent implementation of unreviewed features.
