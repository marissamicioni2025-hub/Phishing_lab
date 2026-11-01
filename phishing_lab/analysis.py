"""Deterministic teaching heuristics. Never resolves domains or fetches URLs."""
import re
from urllib.parse import urlsplit

DISCLAIMER = 'Demo heuristic, not a validated detection model. Review evidence before acting.'
TRUSTED = {'Northstar IT': 'example.com', 'Northstar Payroll': 'example.com',
           'Harbor Training': 'example.org'}

def domain(address):
    return address.rsplit('@', 1)[-1].lower()

def analyze(email):
    findings = []
    def flag(rule, weight, explanation):
        findings.append({'rule': rule, 'weight': weight, 'explanation': explanation})
    sender = domain(email['from_address'])
    expected = TRUSTED.get(email['display_name'])
    if expected and sender != expected:
        flag('Display-name mismatch', 20, f"The fictional directory expects {expected} for {email['display_name']}, but From uses {sender}. Display names are easily copied; verify the identity.")
    if domain(email['reply_to']) != sender:
        flag('Reply-To mismatch', 15, 'Replies go to a different domain from From. This may be legitimate delegation, so verify the relationship.')
    structures, off_domain = [], []
    for url in email['urls']:
        parsed = urlsplit(url)
        host = parsed.hostname or ''
        if parsed.username or host == '192.0.2.10' or host.count('.') >= 4 or 'xn--' in host:
            structures.append(url)
        if host != sender and not host.endswith('.' + sender):
            off_domain.append(url)
    if structures:
        flag('Suspicious URL structure', 20, 'A URL uses user-info before @, a reserved IP, punycode, or deep subdomains. Read the actual hostname; these structures alone do not prove abuse.')
    if off_domain:
        flag('URL domain differs', 10, 'At least one URL hostname differs from the sender domain. Third-party services can be legitimate; corroborate independently.')
    text = (email['subject'] + ' ' + email['body']).lower()
    if re.search(r'\b(urgent|immediately|within 24 hours|suspended|final warning)\b', text):
        flag('Urgency', 5, 'Time pressure can discourage verification. Urgent language alone is weak evidence.')
    if re.search(r'\b(password|credentials|sign in|verify your account|log in)\b', text):
        flag('Credential-related request', 15, 'The message references account access or credentials. Use a known bookmark or contact the service independently; never enter credentials from an unsolicited message.')
    failed = [key.upper() for key, value in email['authentication'].items() if value == 'fail']
    if failed:
        flag('Authentication failure', 25, f"Simulated {', '.join(failed)} failed. Forwarding or configuration can also cause failures; authentication is supporting evidence.")
    missing = [key.upper() for key, value in email['authentication'].items() if value == 'unknown']
    score = min(100, sum(item['weight'] for item in findings))
    risk = 'High' if score >= 60 else 'Medium' if score >= 25 else 'Low'
    actions = ['Verify the sender out-of-band using a known contact or bookmark.',
               'Document findings and preserve the original message and headers.']
    if score >= 25:
        actions += ['Report to the security team for review.', 'Consider quarantining the message under organizational policy pending verification.']
    actions += ['If credentials were entered or compromise is confirmed, contact incident response, reset affected credentials, revoke sessions, and review MFA. Otherwise a reset is not automatically warranted.']
    return {'score': score, 'risk': risk, 'findings': findings, 'actions': actions,
            'authentication_note': ('Unavailable: ' + ', '.join(missing) + '. Unknown is not a pass or a failure.') if missing else 'Authentication results are supplied synthetic metadata, not live checks. Passing authentication does not establish safety.',
            'disclaimer': DISCLAIMER,
            'iocs': {'domains': sorted({sender, domain(email['reply_to'])} | {urlsplit(u).hostname for u in email['urls']}),
                     'email_addresses': sorted({email['from_address'], email['reply_to']}), 'urls': email['urls']}}
