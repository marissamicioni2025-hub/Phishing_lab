"""Bounded JSON validation and atomic local record persistence."""
import json
import os
import re
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

STATUSES = ('New', 'Investigating', 'Closed')

def reserved(host):
    return any(host == d or host.endswith('.' + d) for d in ('example.com', 'example.org', 'example.net'))

def validate_samples(samples):
    if not isinstance(samples, list) or not 1 <= len(samples) <= 100:
        raise ValueError('Expected 1–100 synthetic samples')
    seen = set()
    for item in samples:
        if not isinstance(item, dict):
            raise ValueError('Sample must be an object')
        limits = {'id': 40, 'display_name': 100, 'from_address': 254, 'reply_to': 254,
                  'subject': 200, 'body': 10000, 'difficulty': 40, 'scenario': 300}
        for key, limit in limits.items():
            if not isinstance(item.get(key), str) or not 1 <= len(item[key]) <= limit:
                raise ValueError(f'Invalid {key}')
        if not re.fullmatch(r'[a-z0-9-]+', item['id']) or item['id'] in seen:
            raise ValueError('Invalid or duplicate ID')
        seen.add(item['id'])
        if item.get('synthetic') is not True:
            raise ValueError('Only explicitly synthetic samples are supported')
        for key in ('from_address', 'reply_to'):
            address = item[key]
            if not re.fullmatch(r'[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+', address) or not reserved(address.split('@')[1]):
                raise ValueError('Only reserved example email domains are allowed')
        urls = item.get('urls')
        if not isinstance(urls, list) or len(urls) > 20:
            raise ValueError('Invalid URL list')
        for url in urls:
            if not isinstance(url, str) or len(url) > 2000 or any(c.isspace() for c in url):
                raise ValueError('Invalid URL')
            try:
                parsed = urlsplit(url)
                port = parsed.port
                host = parsed.hostname or ''
            except ValueError as exc:
                raise ValueError('Malformed URL') from exc
            if parsed.scheme not in ('http', 'https') or not (reserved(host) or host == '192.0.2.10') or port not in (None, 80, 443):
                raise ValueError('Only reserved synthetic HTTP URLs are supported')
        auth = item.get('authentication')
        if not isinstance(auth, dict) or set(auth) != {'spf', 'dkim', 'dmarc'} or any(v not in ('pass', 'fail', 'unknown') for v in auth.values()):
            raise ValueError('Invalid authentication metadata')
    return samples

def read_json(path, maximum=1_000_000):
    path = Path(path)
    if path.stat().st_size > maximum:
        raise ValueError('JSON file is too large')
    return json.loads(path.read_text(encoding='utf-8'))

def save_records(path, records):
    """Replace atomically so interrupted writes do not leave partial JSON."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(records, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
