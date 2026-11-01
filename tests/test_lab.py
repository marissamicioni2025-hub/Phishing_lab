"""Exercise scoring, safety boundaries, persistent notes, and real report content."""
import copy
import json
import pytest
from app import create_app
from phishing_lab.analysis import analyze
from phishing_lab.storage import read_json, validate_samples

@pytest.fixture
def samples():
    return read_json('data/emails.json')

@pytest.fixture
def app(tmp_path):
    return create_app({'TESTING': True, 'SECRET_KEY': 'test-only', 'RECORDS_PATH': tmp_path / 'records.json'})

@pytest.fixture
def client(app):
    return app.test_client()

def token(client):
    client.get('/')
    with client.session_transaction() as session:
        return {'X-CSRF-Token': session['csrf']}

def test_expected_sample_risks(samples):
    assert [(analyze(e)['score'], analyze(e)['risk']) for e in samples] == [
        (0, 'Low'), (100, 'High'), (25, 'Medium'), (45, 'Medium'), (5, 'Low'), (30, 'Medium'), (65, 'High')]

def test_urgency_unknown_and_tld_do_not_prove_phishing(samples):
    email = copy.deepcopy(samples[4])
    email['authentication'] = dict.fromkeys(('spf', 'dkim', 'dmarc'), 'unknown')
    result = analyze(email)
    assert result['score'] == 5
    assert 'Unknown is not a pass' in result['authentication_note']
    email['subject'], email['body'] = 'Notice', 'No action required.'
    email['urls'] = ['https://example.net/notice']
    email['from_address'] = email['reply_to'] = 'facilities@example.net'
    assert analyze(email)['score'] == 0

def test_auth_pass_does_not_hide_lure_and_weights_count_once(samples):
    email = copy.deepcopy(samples[3])
    email['urls'] *= 4
    result = analyze(email)
    assert result['score'] == 45
    assert sum(f['weight'] for f in result['findings']) == 45
    assert 'reset' in ' '.join(result['actions'])
    assert 'Otherwise a reset is not automatically warranted' in result['actions'][-1]

def test_thresholds_and_score_cap(samples):
    email = copy.deepcopy(samples[1])
    email['urls'].append('https://example.org/verify')
    result = analyze(email)
    assert sum(f['weight'] for f in result['findings']) > 100
    assert result['score'] == 100
    assert analyze(samples[2])['risk'] == 'Medium'  # exact lower boundary: 25
    assert analyze(samples[4])['risk'] == 'Low'

def test_iocs_use_actual_hostname(samples):
    result = analyze(samples[1])
    assert 'access.example.net' in result['iocs']['domains']
    assert result['iocs']['email_addresses'] == ['collector@example.org', 'support@example.net']
    assert result['iocs']['urls'] == samples[1]['urls']

@pytest.mark.parametrize('field,value', [
    ('urls', ['javascript:alert(1)']), ('urls', ['https://real-domain.invalid/']),
    ('urls', ['https://example.com:bad/']), ('urls', ['https://[bad/']),
    ('from_address', 'person@real-domain.invalid'), ('body', 'a' * 10001),
    ('synthetic', False), ('authentication', {'spf': 'pass'}),
    ('id', '../../etc/passwd'), ('urls', ['https://example.com/'] * 21),
])
def test_reject_invalid_samples(samples, field, value):
    sample = copy.deepcopy(samples[0]); sample[field] = value
    with pytest.raises(ValueError):
        validate_samples([sample])

def test_duplicate_and_oversized_json(samples, tmp_path):
    with pytest.raises(ValueError):
        validate_samples([samples[0], samples[0]])
    path = tmp_path / 'large.json'; path.write_text(' ' * 101)
    with pytest.raises(ValueError):
        read_json(path, 100)

def test_dashboard_and_all_cases(client, samples):
    home = client.get('/')
    assert home.status_code == 200
    assert b'SignalDesk' in home.data
    assert b'unsafe-inline' not in home.headers['Content-Security-Policy'].encode()
    assert "connect-src 'self'" in home.headers['Content-Security-Policy']
    queue = client.get('/api/emails').json
    assert len(queue) == 7 and all(e['status'] == 'New' for e in queue)
    for sample in samples:
        result = client.get('/api/emails/' + sample['id'])
        assert result.status_code == 200
        assert result.json['email']['synthetic'] is True
    assert client.get('/api/emails/missing').status_code == 404

def test_notes_persist_and_exports_include_saved_content(client, app):
    headers = token(client)
    notes = '<script>alert("test")</script>\nVerified through known contact; no credentials entered.'
    payload = {'notes': notes, 'status': 'Investigating'}
    result = client.post('/api/emails/case-002/investigation', json=payload, headers=headers)
    assert result.status_code == 200
    assert read_json(app.config['RECORDS_PATH'])['case-002']['notes'] == notes
    fresh = create_app(dict(app.config)).test_client()
    assert fresh.get('/api/emails/case-002').json['investigation']['notes'] == notes
    queue = client.get('/api/emails').json
    assert queue[1]['status'] == 'Investigating'
    for fmt in ('txt', 'json'):
        export = client.get('/api/emails/case-002/export?format=' + fmt)
        assert export.status_code == 200
        assert 'attachment;' in export.headers['Content-Disposition']
        if fmt == 'json':
            assert json.loads(export.data)['investigation']['notes'] == notes
        else:
            assert notes in export.text and '100/100 (High)' in export.text
    assert client.get('/api/emails/case-002/export?format=html').status_code == 400

@pytest.mark.parametrize('payload', [None, [], {'notes':'x','status':'Invalid'},
    {'notes':'x'*5001,'status':'New'}, {'notes':42,'status':'New'},
    {'notes':'x','status':'New','extra':True}])
def test_reject_bad_notes(client, payload):
    headers = token(client)
    result = client.post('/api/emails/case-001/investigation', data=json.dumps(payload), content_type='application/json', headers=headers)
    assert result.status_code == 400

def test_csrf_and_request_size(client):
    assert client.post('/api/emails/case-001/investigation', json={'notes':'x','status':'New'}).status_code == 403
    headers = token(client)
    result = client.post('/api/emails/case-001/investigation', data='x'*21000, content_type='application/json', headers=headers)
    assert result.status_code == 413

def test_corrupt_records_not_silently_overwritten(client, app):
    app.config['RECORDS_PATH'].write_text('{"unknown": {}}')
    assert client.get('/api/emails').status_code == 400
