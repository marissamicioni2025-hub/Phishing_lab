"""Run with python app.py; loopback only, with debug disabled."""
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from flask import Flask, abort, jsonify, render_template, request, session, Response
from werkzeug.exceptions import HTTPException
from phishing_lab.analysis import analyze
from phishing_lab.storage import STATUSES, read_json, save_records, validate_samples

ROOT = Path(__file__).resolve().parent

def create_app(config=None):
    app = Flask(__name__)
    app.config.update(SECRET_KEY=secrets.token_hex(32), MAX_CONTENT_LENGTH=20000,
                      RECORDS_PATH=ROOT / 'data/investigations.json',
                      SAMPLES_PATH=ROOT / 'data/emails.json', SESSION_COOKIE_SAMESITE='Strict',
                      SESSION_COOKIE_HTTPONLY=True)
    if config:
        app.config.update(config)
    samples = validate_samples(read_json(app.config['SAMPLES_PATH']))
    by_id = {item['id']: item for item in samples}
    lock = Lock()
    def records():
        path = Path(app.config['RECORDS_PATH'])
        data = read_json(path, 2_000_000) if path.exists() else {}
        if not isinstance(data, dict) or len(data) > 100:
            raise ValueError('Invalid investigation records')
        for key, value in data.items():
            if key not in by_id or not isinstance(value, dict) or value.get('status') not in STATUSES or not isinstance(value.get('notes'), str) or len(value['notes']) > 5000 or not isinstance(value.get('updated_at'), str):
                raise ValueError('Invalid investigation record')
        return data
    def case(case_id):
        if case_id not in by_id:
            abort(404)
        return by_id[case_id]
    def record(case_id):
        return records().get(case_id, {'status': 'New', 'notes': '', 'updated_at': 'Not saved'})
    @app.after_request
    def security_headers(response):
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Cache-Control'] = 'no-store'
        return response
    @app.errorhandler(ValueError)
    def invalid_data(error):
        return jsonify(error='Invalid local JSON data. Check its schema and size.'), 400
    @app.errorhandler(HTTPException)
    def http_error(error):
        return jsonify(error=error.description), error.code
    @app.get('/')
    def dashboard():
        session.setdefault('csrf', secrets.token_hex(32))
        return render_template('index.html', csrf=session['csrf'])
    @app.get('/api/emails')
    def emails():
        saved = records()
        return jsonify([dict(id=e['id'], subject=e['subject'], display_name=e['display_name'],
                            difficulty=e['difficulty'], score=analyze(e)['score'], risk=analyze(e)['risk'],
                            status=saved.get(e['id'], {}).get('status', 'New')) for e in samples])
    @app.get('/api/emails/<case_id>')
    def details(case_id):
        email = case(case_id)
        return jsonify(email=email, analysis=analyze(email), investigation=record(case_id))
    @app.post('/api/emails/<case_id>/investigation')
    def update(case_id):
        case(case_id)
        token = request.headers.get('X-CSRF-Token', '')
        if not session.get('csrf') or not secrets.compare_digest(token, session['csrf']):
            abort(403, 'Reload the page before saving.')
        payload = request.get_json()
        if not isinstance(payload, dict) or set(payload) != {'status', 'notes'} or payload.get('status') not in STATUSES or not isinstance(payload.get('notes'), str) or len(payload['notes']) > 5000:
            abort(400, 'Use a valid status and notes of at most 5,000 characters.')
        result = dict(payload, updated_at=datetime.now(timezone.utc).isoformat())
        with lock:
            saved = records()
            saved[case_id] = result
            save_records(app.config['RECORDS_PATH'], saved)
        return jsonify(result)
    @app.get('/api/emails/<case_id>/export')
    def export(case_id):
        email = case(case_id)
        report = dict(synthetic=True, email=email, analysis=analyze(email), investigation=record(case_id))
        fmt = request.args.get('format', 'json')
        if fmt not in ('json', 'txt'):
            abort(400, 'Supported formats: json, txt')
        if fmt == 'json':
            content = json.dumps(report, indent=2)
        else:
            result = report['analysis']
            content = '\n'.join(['SYNTHETIC SOC INVESTIGATION — ' + case_id, result['disclaimer'],
                'Subject: ' + email['subject'], 'From: ' + email['from_address'], 'Reply-To: ' + email['reply_to'],
                'Body: ' + email['body'], f"Risk: {result['score']}/100 ({result['risk']})",
                'Findings:'] + [f"+{f['weight']} {f['rule']}: {f['explanation']}" for f in result['findings']] +
                ['Authentication: ' + json.dumps(email['authentication']), result['authentication_note'],
                 'IOCs (inert): ' + json.dumps(result['iocs']), 'Recommended actions:'] + result['actions'] +
                ['Status: ' + report['investigation']['status'], 'Notes: ' + report['investigation']['notes'],
                 'Updated: ' + report['investigation']['updated_at']])
        return Response(content, mimetype='application/json' if fmt == 'json' else 'text/plain',
                        headers={'Content-Disposition': f'attachment; filename="{case_id}.{fmt}"'})
    return app

if __name__ == '__main__':
    create_app().run(host='127.0.0.1', port=5000, debug=False)
