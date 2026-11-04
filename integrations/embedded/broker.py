"""Opt-in loopback secure-input broker. Reference adapter, not a host installation."""
import argparse
import hmac
import json
import math
import os
from pathlib import Path
import secrets
import signal
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit, quote
import urllib.request
import uuid

MAX_BODY = 32 * 1024
VAULT_URL = 'https://vault.wannian.fun/api/v1/credentials'
WEB = Path(__file__).resolve().parent / 'web'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def save_to_vault(metadata, secret, timeout):
    """One HTTPS attempt; no redirects, retry, configurable URL, or secret logging."""
    session_path = Path(os.environ.get('VAULT_CLIENT_SESSION') or
                        Path.home() / '.hermes' / 'vault_client.json')
    session = json.loads(session_path.read_text(encoding='utf-8'))
    token = session['token']
    if not isinstance(token, str) or not token:
        raise ValueError('invalid session')
    body = {'service_id': metadata['service'], 'account_alias': metadata['account'],
            'secret': secret, 'credential_type': 'password',
            'allowed_operations': ['login', 'read', 'fill']}
    req = urllib.request.Request(VAULT_URL, data=json.dumps(body).encode(),
                                 headers={'Authorization': 'Bearer ' + token,
                                          'Content-Type': 'application/json'}, method='POST')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(req, timeout=min(timeout, 15)) as response:
        if response.status != 200:
            raise ValueError('save failed')
        raw = response.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise ValueError('invalid response')
        value = json.loads(raw)
    if not isinstance(value, dict) or value.get('status') != 'saved':
        raise ValueError('save failed')
    return str(uuid.UUID(value['connection_id']))


class Broker:
    """In-memory request sessions. save_callback is for synthetic tests only.

    Callback signature: (metadata, secret, remaining_seconds) -> UUID string.
    It must perform at most one bounded save; exceptions permanently decline.
    """
    def __init__(self, admin_token, *, save_callback=None):
        if not isinstance(admin_token, str) or len(admin_token) < 32 or not admin_token.isascii():
            raise ValueError('admin token must contain at least 32 ASCII characters')
        self.token = admin_token
        self._save_callback = save_callback
        self.save = save_callback or save_to_vault
        # Save callbacks may be plain `(metadata, secret, remaining) -> uuid`
        # or a request-aware adapter `(metadata, secret, remaining, request_id=...) -> uuid`.
        self.save_aware = save_callback is not None
        self.lock = threading.Lock()
        self.requests = {}
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), self._handler())
        self.server.daemon_threads = True
        self.origin = 'http://127.0.0.1:' + str(self.server.server_port)

    def _expire(self, item):
        if item['status'] == 'pending' and not item['processing'] and time.monotonic() >= item['deadline']:
            item['status'] = 'expired'

    @staticmethod
    def _result(item, metadata=False):
        result = {'request_id': item['request_id'], 'status': item['status']}
        if metadata:
            result.update({key: item[key] for key in ('service', 'account', 'prompt')})
        if item['status'] == 'captured':
            result['ref'] = item['ref']
        return result

    def _handler(self):
        broker = self

        class Handler(BaseHTTPRequestHandler):
            # Never emit HTTP request lines (card URLs contain capabilities).
            def log_message(self, format, *args):
                pass

            def handle(self):
                self.connection.settimeout(5)
                try:
                    super().handle()
                except (OSError, ValueError):
                    pass

            def send(self, status, value, mime='application/json'):
                data = json.dumps(value).encode() if mime == 'application/json' else value
                self.send_response(status)
                self.send_header('Content-Type', mime)
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Referrer-Policy', 'no-referrer')
                self.send_header('X-Content-Type-Options', 'nosniff')
                if getattr(self, 'card_authorized', False) and self.headers.get('Origin') == 'null':
                    self.send_header('Access-Control-Allow-Origin', 'null')
                    self.send_header('Vary', 'Origin')
                self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' " + broker.origin + "; frame-ancestors *")
                self.end_headers()
                self.wfile.write(data)

            def error(self, status, code):
                self.send(status, {'error': code})

            def authenticated(self):
                supplied = self.headers.get('Authorization', '')
                return hmac.compare_digest(supplied.encode(), ('Bearer ' + broker.token).encode())

            def route(self, post=False):
                parsed = urlsplit(self.path)
                path = parsed.path
                # Validate Host as well as Origin to resist DNS rebinding.
                if self.headers.get('Host') != broker.origin.removeprefix('http://'):
                    self.error(403, 'invalid_host')
                    return
                admin = path in ('/host/requests', '/host/storage', '/requests') or path.startswith('/requests/')
                if admin and not self.authenticated():
                    self.error(401, 'unauthorized')
                    return
                body = None
                if post:
                    if self.headers.get('Origin') not in (broker.origin, 'null') and not admin:
                        self.error(403, 'invalid_origin')
                        return
                    try:
                        length = int(self.headers.get('Content-Length', '-1'))
                        if self.headers.get('Transfer-Encoding') or not 0 <= length <= MAX_BODY:
                            self.error(413, 'invalid_body_size')
                            return
                        body = json.loads(self.rfile.read(length))
                        if not isinstance(body, dict):
                            raise ValueError()
                    except (ValueError, UnicodeError):
                        self.error(400, 'invalid_json')
                        return
                if path == '/requests' and post:
                    self.create(body)
                elif path == '/host/storage' and not post:
                    status = 'local' if broker.save_aware else 'remote'
                    self.send(200, {'storage': status, 'location': status})
                elif path == '/host/requests' and not post:
                    with broker.lock:
                        pending = []
                        for item in broker.requests.values():
                            broker._expire(item)
                            if item['status'] == 'pending':
                                value = broker._result(item, True)
                                value['timeout_s'] = item['timeout_s']
                                value['frame_url'] = broker.origin + '/card/' + item['request_id'] + '?key=' + item['key']
                                pending.append(value)
                    self.send(200, {'requests': pending})
                elif path.startswith('/requests/') and not post:
                    with broker.lock:
                        item = broker.requests.get(path.removeprefix('/requests/'))
                        if item:
                            broker._expire(item)
                            value = broker._result(item)
                        else:
                            value = None
                    self.send(200, value) if value else self.error(404, 'not_found')
                elif path in ('/assets/card.js', '/assets/card.css') and not post:
                    self.asset(path.rsplit('/', 1)[1])
                elif path.startswith('/card/'):
                    query = parse_qs(parsed.query)
                    request_id = path.removeprefix('/card/')
                    value = None
                    with broker.lock:
                        item = broker.requests.get(request_id)
                        keys = query.get('key', [])
                        valid = item and len(keys) == 1 and hmac.compare_digest(keys[0].encode(), item['key'].encode())
                        if valid:
                            broker._expire(item)
                            value = broker._result(item, True)
                            value['timeout_s'] = item['timeout_s']
                    self.card_authorized = bool(valid)
                    if not valid:
                        self.error(404, 'not_found')
                    elif post:
                        self.submit(item, body)
                    elif query.get('format') == ['json']:
                        self.send(200, value)
                    else:
                        self.asset('card.html')
                else:
                    self.error(404, 'not_found')

            def asset(self, name):
                try:
                    content = (WEB / name).read_bytes()
                except OSError:
                    self.error(404, 'asset_unavailable')
                    return
                mime = {'card.html': 'text/html; charset=utf-8', 'card.js': 'application/javascript',
                        'card.css': 'text/css'}[name]
                self.send(200, content, mime)

            def create(self, body):
                fields = ('service', 'account', 'prompt')
                if (set(body) - set(fields) - {'timeout_s'} or
                    any(not isinstance(body.get(k), str) or not body[k].strip() or len(body[k]) > 1024 for k in fields)):
                    self.error(400, 'invalid_metadata')
                    return
                ttl = body.get('timeout_s', 120)
                if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or not math.isfinite(ttl) or not 0 < ttl <= 3600:
                    self.error(400, 'invalid_timeout')
                    return
                with broker.lock:
                    for item in broker.requests.values():
                        broker._expire(item)
                    if sum(item['status'] == 'pending' for item in broker.requests.values()) >= 16:
                        self.error(429, 'pending_limit')
                        return
                    request_id = str(uuid.uuid4())
                    item = {k: body[k] for k in fields}
                    item.update(request_id=request_id, key=secrets.token_urlsafe(32), timeout_s=ttl,
                                deadline=time.monotonic() + ttl, status='pending', processing=False)
                    broker.requests[request_id] = item
                self.send(201, broker._result(item))

            def submit(self, item, body):
                decline = set(body) == {'declined'} and body['declined'] is True
                if not decline and (set(body) != {'secret'} or not isinstance(body['secret'], str) or not body['secret']):
                    self.error(400, 'invalid_submission')
                    return
                with broker.lock:
                    broker._expire(item)
                    if item['status'] != 'pending' or item['processing']:
                        self.send(409, broker._result(item))
                        return
                    if decline:
                        item['status'] = 'declined'
                        self.send(200, broker._result(item))
                        return
                    item['processing'] = True
                    remaining = item['deadline'] - time.monotonic()
                    if remaining <= 0:
                        item.update(processing=False, status='expired')
                        self.send(409, broker._result(item))
                        return
                try:
                    metadata = {k: item[k] for k in ('service', 'account', 'prompt')}
                    try:
                        outcome = broker.save(metadata, body['secret'], remaining, request_id=item['request_id'])
                    except TypeError:
                        # Plain test/synthetic callbacks use the 3-argument form.
                        outcome = broker.save(metadata, body['secret'], remaining)
                    if isinstance(outcome, str):
                        reference = str(uuid.UUID(outcome))
                    elif isinstance(outcome, tuple) and len(outcome) == 2 and isinstance(outcome[0], str):
                        reference = str(uuid.UUID(outcome[0]))
                    else:
                        raise ValueError('invalid_reference')
                except Exception:
                    # Do not reflect exception text, response bodies, tokens, or the input.
                    with broker.lock:
                        item.update(status='declined', processing=False)
                    self.error(502, 'save_failed')
                    return
                finally:
                    body.clear()
                with broker.lock:
                    item.update(status='captured', processing=False, ref='vault://' + quote(item['service'], safe='') + '/' + quote(item['account'], safe=''))
                    value = broker._result(item)
                self.send(200, value)

            def do_GET(self):
                self.route()

            def do_POST(self):
                self.route(True)

        return Handler

    def serve_forever(self):
        self.server.serve_forever(poll_interval=0.1)

    def close(self):
        self.server.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serve', action='store_true', required=True)
    parser.add_argument('--token-file', type=Path)
    parser.add_argument('--discovery-file', type=Path, required=True)
    parser.add_argument('--local', action='store_true', help='use the authenticated local Vault management backend instead of the fixed remote endpoint')
    args = parser.parse_args()
    if not args.discovery_file.is_absolute():
        parser.error('--discovery-file must be absolute')
    broker = None
    created = False
    def stop(signum, frame):
        raise KeyboardInterrupt()
    previous_sigterm = signal.signal(signal.SIGTERM, stop)
    try:
        token = args.token_file.read_text(encoding='utf-8').strip() if args.token_file else secrets.token_urlsafe(32)
        save_callback = None
        if args.local:
            try:
                from .local_store import make_local_save_callback
            except ImportError:
                from local_store import make_local_save_callback
            save_callback, _adapter = make_local_save_callback()
        broker = Broker(token, save_callback=save_callback)
        # Exclusive creation avoids overwriting existing configuration or following symlinks.
        fd = os.open(args.discovery_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        if os.name != 'nt' and os.fstat(fd).st_mode & 0o777 != 0o600:
            os.close(fd)
            raise ValueError('private discovery permissions unavailable')
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump({'origin': broker.origin, 'token': token}, stream)
        print(json.dumps({'status': 'ready', 'origin': broker.origin}), flush=True)
        broker.serve_forever()
    except KeyboardInterrupt:
        pass
    except Exception:
        # No exception representation: it may contain session/token material.
        print(json.dumps({'status': 'error', 'error': 'broker_start_or_serve_failed'}), flush=True)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm)
        if broker:
            broker.close()
        if created:
            args.discovery_file.unlink(missing_ok=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
