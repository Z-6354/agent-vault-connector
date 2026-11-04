"""Loopback lifecycle controller and capability-scoped inline card service.

Run: python lifecycle_http.py --db <path> --session <vault_client.json>
The controller writes discovery metadata, never passphrases or account secrets.
Existing frozen broker/MCP entrypoints are not modified by this next-gen adapter.
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading
import time
import urllib.parse
import uuid

from lifecycle_core import LifecycleEngine, LifecycleError

ROOT = Path(__file__).resolve().parent

class LifecycleController:
    def __init__(self, engine):
        self.engine = engine
        self.tickets = {}
        self.lock = threading.RLock()

    def guide(self, args):
        allowed = {'intent', 'target', 'origin', 'consent', 'account', 'name'}
        if set(args) - allowed: raise LifecycleError('invalid_arguments')
        result = self.engine.guide(**args)
        if result.get('status') == 'needs_card':
            return self._ticket(result)
        return result

    def credential(self, args):
        if set(args) - {'service', 'account'}: raise LifecycleError('invalid_arguments')
        service, account = args.get('service', ''), args.get('account', '')
        if not isinstance(service, str) or not service.strip(): raise LifecycleError('invalid_service')
        if self.engine.status()['status'] != 'ready': raise LifecycleError('login_required')
        session = self.engine.sessions.load()
        return self._ticket({'mode': 'credential', 'target': session['target'],
                             'service': service, 'account': account, 'name': ''})

    def _ticket(self, context):
        with self.lock:
            self._expire()
            if len(self.tickets) >= 100: raise LifecycleError('too_many_cards')
            identifier = str(uuid.uuid4())
            cap = secrets.token_urlsafe(32)
            self.tickets[identifier] = {'context': context, 'cap': cap, 'expires': time.monotonic() + 300,
                'generation': self.engine.generation, 'busy': False, 'result': {'status': 'pending'}}
            return {'status': 'pending', 'request_id': identifier}

    def _expire(self):
        for identifier in list(self.tickets):
            item = self.tickets[identifier]
            if item['expires'] < time.monotonic() and not item['busy']:
                del self.tickets[identifier]

    def frame(self, identifier, origin):
        with self.lock:
            self._expire()
            item = self.tickets.get(identifier)
            if not item: raise LifecycleError('expired_card')
            return {'request_id': identifier, 'frame_url': origin + '/lifecycle/card/' + item['cap']}

    def by_cap(self, cap):
        with self.lock:
            self._expire()
            for item in self.tickets.values():
                if secrets.compare_digest(item['cap'], cap): return item
        raise LifecycleError('expired_card')

    def context(self, cap):
        item = self.by_cap(cap)
        return {k: item['context'].get(k, '') for k in ('mode', 'target', 'name', 'account', 'service')}

    def result(self, identifier):
        with self.lock:
            self._expire()
            item = self.tickets.get(identifier)
            if not item: return {'status': 'expired'}
            return dict(item['result'])

    def submit(self, cap, body):
        with self.lock:
            item = self.by_cap(cap)
            if item['busy']: raise LifecycleError('submission_in_progress')
            if item['result']['status'] in ('ready', 'valid', 'validation_unavailable', 'validation_unsupported'):
                return dict(item['result'])
            if item['generation'] != self.engine.generation: raise LifecycleError('stale_card')
            item['busy'] = True
            context = item['context']
        try:
            mode = context['mode']
            if mode == 'create':
                if set(body) - {'account', 'passphrase', 'confirm_passphrase', 'name'}:
                    raise LifecycleError('invalid_arguments')
                # Consent was recorded before issuing this create-only capability.
                result = self.engine.create(body.get('account'), body.get('passphrase'),
                    body.get('confirm_passphrase'), consent=True, target=context['target'],
                    origin=context.get('origin'), name=body.get('name', context.get('name', '')))
            elif mode == 'login':
                if set(body) - {'account', 'passphrase'}: raise LifecycleError('invalid_arguments')
                result = self.engine.login(body.get('account'), body.get('passphrase'),
                    target=context['target'], origin=context.get('origin'))
            else:
                if set(body) - {'account', 'service', 'secret'}: raise LifecycleError('invalid_arguments')
                if body.get('service', context['service']) != context['service']:
                    raise LifecycleError('service_mismatch')
                result = self.engine.save_and_verify(context['service'], body.get('account'),
                    body.get('secret'), generation=item['generation'])
            with self.lock: item['result'] = result
            return result
        finally:
            with self.lock: item['busy'] = False


def make_server(controller, token, port=0):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args): pass  # no paths/capabilities/payload logging

        def send(self, code, value, html=False):
            data = value.encode() if html else json.dumps(value, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'text/html; charset=utf-8' if html else 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src http://127.0.0.1:*; img-src data:; base-uri 'none'; form-action 'none'")
            if self.headers.get('Origin') == 'null': self.send_header('Access-Control-Allow-Origin', 'null')
            self.end_headers()
            self.wfile.write(data)

        @property
        def origin(self):
            return 'http://127.0.0.1:%d' % self.server.server_port

        def route(self, post=False):
            if self.headers.get('Host') != '127.0.0.1:%d' % self.server.server_port:
                return self.send(403, {'status': 'error', 'message': 'invalid_host'})
            path = urllib.parse.urlsplit(self.path).path
            card_prefix = '/lifecycle/card/'
            try:
                body = {}
                if post:
                    try: length = int(self.headers.get('Content-Length', '0'))
                    except ValueError: length = -1
                    if not 0 < length <= 131072: raise LifecycleError('invalid_body')
                    body = json.loads(self.rfile.read(length))
                    if not isinstance(body, dict): raise LifecycleError('invalid_body')
                if path.startswith(card_prefix):
                    parts = path[len(card_prefix):].split('/')
                    cap = parts[0]
                    if not post and len(parts) == 1:
                        controller.by_cap(cap)
                        return self.send(200, ROOT.joinpath('web/lifecycle-card.html').read_text(encoding='utf8'), html=True)
                    if not post and parts[1:] == ['context']:
                        return self.send(200, controller.context(cap))
                    if post and parts[1:] == ['submit']:
                        if self.headers.get('Origin') not in ('null', self.origin):
                            return self.send(403, {'status': 'error', 'message': 'invalid_origin'})
                        return self.send(200, controller.submit(cap, body))
                    raise LifecycleError('not_found')
                auth = self.headers.get('Authorization', '')
                if not secrets.compare_digest(auth, 'Bearer ' + token):
                    return self.send(401, {'status': 'error', 'message': 'unauthorized'})
                if not post and path == '/lifecycle/status': result = controller.engine.status()
                elif not post and path == '/lifecycle/probe': result = controller.engine.probe()
                elif post and path == '/lifecycle/guide': result = controller.guide(body)
                elif post and path == '/lifecycle/credential': result = controller.credential(body)
                elif not post and path.startswith('/lifecycle/frame/'):
                    result = controller.frame(path.rsplit('/', 1)[1], self.origin)
                elif not post and path.startswith('/lifecycle/result/'):
                    result = controller.result(path.rsplit('/', 1)[1])
                else: raise LifecycleError('not_found')
                return self.send(200, result)
            except LifecycleError as error:
                return self.send(400, {'status': 'error', 'message': str(error)})
            except (ValueError, TypeError):
                return self.send(400, {'status': 'error', 'message': 'invalid_body'})
            except (sqlite3.DatabaseError, OSError):
                # Locked/corrupt storage or failed session-file persistence must not
                # leak filesystem paths or arbitrary exception text into the card.
                return self.send(503, {'status': 'error', 'message': 'storage_unavailable'})

        def do_GET(self): self.route()
        def do_POST(self): self.route(True)
    return http.server.ThreadingHTTPServer(('127.0.0.1', port), Handler)


def main():
    parser = argparse.ArgumentParser(description='Next-generation inline Vault lifecycle controller')
    parser.add_argument('--db', type=Path, default=Path.home() / '.hermes/vault/vault.db')
    parser.add_argument('--session', type=Path, default=Path.home() / '.hermes/vault_client.json')
    parser.add_argument('--discovery', type=Path, default=Path.home() / '.hermes/vault-lifecycle.json')
    parser.add_argument('--port', type=int, default=3210)
    args = parser.parse_args()
    controller = LifecycleController(LifecycleEngine(args.db, args.session))
    token = secrets.token_urlsafe(32)
    server = make_server(controller, token, args.port)
    from lifecycle_core import SessionFile
    # Discovery is user-protected like session material, not a model-visible tool result.
    SessionFile(args.discovery).save({'origin': 'http://127.0.0.1:%d' % server.server_port, 'token': token})
    print('Local lifecycle controller ready (database unchanged until consent).', flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()

if __name__ == '__main__': main()
