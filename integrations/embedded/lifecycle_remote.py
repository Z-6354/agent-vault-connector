"""TLS cloud protocol adapter, loopback bound for an operator-managed tunnel/proxy.

No cloud provisioning is performed by the desktop agent. Creation requires an
operator bootstrap token held in protected native config; existing vault login
uses the owner account and master password. No endpoint returns credential secrets.
"""
import argparse
import http.server
import json
from pathlib import Path
import secrets
import ssl
import sqlite3

from lifecycle_core import LifecycleEngine, LifecycleError, SessionFile


def make_remote_server(engine, bootstrap_token, tls_context, port=0, *, expected_host=None):
    if tls_context is None: raise ValueError('tls_required')
    if len(bootstrap_token) < 32: raise ValueError('invalid_bootstrap')
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args): pass
        def send(self, code, value):
            data = json.dumps(value).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers(); self.wfile.write(data)

        def route(self, post=False):
            allowed_host = expected_host or '127.0.0.1:%d' % self.server.server_address[1]
            if self.headers.get('Host') != allowed_host or self.headers.get('Origin') is not None:
                return self.send(403, {'status': 'error', 'message': 'invalid_origin'})
            path = self.path
            try:
                body = {}
                if post:
                    length = int(self.headers.get('Content-Length', 0))
                    if not 0 < length <= 131072: raise LifecycleError('invalid_body')
                    body = json.loads(self.rfile.read(length))
                    if not isinstance(body, dict): raise LifecycleError('invalid_body')
                if not post and path == '/lifecycle/probe':
                    return self.send(200, engine.probe())
                if post and path == '/lifecycle/create':
                    if not secrets.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + bootstrap_token):
                        return self.send(403, {'status': 'error', 'message': 'creation_not_authorized'})
                    if set(body) - {'account', 'passphrase', 'confirm_passphrase', 'consent', 'name'}:
                        raise LifecycleError('invalid_arguments')
                    with engine.lock:
                        result = engine.create(**body)
                        result['token'] = engine.sessions.load()['token']
                    return self.send(200, result)
                if post and path == '/lifecycle/login':
                    if set(body) != {'account', 'passphrase'}: raise LifecycleError('invalid_arguments')
                    with engine.lock:
                        result = engine.login(**body)
                        result['token'] = engine.sessions.load()['token']
                    return self.send(200, result)
                auth = self.headers.get('Authorization', '')
                if not auth.startswith('Bearer '): raise LifecycleError('session_expired')
                session = engine.session_for_token(auth[7:])
                if not post and path == '/lifecycle/session':
                    return self.send(200, {'status': 'ready'})
                if post and path == '/lifecycle/credentials':
                    if set(body) != {'service', 'account', 'secret'}: raise LifecycleError('invalid_arguments')
                    return self.send(200, engine.save_and_verify(**body, authenticated_session=session))
                raise LifecycleError('not_found')
            except LifecycleError as error:
                code = 401 if str(error) in ('invalid_login', 'session_expired') else 400
                return self.send(code, {'status': 'error', 'message': str(error)})
            except (ValueError, TypeError, sqlite3.DatabaseError):
                return self.send(400, {'status': 'error', 'message': 'invalid_request'})
        def do_GET(self): self.route()
        def do_POST(self): self.route(True)
    server = http.server.ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    return server


def main():
    parser = argparse.ArgumentParser(description='Operator-managed TLS Vault lifecycle backend')
    parser.add_argument('--db', type=Path, required=True)
    parser.add_argument('--session', type=Path, required=True)
    parser.add_argument('--bootstrap-file', type=Path, required=True)
    parser.add_argument('--tls-cert', type=Path, required=True)
    parser.add_argument('--tls-key', type=Path, required=True)
    parser.add_argument('--host-header')
    parser.add_argument('--port', type=int, default=3210)
    args = parser.parse_args()
    config = SessionFile(args.bootstrap_file).load()
    if not config or not isinstance(config.get('token'), str):
        raise SystemExit('Protected bootstrap configuration required; never enter it in chat.')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.tls_cert, args.tls_key)
    engine = LifecycleEngine(args.db, args.session)
    server = make_remote_server(engine, config['token'], context, args.port, expected_host=args.host_header)
    print('TLS Vault backend ready on loopback; database creation still requires explicit consent.', flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()

if __name__ == '__main__': main()
