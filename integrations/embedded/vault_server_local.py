"""Single-file local Vault management service (loopback-only, SQLite + AES-256-GCM).

Newcomer-friendly one-file deployment:
- Pure Python stdlib for transport/storage (http.server, sqlite3, hashlib PBKDF2);
  AES-256-GCM via the installed `cryptography` package (the only non-stdlib need).
- Binds 127.0.0.1:3210 only — zero network exposure.
- Database: C:/Users/han/.hermes/vault/vault.db (auto-created if missing, and fully
  compatible with the existing credentials/meta schema — existing rows untouched).
- Storage-only policy: ANY real service name (deepseek-api, github, ...) is accepted
  for credential_type='password' with granted_operations=[] (zero executable
  permissions). Secrets are AES-256-GCM encrypted before hitting disk and are never
  returned by any endpoint.
- API matches local_backend.py: POST /management/login, POST /management/unlock,
  GET /management/session, GET /management/connections, POST /management/drafts,
  POST /management/drafts/<id>/confirm. Bearer token + vault_session cookie + CSRF.

Usage:
  python vault_server_local.py --install            (create dirs/db/env file)
  python vault_server_local.py --serve              (run on 127.0.0.1:3210)
  python vault_server_local.py --serve --auto-unlock (also unlock from env file)
  python vault_server_local.py --status
Options: --port, --db, --env-file, --passphrase (install only).
"""
import argparse
import contextlib
import base64
import hashlib
import hmac
import http.server
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading
import time
import urllib.parse

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as error:
    raise SystemExit('vault_server_local requires the `cryptography` package for AES-256-GCM '
                     '(installed in this environment as cryptography 50.0.2): %s' % error)

DEFAULT_DB = str(Path.home() / '.hermes' / 'vault' / 'vault.db')
DEFAULT_PORT = 3210
KDF_ITERATIONS = 200_000
VERIFIER_ITERATIONS = 100_000
PBKDF2 = 'sha256'
MAX_BODY = 1 << 20  # 1 MiB

# ---------------------------------------------------------------------------
# crypto helpers

def _derive(passphrase: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac(PBKDF2, passphrase.encode('utf8'), salt, iterations)

def _self_check() -> None:
    """Round-trip check that AES-256-GCM works in this environment at startup."""
    key = os.urandom(32); nonce = os.urandom(12); data = b'self-check'
    sealed = AESGCM(key).encrypt(nonce, data, b'vault-local')
    assert AESGCM(key).decrypt(nonce, sealed, b'vault-local') == data, 'AES-GCM self-check failed'

# ---------------------------------------------------------------------------
# storage

class Store:
    """SQLite-backed credential store, compatible with the existing schema."""

    def __init__(self, db_path: str):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    @contextlib.contextmanager
    def _connect(self):
        con = sqlite3.connect(str(self.path), timeout=10)
        try:
            with con:
                yield con
        finally:
            con.close()

    def _init_schema(self):
        with self._lock, self._connect() as con:
            con.execute("""CREATE TABLE IF NOT EXISTS credentials (
                connection_id TEXT PRIMARY KEY,
                service_id TEXT NOT NULL,
                account_alias TEXT NOT NULL,
                credential_type TEXT NOT NULL DEFAULT 'api_key',
                ciphertext_blob BLOB NOT NULL,
                iv BLOB NOT NULL,
                tag BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL)""")
            con.execute("""CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY, value TEXT NOT NULL)""")

    def meta_get(self, key: str):
        with self._lock, self._connect() as con:
            row = con.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
            return row[0] if row else None

    def meta_set(self, key: str, value: str):
        with self._lock, self._connect() as con:
            con.execute('INSERT INTO meta(key,value) VALUES(?,?) '
                        'ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, value))

    def insert_credential(self, service_id: str, account_alias: str, credential_type: str,
                          key: bytes, secret: str) -> str:
        """Encrypt secret with AES-256-GCM and persist. Returns connection_id."""
        connection_id = str(__import__('uuid').uuid4())
        nonce = os.urandom(12)
        now = int(time.time())
        sealed = AESGCM(key).encrypt(nonce, secret.encode('utf8'), b'vault-local')
        ciphertext, tag = sealed[:-16], sealed[-16:]
        with self._lock, self._connect() as con:
            con.execute('INSERT INTO credentials(connection_id, service_id, account_alias, '
                        'credential_type, ciphertext_blob, iv, tag, created_at, updated_at) '
                        'VALUES(?,?,?,?,?,?,?,?,?)',
                        (connection_id, service_id, account_alias, credential_type,
                         ciphertext, nonce, tag, now, now))
        return connection_id

    def credential_count(self) -> int:
        with self._lock, self._connect() as con:
            return con.execute('SELECT COUNT(*) FROM credentials').fetchone()[0]

# ---------------------------------------------------------------------------
# server

class LocalVault:
    """Session state machine: S0 anonymous -> S1 authenticated -> S2 unlocked.

    With token-direct mode (auto-unlock), a valid Bearer token on a loopback
    request is itself treated as an authenticated S2 session: the token lives in
    the management env file next to the passphrase, both user-profile scoped, and
    an explicit Authorization header cannot be attached by a cross-site page —
    which is what CSRF protection exists for.
    """

    def __init__(self, token: str, store: Store, token_session: bool = False):
        self.admin_token = token
        self.store = store
        self.token_session = token_session
        self._sessions = {}          # sid -> {'csrf': str, 'state': 'S1'|'S2'}
        self._master_key = None      # bytes while unlocked, None while locked
        self._drafts = {}            # draft_id -> {version, payload}
        salt_hex = store.meta_get('kdf_salt')
        if salt_hex is None:
            salt_hex = os.urandom(32).hex()
            store.meta_set('kdf_salt', salt_hex)
        self.salt = bytes.fromhex(salt_hex)
        verifier_hex = store.meta_get('kdf_verifier')
        if verifier_hex is None:
            # not yet initialized with a passphrase: install() sets it
            self.verifier = None
        else:
            self.verifier = bytes.fromhex(verifier_hex)

    # -- auth helpers ------------------------------------------------------
    def set_passphrase(self, passphrase: str):
        self.store.meta_set('kdf_verifier', _derive(passphrase, b'verifier:' + self.salt,
                                                    VERIFIER_ITERATIONS).hex())
        self.verifier = _derive(passphrase, b'verifier:' + self.salt, VERIFIER_ITERATIONS)

    def check_passphrase(self, passphrase: str) -> bool:
        candidate = _derive(passphrase, b'verifier:' + self.salt, VERIFIER_ITERATIONS)
        return hmac.compare_digest(candidate, self.verifier or b'')

    def master_key(self, passphrase: str) -> bytes:
        return _derive(passphrase, self.salt, KDF_ITERATIONS)

    def new_session(self, state: str):
        sid = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        self._sessions[sid] = {'csrf': csrf, 'state': state, 'created': time.time()}
        return sid, csrf

    def session(self, sid: str):
        return self._sessions.get(sid)

    def unlock(self, sid: str, passphrase: str) -> bool:
        if not self.check_passphrase(passphrase):
            return False
        self._master_key = self.master_key(passphrase)
        entry = self._sessions.get(sid)
        if entry: entry['state'] = 'S2'
        return True

    def lock(self):
        self._master_key = None

    def unlocked(self) -> bool:
        return self._master_key is not None

    def key(self) -> bytes:
        if self._master_key is None:
            raise PermissionError('vault_locked')
        return self._master_key

    # -- drafts ------------------------------------------------------------
    def create_draft(self, payload: dict):
        draft_id = secrets.token_urlsafe(16)
        version = 1
        self._drafts[draft_id] = {'version': version, 'payload': payload, 'created': time.time()}
        return draft_id, version

    def confirm_draft(self, draft_id: str, version):
        entry = self._drafts.pop(draft_id, None)
        if not entry or entry['version'] != version:
            return None
        return entry['payload']


def make_handler(vault: LocalVault, port: int):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        server_version = 'vault-local/1.0'

        def log_message(self, format, *args):  # never log payloads
            print('[http] %s %s' % (self.command, self.path), flush=True)

        def _send(self, code, value, cookie=None):
            data = json.dumps(value).encode('utf8')
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            if cookie:
                self.send_header('Set-Cookie', 'vault_session=%s; HttpOnly; SameSite=Strict' % cookie)
            self.end_headers()
            self.wfile.write(data)

        def _authorized(self):
            if self.headers.get('Host') not in ('127.0.0.1:%d' % port, 'localhost:%d' % port):
                return False
            provided = self.headers.get('Authorization') or ''
            expected = 'Bearer ' + vault.admin_token
            return hmac.compare_digest(provided.encode(), expected.encode())

        def _session_state(self):
            cookie = self.headers.get('Cookie') or ''
            for part in cookie.split(';'):
                part = part.strip()
                if part.startswith('vault_session='):
                    return vault.session(part.split('=', 1)[1])
            return None

        def _session_id(self):
            cookie = self.headers.get('Cookie') or ''
            for part in cookie.split(';'):
                part = part.strip()
                if part.startswith('vault_session='):
                    return part.split('=', 1)[1]
            return None

        def _csrf_ok(self, entry):
            if not entry:
                return False
            return hmac.compare_digest(self.headers.get('X-CSRF-Token') or '', entry['csrf'])

        def _body(self):
            length = int(self.headers.get('Content-Length') or 0)
            if length <= 0 or length > MAX_BODY:
                return {}
            try:
                return json.loads(self.rfile.read(length) or b'{}')
            except ValueError:
                return {}

        def do_GET(self):
            if not self._authorized():
                return self._send(401, {'error': 'unauthorized'})
            path = urllib.parse.urlparse(self.path).path
            if path == '/management/session':
                entry = self._session_state()
                if not entry and vault.token_session and vault.unlocked():
                    # token-direct: Bearer token on loopback counts as an unlocked session
                    return self._send(200, {'authenticated': True, 'state': 'S2', 'unlocked': True})
                if not entry:
                    return self._send(200, {'authenticated': False, 'state': 'S0'})
                return self._send(200, {'authenticated': True, 'state': entry['state'],
                                        'unlocked': vault.unlocked()})
            if path == '/management/connections':
                return self._send(200, {'services': [
                    {'service_id': 'synthetic-login', 'origin': 'http://127.0.0.1:%d' % port,
                     'credential_types': ['password'], 'operations': []}]})
            return self._send(404, {'error': 'not_found'})

        def _write_session(self):
            """Resolve the acting session for a write: cookie session (CSRF-checked)
            or, in token-direct mode, the Bearer token itself."""
            entry = self._session_state()
            if entry:
                if not self._csrf_ok(entry):
                    return 'csrf'
                if entry['state'] != 'S2' or not vault.unlocked():
                    return 'locked'
                return entry
            if vault.token_session and vault.unlocked():
                return 'token-direct'
            return 'auth'

        def do_POST(self):
            if not self._authorized():
                return self._send(401, {'error': 'unauthorized'})
            path = urllib.parse.urlparse(self.path).path
            body = self._body()
            entry = self._session_state()

            if path == '/management/login':
                if not vault.check_passphrase(body.get('passphrase') or ''):
                    return self._send(401, {'error': 'invalid_passphrase'})
                sid, csrf = vault.new_session('S1')
                return self._send(200, {'authenticated': True, 'csrf': csrf, 'state': 'S1'}, cookie=sid)

            if path == '/management/unlock':
                if not vault.check_passphrase(body.get('passphrase') or ''):
                    return self._send(401, {'error': 'invalid_passphrase'})
                if not entry:
                    sid, csrf = vault.new_session('S2')
                    vault.unlock(sid, body.get('passphrase') or '')
                    return self._send(200, {'csrf': csrf, 'state': 'S2'}, cookie=sid)
                if not vault.unlock(self._session_id() or '', body.get('passphrase') or ''):
                    return self._send(409, {'error': 'unlock_failed'})
                return self._send(200, {'csrf': entry['csrf'], 'state': 'S2'})

            if path == '/management/drafts':
                session = self._write_session()
                if session == 'csrf':
                    return self._send(403, {'error': 'csrf_required'})
                if session == 'locked':
                    return self._send(423, {'error': 'vault_locked'})
                if session == 'auth':
                    return self._send(403, {'error': 'session_required'})
                # storage-only policy enforcement
                if (body.get('credential_type') != 'password'
                        or body.get('granted_operations') != []
                        or not body.get('service_id') or not str(body.get('service_id')).strip()
                        or not body.get('account_alias')
                        or not isinstance(body.get('secret'), str) or not body.get('secret')):
                    return self._send(400, {'error': 'invalid_draft'})
                draft_id, version = vault.create_draft(body)
                return self._send(201, {'draft': {'draft_id': draft_id, 'draft_version': version},
                                        'request_id': secrets.token_urlsafe(16)})

            if path.startswith('/management/drafts/') and path.endswith('/confirm'):
                session = self._write_session()
                if session == 'csrf':
                    return self._send(403, {'error': 'csrf_required'})
                if session == 'locked':
                    return self._send(423, {'error': 'vault_locked'})
                if session == 'auth':
                    return self._send(403, {'error': 'session_required'})
                draft_id = path[len('/management/drafts/'):-len('/confirm')]
                payload = vault.confirm_draft(draft_id, body.get('draft_version'))
                if payload is None:
                    return self._send(409, {'error': 'draft_conflict'})
                connection_id = vault.store.insert_credential(
                    str(payload['service_id']), str(payload['account_alias']),
                    'password', vault.key(), str(payload['secret']))
                # never echo the secret back; only the reference identity
                return self._send(200, {'connection': {'id': connection_id, 'status': 'active'}})

            return self._send(404, {'error': 'not_found'})

    return Handler

# ---------------------------------------------------------------------------
# install / serve / status

def _env_path(args):
    return Path(args.env_file or os.path.join(os.environ.get('TEMP') or str(Path.home()), 'agent-vault-management.env'))

def do_install(args):
    store = Store(args.db)
    env_path = _env_path(args)
    already_initialized = store.meta_get('kdf_verifier') is not None and env_path.exists()
    if already_initialized:
        print('already initialized (existing passphrase/verifier kept): %s' % args.db)
        print('management env: %s' % env_path)
        return 0
    token = secrets.token_urlsafe(32)
    passphrase = args.passphrase or secrets.token_urlsafe(24)
    vault = LocalVault(token, store)
    vault.set_passphrase(passphrase)
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text(json.dumps({
        'origin': 'http://127.0.0.1:%d' % args.port,
        'token': token,
        'passphrase': passphrase,
    }, indent=2), encoding='utf8')
    print('initialized db: %s (%d existing credentials preserved)' % (args.db, store.credential_count()))
    print('management env: %s' % env_path)
    return 0

def do_serve(args):
    _self_check()
    env_path = _env_path(args)
    try:
        config = json.loads(env_path.read_text(encoding='utf8'))
        token = config['token']
    except (OSError, ValueError, KeyError):
        raise SystemExit('missing management env file; run --install first (%s)' % env_path)
    store = Store(args.db)
    vault = LocalVault(token, store, token_session=args.auto_unlock)
    if vault.verifier is None:
        raise SystemExit('database has no passphrase set; run --install first')
    if args.auto_unlock:
        passphrase = config.get('passphrase') or ''
        if vault.check_passphrase(passphrase):
            vault._master_key = vault.master_key(passphrase)
            print('auto-unlocked from management env (S2)', flush=True)
        else:
            print('auto-unlock failed: passphrase mismatch', flush=True)
    server = http.server.ThreadingHTTPServer(('127.0.0.1', args.port), make_handler(vault, args.port))
    print('vault-local serving on http://127.0.0.1:%d (db=%s, credentials=%d, state=%s)' %
          (args.port, args.db, store.credential_count(), 'S2' if vault.unlocked() else 'S1'), flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0

def do_status(args):
    env_path = _env_path(args)
    print('env file: %s (%s)' % (env_path, 'present' if env_path.exists() else 'MISSING'))
    store = Store(args.db)
    print('db: %s (%d bytes, %d credentials)' % (args.db, Path(args.db).stat().st_size if Path(args.db).exists() else 0, store.credential_count()))
    import urllib.request, urllib.error
    try:
        req = urllib.request.Request('http://127.0.0.1:%d/management/session' % args.port,
                                     headers={'Authorization': 'Bearer ' + json.loads(env_path.read_text(encoding='utf8'))['token']})
        with urllib.request.urlopen(req, timeout=3) as response:
            print('service: %s' % json.loads(response.read()))
    except Exception as error:
        print('service: not reachable (%s)' % error)
    return 0

def main():
    parser = argparse.ArgumentParser(description='single-file local Vault (loopback only)')
    parser.add_argument('command', choices=['install', 'serve', 'status'])
    parser.add_argument('--db', default=DEFAULT_DB)
    parser.add_argument('--port', type=int, default=DEFAULT_PORT)
    parser.add_argument('--env-file')
    parser.add_argument('--passphrase', help='install: explicit master passphrase (default: random)')
    parser.add_argument('--auto-unlock', action='store_true', help='serve: unlock using env-file passphrase')
    args = parser.parse_args()
    raise SystemExit({'install': do_install, 'serve': do_serve, 'status': do_status}[args.command](args))

if __name__ == '__main__':
    main()
