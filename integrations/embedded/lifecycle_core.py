"""Next-generation Vault lifecycle. Secrets stay inside local/native submit paths.

Reuses the existing credentials/meta SQLite layout and AES-GCM ciphertext format.
No database is created by probing. New account/session/validation metadata is only
created after explicit creation consent. Legacy databases require explicit migration.
"""
import base64
import contextlib
import ctypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from credential_verifier import NoRedirect, probe_and_verify_credential
from vault_server_local import Store, _derive, KDF_ITERATIONS

INITIALIZED = '初始化就绪！请告诉 agent 需要输入什么类型密码；请勿在聊天框发送密码或 Token。'
UNREACHABLE = '连接失败，请检查地址、网络及公网安全组/防火墙；若服务使用 3210 端口，请核对该端口。'

class LifecycleError(Exception):
    pass


def _dpapi(data, decrypt=False):
    """Windows current-user protection, with UI disabled; never returns to tools."""
    from ctypes import wintypes
    class Blob(ctypes.Structure):
        _fields_ = [('size', wintypes.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]
    buffer = ctypes.create_string_buffer(data)
    src = Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    dst = Blob()
    crypt = ctypes.WinDLL('crypt32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    crypt.CryptProtectData.argtypes = [ctypes.POINTER(Blob), ctypes.c_wchar_p,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    crypt.CryptUnprotectData.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    if decrypt:
        ok = crypt.CryptUnprotectData(ctypes.byref(src), None, None, None, None, 1, ctypes.byref(dst))
    else:
        ok = crypt.CryptProtectData(ctypes.byref(src), 'Vault session', None, None, None, 1, ctypes.byref(dst))
    if not ok:
        raise LifecycleError('session_protection_failed')
    try:
        return ctypes.string_at(dst.data, dst.size)
    finally:
        kernel.LocalFree(ctypes.cast(dst.data, ctypes.c_void_p))


class SessionFile:
    """Durable vault_client.json. DPAPI on Windows; owner-only file on POSIX.

    Only tokens and metadata persist, never passphrases. Same-user privileged
    tools remain outside this protection boundary.
    """
    def __init__(self, path):
        self.path = Path(path)

    def load(self):
        if not self.path.exists(): return None
        try:
            value = json.loads(self.path.read_text(encoding='utf8'))
            if value.get('protection') == 'dpapi':
                value = json.loads(_dpapi(base64.b64decode(value['data']), True))
            elif os.name == 'nt' or self.path.stat().st_mode & 0o077:
                raise LifecycleError('unsafe_session_file')
            return value
        except (OSError, ValueError, KeyError):
            raise LifecycleError('invalid_session_file') from None

    def save(self, value):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(value).encode('utf8')
        if os.name == 'nt':
            data = json.dumps({'protection': 'dpapi', 'data': base64.b64encode(_dpapi(data)).decode()}).encode()
        temp = self.path.with_name(self.path.name + '.' + secrets.token_hex(6))
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            os.replace(temp, self.path)
        finally:
            if temp.exists(): temp.unlink()


class RemoteClient:
    """Creation bootstrap comes from native protected config, never tool arguments."""
    def __init__(self, targets_path, *, tls_context=None):
        self.targets = SessionFile(targets_path)
        self.tls_context = tls_context

    def __call__(self, origin, path, body=None, token=None):
        if path == '/lifecycle/create':
            targets = self.targets.load() or {}
            token = targets.get(origin)
            if not token: raise LifecycleError('cloud_create_requires_provisioning')
        return remote_request(origin, path, body, token, tls_context=self.tls_context)


def remote_request(origin, path, body=None, token=None, *, tls_context=None):
    """HTTPS only, no redirects, no implicit proxies, no upstream error bodies."""
    parsed = urllib.parse.urlsplit(origin)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ('', '/') or parsed.query or parsed.fragment):
        raise LifecycleError('invalid_remote_origin')
    headers = {'Content-Type': 'application/json'}
    if token: headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(origin.rstrip('/') + path,
        data=None if body is None else json.dumps(body).encode(), headers=headers)
    handlers = [urllib.request.ProxyHandler({}), NoRedirect()]
    if tls_context is not None: handlers.append(urllib.request.HTTPSHandler(context=tls_context))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=5) as response:
            raw = response.read(65537)
            if len(raw) > 65536: raise LifecycleError('invalid_remote_response')
            return response.status, json.loads(raw)
    except urllib.error.HTTPError as error:
        code = error.code; error.close()
        return code, {}
    except (OSError, ValueError, urllib.error.URLError):
        raise LifecycleError('remote_unreachable') from None


class LifecycleEngine:
    def __init__(self, db_path=None, session_path=None, *, verifier=None, remote=None):
        self.db = Path(db_path or Path.home() / '.hermes/vault/vault.db')
        self.sessions = SessionFile(session_path or Path.home() / '.hermes/vault_client.json')
        self.verify = verifier or probe_and_verify_credential
        self.remote = remote or RemoteClient(self.sessions.path.with_name('vault_targets.json'))
        self.lock = threading.RLock()
        self.generation = 0

    @contextlib.contextmanager
    def connection(self):
        con = sqlite3.connect(str(self.db), timeout=10)
        try:
            con.execute('PRAGMA secure_delete=ON')
            con.execute('PRAGMA foreign_keys=ON')
            with con: yield con
        finally:
            con.close()

    def probe(self, target='local', origin=None):
        if target == 'cloud':
            if not origin: return {'status': 'needs_server', 'target': 'cloud'}
            try:
                code, value = self.remote(origin, '/lifecycle/probe')
            except LifecycleError:
                return {'status': 'unreachable', 'message': UNREACHABLE}
            if code in (401, 403): return {'status': 'unauthorized'}
            if code != 200 or value.get('status') not in ('exists', 'absent'):
                return {'status': 'incompatible'}
            return {'status': value['status'], 'target': 'cloud'}
        if target != 'local': raise LifecycleError('invalid_target')
        if not self.db.exists(): return {'status': 'absent', 'target': 'local'}
        try:
            with contextlib.closing(sqlite3.connect(self.db.resolve().as_uri() + '?mode=ro', uri=True)) as con:
                tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if not {'credentials', 'meta'} <= tables: return {'status': 'incompatible'}
                account = con.execute("SELECT value FROM meta WHERE key='lifecycle_account'").fetchone()
            return {'status': 'exists', 'target': 'local', 'login_supported': bool(account)}
        except sqlite3.DatabaseError:
            return {'status': 'incompatible'}

    def guide(self, *, intent='start', target=None, origin=None, consent=False, account='', name=''):
        if intent not in ('start', 'switch_account', 'switch_server'):
            raise LifecycleError('invalid_intent')
        if type(consent) is not bool or not isinstance(account, str) or not isinstance(name, str):
            raise LifecycleError('invalid_arguments')
        if target is None and intent == 'start':
            current = self.status()
            if current['status'] == 'ready': return current
        if intent == 'switch_account' and target is None:
            current = self.sessions.load()
            if current:
                target, origin = current['target'], current.get('origin')
        if target is None:
            return {'status': 'needs_target', 'message': '密码库希望保存在本地单机还是云端服务器？'}
        found = self.probe(target, origin)
        if found['status'] not in ('exists', 'absent'): return found
        if found['status'] == 'absent':
            if not consent: return {'status': 'needs_create_consent', 'message': '未发现数据库，是否创建？'}
            mode = 'create'
        else:
            if not consent: return {'status': 'needs_login_consent', 'message': '已发现数据库，是否登录？'}
            mode = 'login'
        return {'status': 'needs_card', 'mode': mode, 'target': target,
                'origin': origin, 'account': account, 'name': name}

    def create(self, account, passphrase, confirm_passphrase, *, consent=False, target='local', origin=None, name=''):
        self._identity(account, passphrase)
        if consent is not True: raise LifecycleError('create_consent_required')
        if not isinstance(name, str) or len(name) > 80: raise LifecycleError('invalid_name')
        if passphrase != confirm_passphrase: raise LifecycleError('passphrase_mismatch')
        if target == 'cloud':
            code, reply = self.remote(origin, '/lifecycle/create', {'account': account,
                'passphrase': passphrase, 'confirm_passphrase': confirm_passphrase, 'consent': True, 'name': name})
            return self._remote_login_result(code, reply, origin, account)
        if target != 'local': raise LifecycleError('invalid_target')
        with self.lock:
            if self.db.exists(): raise LifecycleError('database_exists')
            self.db.parent.mkdir(parents=True, exist_ok=True)
            # Exclusive reservation prevents two create cards overwriting one another.
            fd = os.open(self.db, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
            Store(str(self.db))
            salt = os.urandom(32)
            key = _derive(passphrase, salt, KDF_ITERATIONS)
            nonce = os.urandom(12)
            check = nonce + AESGCM(key).encrypt(nonce, b'vault-lifecycle-key-check', b'lifecycle')
            with self.connection() as con:
                con.executemany('INSERT INTO meta(key,value) VALUES(?,?)', [
                    ('kdf_salt', salt.hex()), ('lifecycle_account', account),
                    ('lifecycle_name', name), ('lifecycle_key_check', check.hex())])
                self._schema(con)
            return self._issue_local(account, key)

    @staticmethod
    def _schema(con):
        con.execute('CREATE TABLE IF NOT EXISTS lifecycle_sessions (token_hash TEXT PRIMARY KEY, '
                    'account TEXT NOT NULL, wrapped_key BLOB NOT NULL)')
        con.execute('CREATE TABLE IF NOT EXISTS lifecycle_validation (connection_id TEXT PRIMARY KEY '
                    'REFERENCES credentials(connection_id) ON DELETE CASCADE, status TEXT NOT NULL)')

    @staticmethod
    def _identity(account, passphrase):
        if not isinstance(account, str) or not account.strip() or len(account) > 80:
            raise LifecycleError('invalid_account')
        if not isinstance(passphrase, str) or not 8 <= len(passphrase) <= 1024:
            raise LifecycleError('invalid_passphrase')

    def login(self, account, passphrase, *, target='local', origin=None):
        self._identity(account, passphrase)
        if target == 'cloud':
            code, reply = self.remote(origin, '/lifecycle/login', {'account': account, 'passphrase': passphrase})
            return self._remote_login_result(code, reply, origin, account)
        if target != 'local': raise LifecycleError('invalid_target')
        if self.probe()['status'] != 'exists': raise LifecycleError('database_unavailable')
        with self.lock, self.connection() as con:
            meta = dict(con.execute('SELECT key,value FROM meta'))
            if 'lifecycle_key_check' not in meta: raise LifecycleError('legacy_database_requires_migration')
            key = _derive(passphrase, bytes.fromhex(meta['kdf_salt']), KDF_ITERATIONS)
            check = bytes.fromhex(meta['lifecycle_key_check'])
            try:
                plain = AESGCM(key).decrypt(check[:12], check[12:], b'lifecycle')
            except InvalidTag:
                raise LifecycleError('invalid_login') from None
            if not hmac.compare_digest(meta['lifecycle_account'].encode(), account.encode()) or plain != b'vault-lifecycle-key-check':
                raise LifecycleError('invalid_login')
        return self._issue_local(account, key)

    def _issue_local(self, account, key):
        token = secrets.token_urlsafe(32)
        token_key = hashlib.sha256(b'wrap:' + token.encode()).digest()
        nonce = os.urandom(12)
        wrapped = nonce + AESGCM(token_key).encrypt(nonce, key, account.encode())
        with self.connection() as con:
            con.execute('INSERT INTO lifecycle_sessions VALUES(?,?,?)', (hashlib.sha256(b'lookup:' + token.encode()).hexdigest(), account, wrapped))
        self.sessions.save({'target': 'local', 'account': account, 'token': token})
        self.generation += 1
        return {'status': 'ready', 'message': INITIALIZED}

    def _remote_login_result(self, code, reply, origin, account):
        if code != 200 or reply.get('status') != 'ready' or not isinstance(reply.get('token'), str) or len(reply['token']) < 32:
            raise LifecycleError('remote_login_failed')
        self.sessions.save({'target': 'cloud', 'origin': origin, 'account': account, 'token': reply['token']})
        self.generation += 1
        return {'status': 'ready', 'message': INITIALIZED}

    def local_key(self, session):
        if not self.db.exists(): raise LifecycleError('session_expired')
        token_key = hashlib.sha256(b'wrap:' + session['token'].encode()).digest()
        with self.connection() as con:
            try:
                row = con.execute('SELECT account,wrapped_key FROM lifecycle_sessions WHERE token_hash=?',
                                  (hashlib.sha256(b'lookup:' + session['token'].encode()).hexdigest(),)).fetchone()
            except sqlite3.OperationalError:
                raise LifecycleError('session_expired') from None
        if not row or row[0] != session['account']: raise LifecycleError('session_expired')
        blob = row[1]
        try:
            return AESGCM(token_key).decrypt(blob[:12], blob[12:], row[0].encode())
        except InvalidTag:
            raise LifecycleError('session_expired') from None

    def status(self):
        session = self.sessions.load()
        if not session: return {'status': 'needs_target'}
        if session['target'] == 'cloud':
            try:
                code, result = self.remote(session['origin'], '/lifecycle/session', token=session['token'])
            except LifecycleError:
                return {'status': 'unreachable', 'message': UNREACHABLE}
            return {'status': 'ready' if code == 200 and result.get('status') == 'ready' else 'needs_login'}
        try:
            self.local_key(session)
            return {'status': 'ready', 'target': 'local', 'account': session['account']}
        except LifecycleError:
            return {'status': 'needs_login'}

    def revoke(self):
        with self.lock:
            session = self.sessions.load()
            if session and session['target'] == 'local' and self.db.exists():
                with self.connection() as con:
                    con.execute('DELETE FROM lifecycle_sessions WHERE token_hash=?',
                                (hashlib.sha256(b'lookup:' + session['token'].encode()).hexdigest(),))
            if self.sessions.path.exists(): self.sessions.path.unlink()
            self.generation += 1
        return {'status': 'needs_login'}

    def session_for_token(self, token):
        if not isinstance(token, str) or len(token) < 32 or not self.db.exists():
            raise LifecycleError('session_expired')
        lookup = hashlib.sha256(b'lookup:' + token.encode()).hexdigest()
        with self.connection() as con:
            row = con.execute('SELECT account FROM lifecycle_sessions WHERE token_hash=?', (lookup,)).fetchone()
        if not row: raise LifecycleError('session_expired')
        session = {'target': 'local', 'account': row[0], 'token': token}
        self.local_key(session)
        return session

    def save_and_verify(self, service, account, secret, *, generation=None, authenticated_session=None):
        if (not isinstance(service, str) or not service.strip() or len(service) > 100
                or not isinstance(account, str) or not account.strip() or len(account) > 80
                or not isinstance(secret, str) or not secret or len(secret) > 65536):
            raise LifecycleError('invalid_credential')
        with self.lock:
            if generation is not None and generation != self.generation: raise LifecycleError('stale_card')
            session = authenticated_session if authenticated_session is not None else self.sessions.load()
            if not session: raise LifecycleError('login_required')
            if session['target'] == 'cloud':
                code, reply = self.remote(session['origin'], '/lifecycle/credentials',
                    {'service': service, 'account': account, 'secret': secret}, token=session['token'])
                if code != 200: raise LifecycleError('remote_save_failed')
                state = reply.get('status')
                messages = {'valid': '凭据验证成功，已安全保存。', 'rejected': '服务拒绝了凭据，已清理本次记录，请重新输入。',
                    'validation_unavailable': '云端暂时无法验证，记录保持待验证状态。',
                    'validation_unsupported': '已加密保存，尚不支持该服务的自动验证。'}
                if state not in messages: raise LifecycleError('invalid_remote_response')
                safe = {'status': state, 'message': messages[state]}
                if state == 'valid': safe['ref'] = self._ref(service, account)
                return safe
            key = self.local_key(session)
            cid = str(uuid.uuid4())
            nonce = os.urandom(12)
            sealed = AESGCM(key).encrypt(nonce, secret.encode(), b'vault-local')
            now = int(time.time())
            with self.connection() as con:
                con.execute('INSERT INTO credentials VALUES(?,?,?,?,?,?,?,?,?)',
                    (cid, service, account, 'password', sealed[:-16], nonce, sealed[-16:], now, now))
                con.execute('INSERT INTO lifecycle_validation VALUES(?,?)', (cid, 'pending_validation'))
        # Network request happens after encrypted INSERT commits, never inside SQLite transaction.
        result = self.verify(service, account, secret)
        state = result['status']
        if state not in ('valid', 'rejected', 'validation_unavailable', 'validation_unsupported'):
            raise LifecycleError('invalid_verification_result')
        with self.lock, self.connection() as con:
            if state == 'rejected':
                con.execute('DELETE FROM credentials WHERE connection_id=?', (cid,))
            else:
                con.execute('UPDATE lifecycle_validation SET status=? WHERE connection_id=?', (state, cid))
        safe = {'status': state, 'message': result['message']}
        if state == 'valid': safe['ref'] = self._ref(service, account)
        return safe

    @staticmethod
    def _ref(service, account):
        return 'vault://' + urllib.parse.quote(service, safe='') + '/' + urllib.parse.quote(account, safe='')
