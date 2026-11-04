"""Local-storage credential card broker (protocol-compatible with broker.py).

Loaded as the broker's request-aware save callback; HTTP/admin/card transport stays
unchanged. Requires a running local Vault management server already authenticated and
unlocked (S2). Secrets and passphrases never enter MCP stdio, logs or tool results.
"""
import json
import os
from pathlib import Path
import tempfile

try:
    from .local_backend import LocalBackend, LocalBackendError
except ImportError:
    from local_backend import LocalBackend, LocalBackendError

HOST='127.0.0.1'

def _env_path():
    return Path(os.environ.get('VAULT_MANAGEMENT_ENV_FILE') or str(Path(tempfile.gettempdir()) / 'agent-vault-management.env'))

def _config():
    try:
        config=json.loads(_env_path().read_text(encoding='utf8'))
        origin=config['origin'];token=config['token']
    except (OSError, ValueError, KeyError):
        return None
    if not isinstance(origin,str) or not origin.startswith('http://'+HOST+':') or not isinstance(token,str) or not token:
        return None
    return origin.rstrip('/'),token

class LocalStoreAdapter:
    """Save callback for a local Vault that is already authenticated and unlocked (S2)."""
    def __init__(self, backend=None):
        self.backend=backend if backend is not None else LocalBackend()
    def location(self):
        return 'local'
    def _unlocked(self):
        status,value=self.backend.request('/management/session')
        return status==200 and value.get('state')=='S2' and value.get('authenticated') is True
    def save(self, metadata, secret, remaining, request_id=None):
        # The local Vault must already be unlocked via its own management surface
        # (the tray panel). A locked vault is surfaced as an error, never bypassed.
        if not self._unlocked():
            raise LocalBackendError('vault_locked')
        try:
            _,connection_id=self.backend.save(metadata['service'],metadata['account'],secret)
        finally:
            secret=''
        # Return the connection UUID, matching save_to_vault's contract; the broker
        # derives the vault:// reference from service/account itself.
        return connection_id

def make_local_save_callback():
    adapter=LocalStoreAdapter()
    return adapter.save,adapter
