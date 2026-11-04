"""Read-only, fixed HTTPS authentication probes; no prefix-based success."""
import json
import urllib.request
import urllib.error

ENDPOINTS = {'github': 'https://api.github.com/user', 'github-token': 'https://api.github.com/user',
             'deepseek': 'https://api.deepseek.com/models', 'deepseek-api': 'https://api.deepseek.com/models'}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_auth(url, secret):
    req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + secret,
        'Accept': 'application/json', 'User-Agent': 'Local-Vault-Check/1.0'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(req, timeout=8) as response:
            raw = response.read(65537)
            if len(raw) > 65536: return 502, None
            try: return response.status, json.loads(raw)
            except ValueError: return 502, None
    except urllib.error.HTTPError as error:
        code = error.code
        error.close()
        return code, None

def probe_and_verify_credential(service, account, secret, *, transport=None):
    """Injected transports are for tests, never accepted from tool arguments."""
    url = ENDPOINTS.get(service.lower())
    if url is None:
        return {'status': 'validation_unsupported', 'valid': False, 'should_purge': False,
                'message': '已加密保存，尚不支持该服务的自动验证。'}
    if not isinstance(secret, str) or not secret or any(ord(c) < 33 or ord(c) > 126 for c in secret):
        return {'status': 'rejected', 'valid': False, 'should_purge': True,
                'message': '凭据格式无效，已清理本次记录，请重新输入。'}
    try:
        code, body = (transport or request_auth)(url, secret)
    except (OSError, TimeoutError, urllib.error.URLError):
        code, body = 503, None
    if code == 401:
        return {'status': 'rejected', 'valid': False, 'should_purge': True,
                'message': '服务拒绝了此凭据，已清理本次记录，请重新输入。'}
    shape = False
    if isinstance(body, dict):
        if 'github' in service.lower():
            shape = type(body.get('id')) is int and isinstance(body.get('login'), str) and bool(body['login'])
        else:
            shape = isinstance(body.get('data'), list) and body.get('object') == 'list'
    if code == 200 and shape:
        return {'status': 'valid', 'valid': True, 'should_purge': False,
                'message': '凭据验证成功，已安全保存。'}
    return {'status': 'validation_unavailable', 'valid': False, 'should_purge': False,
            'message': '暂时无法验证（网络、权限或服务限制），凭据保持待验证状态。'}


