"""MCP Apps entrypoint for the next-gen lifecycle controller (no secret tools)."""
import json
import os
from pathlib import Path
import sys
import urllib.request
import uuid

from lifecycle_core import SessionFile
from mcp_apps import Gateway, MIME, EXTENSION

RESOURCE = 'ui://agent-vault/lifecycle'

class LifecycleGateway(Gateway):
    def __init__(self, filename):
        # Reuse the tested gateway origin validation without writing a plaintext token file.
        config = SessionFile(filename).load()
        if not isinstance(config, dict): raise ValueError('invalid_controller')
        from urllib.parse import urlsplit
        origin = urlsplit(config['origin'])
        if (origin.scheme != 'http' or origin.hostname != '127.0.0.1' or not origin.port
                or origin.path or origin.query or origin.fragment or origin.username or origin.password
                or not isinstance(config['token'], str) or len(config['token']) < 32):
            raise ValueError('invalid_controller')
        self.origin, self.token = config['origin'], config['token']
        from mcp_apps import NoRedirect
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


class LifecycleApps:
    def __init__(self, gateway):
        self.gateway = gateway
        self.initialized = False
        self.ui = False

    def call(self, message):
        if not isinstance(message, dict) or message.get('jsonrpc') != '2.0':
            return {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32600, 'message': 'Invalid request'}}
        identifier = message.get('id')
        if type(identifier) not in (str, int, type(None)):
            return {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32600, 'message': 'Invalid request'}}
        if 'id' not in message: return None
        def reply(result): return {'jsonrpc': '2.0', 'id': identifier, 'result': result}
        def error(code, text): return {'jsonrpc': '2.0', 'id': identifier, 'error': {'code': code, 'message': text}}
        method, params = message.get('method'), message.get('params', {})
        if not isinstance(params, dict): return error(-32602, 'Invalid params')
        if method == 'initialize':
            caps = params.get('capabilities', {}).get('extensions', {}).get(EXTENSION, {})
            self.ui = MIME in caps.get('mimeTypes', [])
            self.initialized = True
            return reply({'protocolVersion': '2026-01-26', 'serverInfo': {'name': 'vault-lifecycle', 'version': '0.3.0'},
                'capabilities': {'tools': {}, 'resources': {}, 'extensions': {EXTENSION: {'mimeTypes': [MIME]}}}})
        if not self.initialized: return error(-32002, 'Not initialized')
        if method == 'ping': return reply({})
        if method == 'tools/list':
            def schema(properties): return {'type': 'object', 'properties': properties, 'additionalProperties': False}
            string = {'type': 'string'}
            tools = [
                {'name': 'vault_guide', 'description': 'Guide local/cloud initialization or re-login. Never pass passwords. Ask for consent before create/login.',
                 'inputSchema': schema({'intent': {'enum': ['start', 'switch_account', 'switch_server']},
                    'target': {'enum': ['local', 'cloud']}, 'origin': string, 'consent': {'type': 'boolean'}, 'account': string, 'name': string}),
                 '_meta': {'ui': {'resourceUri': RESOURCE, 'visibility': ['model']}}},
                {'name': 'vault_credential', 'description': 'Request masked credential entry after initialization. Do not pass a secret.',
                 'inputSchema': schema({'service': string, 'account': string}),
                 '_meta': {'ui': {'resourceUri': RESOURCE, 'visibility': ['model']}}},
                {'name': 'vault_lifecycle_result', 'description': 'Read redacted completion state only.',
                 'inputSchema': schema({'request_id': string})},
                {'name': 'vault_lifecycle_frame', 'description': 'App-only inline frame capability.',
                 'inputSchema': schema({'request_id': string}), '_meta': {'ui': {'visibility': ['app']}}},
            ]
            return reply({'tools': tools})
        if method in ('resources/list', 'resources/read'):
            item = {'uri': RESOURCE, 'name': 'Vault lifecycle', 'mimeType': MIME,
                    '_meta': {'ui': {'csp': {'frameDomains': [self.gateway.origin], 'connectDomains': [], 'resourceDomains': []}}}}
            if method == 'resources/list': return reply({'resources': [item]})
            if params.get('uri') != RESOURCE: return error(-32602, 'Unknown resource')
            item['text'] = Path(__file__).with_name('web').joinpath('lifecycle-app.html').read_text(encoding='utf8')
            return reply({'contents': [item]})
        if method != 'tools/call': return error(-32601, 'Unknown method')
        name, args = params.get('name'), params.get('arguments', {})
        if not isinstance(args, dict): return error(-32602, 'Invalid arguments')
        try:
            if name in ('vault_guide', 'vault_credential'):
                if not self.ui: return error(-32602, 'Inline UI required; never enter secrets in chat')
                allowed = ({'intent', 'target', 'origin', 'consent', 'account', 'name'} if name == 'vault_guide'
                           else {'service', 'account'})
                if set(args) - allowed: return error(-32602, 'Secret or unknown arguments forbidden')
                result = self.gateway.request('/lifecycle/guide' if name == 'vault_guide' else '/lifecycle/credential', args)
            elif name in ('vault_lifecycle_result', 'vault_lifecycle_frame'):
                if set(args) != {'request_id'}: return error(-32602, 'Invalid arguments')
                identifier_arg = str(uuid.UUID(args['request_id']))
                result = self.gateway.request(('/lifecycle/frame/' if name.endswith('_frame') else '/lifecycle/result/') + identifier_arg)
                if name.endswith('_frame'):
                    from urllib.parse import urlsplit
                    url = urlsplit(result.get('frame_url', ''))
                    if (url.scheme + '://' + url.netloc != self.gateway.origin or not url.path.startswith('/lifecycle/card/')
                            or url.query or url.fragment): raise ValueError('invalid_frame')
            else: return error(-32602, 'Unknown tool')
            return reply({'content': [{'type': 'text', 'text': json.dumps({'request_id': result['request_id']})
                                      if name == 'vault_lifecycle_frame' else json.dumps(result, ensure_ascii=False)}],
                          'structuredContent': result})
        except (OSError, ValueError, KeyError):
            return reply({'isError': True, 'content': [{'type': 'text', 'text': 'Local lifecycle service unavailable; do not enter secrets in chat.'}]})


def main():
    try:
        app = LifecycleApps(LifecycleGateway(os.environ.get('VAULT_LIFECYCLE_DISCOVERY',
            str(Path.home() / '.hermes/vault-lifecycle.json'))))
    except (OSError, ValueError, KeyError):
        print('Lifecycle controller discovery unavailable.', file=sys.stderr)
        return 1
    sys.stdin.reconfigure(encoding='utf8')
    sys.stdout.reconfigure(encoding='utf8', line_buffering=True)
    for line in sys.stdin:
        try:
            request = json.loads(line)
            response = app.call(request)
        except (ValueError, TypeError, AttributeError):
            response = {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32600, 'message': 'Invalid request'}}
        if response is not None: print(json.dumps(response, ensure_ascii=False))
    return 0

if __name__ == '__main__': raise SystemExit(main())
