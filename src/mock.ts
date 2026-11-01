import http from 'node:http';
import { createHash } from 'node:crypto';

export function startMock() {
  let hits = 0;
  const server = http.createServer((request, response) => {
    if (request.method !== 'GET' || request.url !== '/v1/account/summary') {
      response.writeHead(404).end();
      return;
    }
    const token = request.headers.authorization?.replace(/^Bearer /, '') ?? '';
    if (!/^synthetic_[A-Za-z0-9_-]{6,502}$/.test(token)) {
      response.writeHead(401).end();
      return;
    }
    hits++;
    if (token.startsWith('synthetic_redirect')) {
      response.writeHead(302, { location: 'http://127.0.0.1:43121/redirect-target' }).end();
      return;
    }
    if (token.startsWith('synthetic_timeout')) return;
    response.setHeader('content-type', 'application/json');
    if (token.startsWith('synthetic_oversize')) { response.end(JSON.stringify({ data: 'x'.repeat(40000) })); return; }
    const fingerprint = createHash('sha256').update(token).digest('hex').slice(0, 16);
    response.end(JSON.stringify({
      account: { id: `mock-${fingerprint}`, name: `Synthetic account ${token}`, [token]: token, ignored: token },
      plan: 'test',
      notices: [{ message: `Nested reflection: ${token}`, [token]: token }],
      ignored: { token, [token]: [token] },
      hits,
    }));
  });
  const observable = Object.assign(server, { getHits: () => hits });
  return new Promise<http.Server & { getHits(): number }>((resolve, reject) => {
    server.once('error', reject);
    server.listen(43121, '127.0.0.1', () => resolve(observable));
  });
}
