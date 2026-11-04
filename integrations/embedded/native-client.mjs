import {readFile} from 'node:fs/promises';

// Native host process only. Never expose this object or its discovery file to renderer IPC.
export async function connectEmbeddedBroker(discoveryFile) {
  const config = JSON.parse(await readFile(discoveryFile, 'utf8'));
  const origin = new URL(config.origin);
  if (origin.protocol !== 'http:' || origin.hostname !== '127.0.0.1' || origin.pathname !== '/' || origin.username || origin.password ||
      typeof config.token !== 'string' || config.token.length < 32) throw new Error('Invalid local broker discovery');
  async function request(path, body) {
    const response = await fetch(new URL(path, origin), {
      method: body === undefined ? 'GET' : 'POST', redirect: 'error',
      signal: AbortSignal.timeout(5000),
      headers: {Authorization: `Bearer ${config.token}`, 'Content-Type': 'application/json'},
      ...(body === undefined ? {} : {body: JSON.stringify(body)})
    });
    if (!response.ok) throw new Error('Embedded broker request failed');
    return response.json();
  }
  return Object.freeze({
    // Return only host-specific metadata; call from a trusted preload, not model messages.
    pending: () => request('/host/requests'),
    create: ({service, account, prompt, timeout_s = 120}) => request('/requests', {service, account, prompt, timeout_s}),
    result: id => request(`/requests/${encodeURIComponent(id)}`)
  });
}
