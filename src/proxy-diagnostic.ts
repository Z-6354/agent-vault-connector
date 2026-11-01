// Deliberately accepts only raw header pairs and the socket peer, never a request/logger object.
export function proxyHeaderDiagnostic(rawHeaders: readonly string[], peer: string | undefined): string {
  const clean = (value: string) => value.slice(0, 256).replace(/[^\x20-\x7e]/g, '?');
  const host: string[] = [], origin: string[] = [], forwardedHost: string[] = [], forwardedProto: string[] = [];
  let hostCount = 0;
  for (let i = 0; i < rawHeaders.length; i += 2) {
    const name = rawHeaders[i]?.toLowerCase();
    if (name === 'host') hostCount++;
    const values = name === 'host' ? host : name === 'origin' ? origin : name === 'x-forwarded-host' ? forwardedHost : name === 'x-forwarded-proto' ? forwardedProto : undefined;
    if (values && values.length < 8) values.push(clean(rawHeaders[i + 1] ?? ''));
  }
  return JSON.stringify({ event: 'host_denied', host_count: hostCount, host_values: host, origin, x_forwarded_host: forwardedHost, x_forwarded_proto: forwardedProto, peer: peer === undefined ? null : clean(peer) }) + '\n';
}
