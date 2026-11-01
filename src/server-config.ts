export interface NetworkOptions { publicOrigin?: string; allowedOrigin?: string; bindHost?: string; diagnoseProxyHeaders?: boolean; trustedProxy?: 'loopback' }

// Exact socket representations only; no hostname, forwarded IP or 127/8 inference.
export const isLoopbackPeer = (peer: string | undefined) => peer === '127.0.0.1' || peer === '::ffff:127.0.0.1' || peer === '::ffff:7f00:1';

export function requestHostAllowed(rawHeaders: readonly string[], peer: string | undefined, publicOrigin: string, executionOrigin: string, trustedProxy: boolean, execution: boolean): boolean {
  const values = (name: string) => {
    const result: string[] = [];
    for (let i = 0; i < rawHeaders.length; i += 2) if (rawHeaders[i]?.toLowerCase() === name) result.push(rawHeaders[i + 1] ?? '');
    return result;
  };
  const hosts = values('host'), forwardedHosts = values('x-forwarded-host'), forwardedProtos = values('x-forwarded-proto');
  if (hosts.length !== 1) return false;
  const localHost = new URL(executionOrigin).host;
  if (execution) return hosts[0] === localHost && isLoopbackPeer(peer) && forwardedHosts.length === 0 && forwardedProtos.length === 0;
  const publicHost = new URL(publicOrigin).host;
  if (!trustedProxy) return hosts[0] === publicHost;
  // A second forwarding dialect is ambiguous; the supported gateway uses only these two fields.
  if (values('forwarded').length !== 0) return false;
  const hasForwarding = forwardedHosts.length !== 0 || forwardedProtos.length !== 0;
  if (!hasForwarding) return hosts[0] === publicHost;
  return isLoopbackPeer(peer) && (hosts[0] === localHost || hosts[0] === publicHost)
    && forwardedHosts.length === 1 && forwardedHosts[0] === publicHost
    && forwardedProtos.length === 1 && forwardedProtos[0] === 'https';
}

export function validateNetworkOptions(options: NetworkOptions) {
  if (options.diagnoseProxyHeaders !== undefined && typeof options.diagnoseProxyHeaders !== 'boolean') throw new Error('Invalid proxy diagnostic option');
  if (options.publicOrigin !== undefined && options.allowedOrigin !== undefined) throw new Error('Use only one public origin option');
  const publicOrigin = options.publicOrigin ?? options.allowedOrigin;
  if (publicOrigin !== undefined) {
    let url: URL;
    try { url = new URL(publicOrigin); } catch { throw new Error('Invalid public origin'); }
    if (url.origin !== publicOrigin || url.username || url.password || url.pathname !== '/' || url.search || url.hash
      || /[\s*,\\]/.test(publicOrigin) || !url.hostname || url.hostname.endsWith('.')
      || (url.protocol !== 'https:' && !(url.protocol === 'http:' && url.hostname === '127.0.0.1' && url.port))) {
      throw new Error('Public origin requires one exact canonical HTTPS origin (or explicit 127.0.0.1 HTTP origin)');
    }
  }
  if (options.trustedProxy !== undefined && options.trustedProxy !== 'loopback') throw new Error('Invalid trusted proxy option');
  if (options.trustedProxy && !publicOrigin?.startsWith('https://')) throw new Error('Trusted proxy requires a configured HTTPS public origin');
  // Both supported binds keep the standard 127.0.0.1 stdio bridge reachable.
  const bindHost = options.bindHost ?? '127.0.0.1';
  if (!['127.0.0.1', '0.0.0.0'].includes(bindHost)) throw new Error('Bind host must be 127.0.0.1 or 0.0.0.0');
  if (bindHost !== '127.0.0.1' && !publicOrigin?.startsWith('https://')) throw new Error('Nonloopback binding requires an HTTPS public origin');
  return { publicOrigin, bindHost, trustedProxy: options.trustedProxy, secureCookies: publicOrigin?.startsWith('https://') === true, diagnoseProxyHeaders: options.diagnoseProxyHeaders === true };
}
