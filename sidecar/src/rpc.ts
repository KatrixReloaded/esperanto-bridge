import { FetchRequest } from 'ethers';
import { SocksProxyAgent } from 'socks-proxy-agent';

// Only transport failures and explicitly transient HTTP statuses are retryable.
export class RetryableRpcError extends Error {}
export function retryableHttpStatus(url: URL, status: number | undefined): boolean {
  return status === 429 || status === 502 || status === 503 || status === 504 ||
    (status === 404 && url.href === 'https://1rpc.io/sepolia');
}

/** Ethereum RPC uses only the enclave-local Nym SOCKS listener; DNS occurs at the exit. */
export function rpcRequest(rpcUrl: string, proxyPort = 1080): FetchRequest {
  const url = new URL(rpcUrl);
  if (url.protocol !== 'https:' || url.username || url.password) throw new Error('invalid_rpc_url');
  const request = new FetchRequest(url.href);
  request.timeout = 120_000;
  const agent = new SocksProxyAgent(`socks5h://127.0.0.1:${proxyPort}`, { timeout: 120_000 });
  request.getUrlFunc = FetchRequest.createGetUrlFunc({ agent });
  return request;
}

/** One bounded JSON-RPC HTTP attempt over the same Nym SOCKS route. No redirects or retries. */
export async function rpcJson(rpcUrl: string, payload: unknown, options: { proxyPort?: number; timeoutMs?: number } = {}): Promise<unknown> {
  const { request } = await import('node:https');
  const url = new URL(rpcUrl);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw new Error('invalid_rpc_url');
  const proxyPort = options.proxyPort ?? 1080, timeout = options.timeoutMs ?? 120_000;
  if (!Number.isInteger(proxyPort) || proxyPort < 1 || proxyPort > 65535 || !Number.isInteger(timeout) || timeout < 1 || timeout > 120_000) throw new Error('invalid_rpc_option');
  const body = Buffer.from(JSON.stringify(payload));
  if (body.length > 512 * 1024) throw new Error('rpc_request_too_large');
  const agent = new SocksProxyAgent(`socks5h://127.0.0.1:${proxyPort}`, { timeout });
  return new Promise((resolve, reject) => {
    let settled = false;
    const req = request(url, { method: 'POST', agent, maxHeaderSize: 8192, headers: {
      'content-type': 'application/json', 'accept': 'application/json', 'accept-encoding': 'identity',
      'content-length': String(body.length), 'connection': 'close',
    } });
    const finish = (error?: Error, value?: unknown) => {
      if (settled) return;
      settled = true; clearTimeout(deadline); req.destroy(); agent.destroy();
      if (error) reject(error); else resolve(value);
    };
    const deadline = setTimeout(() => finish(new RetryableRpcError('rpc_timeout')), timeout);
    req.on('error', () => finish(new RetryableRpcError('rpc_transport_failed')));
    req.once('response', response => {
      if (retryableHttpStatus(url, response.statusCode)) {
        response.destroy(); finish(new RetryableRpcError('rpc_http_transient')); return;
      }
      if (response.statusCode !== 200 || (response.headers['content-encoding'] && response.headers['content-encoding'] !== 'identity') ||
          !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers['content-type'] ?? '')) {
        response.destroy(); finish(new Error('rpc_response_rejected')); return;
      }
      let size = 0;
      const chunks: Buffer[] = [];
      response.on('error', () => finish(new RetryableRpcError('rpc_transport_failed')));
      response.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > 1024 * 1024) { response.destroy(); finish(new Error('rpc_response_too_large')); }
        else chunks.push(chunk);
      });
      response.on('end', () => {
        try { finish(undefined, JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)))); }
        catch { finish(new Error('rpc_response_rejected')); }
      });
    });
    req.end(body);
  });
}
