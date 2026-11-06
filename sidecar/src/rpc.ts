import { FetchRequest } from 'ethers';
import { SocksProxyAgent } from 'socks-proxy-agent';

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
