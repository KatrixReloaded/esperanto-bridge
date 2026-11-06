import { createServer as nodeCreateServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomBytes } from 'node:crypto';
import { EvmError, MAX_EVM_BODY, type EvmClient } from './evm.ts';
import { getAddress, ZeroAddress } from 'ethers';
import { SdkError, type SdkAdapter, type PreparedPermit, type DecryptionWidth } from './sdk.ts';

const MAX_BODY = 16 * 1024;
const MAX_UINT64 = (1n << 64n) - 1n;
type Session = { contract: string; user: string; handle: string; width: DecryptionWidth; expires: number; permit: PreparedPermit };
class HttpError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, status: number) { super(code); this.code = code; this.status = status; }
}
function fail(code: string, status = 400): never { throw new HttpError(code, status); }
function bound(value: number | undefined, maximum: number): number {
  if (value === undefined) return maximum;
  if (!Number.isInteger(value) || value < 1 || value > maximum) throw new RangeError('invalid_server_option');
  return value;
}
function address(value: unknown): string {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value)) return fail('invalid_address');
  try { const result = getAddress(value); if (result === ZeroAddress) return fail('invalid_address'); return result; }
  catch { return fail('invalid_address'); }
}
function handle(value: unknown): string {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(value) || /^0x0{64}$/.test(value)) return fail('invalid_handle');
  return value.toLowerCase();
}
function width(value: unknown): DecryptionWidth {
  if (value !== 'uint64' && value !== 'uint256') return fail('invalid_width');
  return value;
}
function fields(body: Record<string, unknown>, names: string[]) {
  if (Object.keys(body).length !== names.length || names.some(name => !Object.hasOwn(body, name))) fail('invalid_request');
}
function send(response: ServerResponse, status: number, body: unknown) {
  if (response.destroyed) return;
  response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', 'connection': 'close', 'x-content-type-options': 'nosniff' });
  response.end(JSON.stringify(body));
}
async function readBody(request: IncomingMessage, maximum = MAX_BODY): Promise<Record<string, unknown>> {
  const bytes = await new Promise<Buffer>((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    const cleanup = () => {
      request.off('data', onData);
      request.off('end', onEnd);
      request.off('error', onError);
      request.off('aborted', onAborted);
    };
    const onError = () => { cleanup(); reject(new HttpError('invalid_request', 400)); };
    const onAborted = () => onError();
    const onData = (chunk: Buffer) => {
      size += chunk.length;
      if (size > maximum) {
        cleanup();
        request.pause();
        reject(new HttpError('body_too_large', 413));
      } else chunks.push(chunk);
    };
    const onEnd = () => { cleanup(); resolve(Buffer.concat(chunks)); };
    request.on('data', onData);
    request.once('end', onEnd);
    request.once('error', onError);
    request.once('aborted', onAborted);
  });
  let body: unknown;
  try { body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { return fail('invalid_json'); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return fail('invalid_request');
  return body as Record<string, unknown>;
}
const sdkErrors: Record<string, number> = {
  invalid_signature: 400, signature_user_mismatch: 403, sdk_acl_denied: 403,
  encrypt_failed: 502, permit_failed: 502, decrypt_failed: 502,
};

/** Single-operation, bounded ephemeral service; the caller must bind to loopback. */
export function createServer(sdk: SdkAdapter, options: { sessionTtlMs?: number; maxSessions?: number; operationTimeoutMs?: number; evm?: EvmClient } = {}) {
  const ttl = bound(options.sessionTtlMs, 300_000);
  const capacity = bound(options.maxSessions, 64);
  const timeout = bound(options.operationTimeoutMs, 120_000);
  const sessions = new Map<string, Session>();
  let busy = false;
  let unavailable = false;
  let closed = false;
  const cleanup = () => { const now = Date.now(); for (const [id, session] of sessions) if (session.expires <= now) sessions.delete(id); };
  const timer = setInterval(cleanup, Math.min(ttl, 30_000));
  timer.unref();
  async function operation<T>(route: string, run: () => Promise<T>): Promise<T> {
    let deadline: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([Promise.resolve().then(run), new Promise<never>((_, reject) => {
        deadline = setTimeout(() => {
          unavailable = true;
          sessions.clear();
          try { sdk.dispose(); } catch { /* Never expose disposal diagnostics. */ }
          reject(new HttpError('operation_timeout', 504));
          // Startup terminates the dedicated process after the response flushes.
          // Disposal alone cannot release a hung SDK operation's key references.
          server.emit('sdkTimeout', route);
        }, timeout);
      })]);
    } finally { clearTimeout(deadline); }
  }
  const server = nodeCreateServer({ maxHeaderSize: 8192 }, (request, response) => {
    request.on('error', () => {});
    void (async () => {
      const peer = request.socket.remoteAddress ?? '';
      if (!(peer === '::1' || /^(?:::ffff:)?127(?:\.\d{1,3}){3}$/.test(peer)) ||
          !/^127\.0\.0\.1(?::\d{1,5})?$/.test(request.headers.host ?? '')) fail('invalid_host', 403);
      if (request.headers.origin !== undefined) fail('origin_forbidden', 403);
      if (request.method !== 'POST') fail('method_not_allowed', 405);
      const evmRoute = ['/evm/read', '/evm/send', '/evm/receipt'].includes(request.url ?? '');
      if (!['/encrypt', '/encrypt-redemption', '/decrypt-request', '/decrypt'].includes(request.url ?? '') && !(evmRoute && options.evm)) fail('not_found', 404);
      const bodyLimit = evmRoute ? MAX_EVM_BODY : MAX_BODY;
      if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers['content-type'] ?? '')) fail('unsupported_media_type', 415);
      const length = request.headers['content-length'];
      if (length && (!/^\d+$/.test(length) || BigInt(length) > BigInt(bodyLimit))) fail('body_too_large', 413);
      const body = await readBody(request, bodyLimit);
      if (unavailable || closed) fail('sdk_unavailable', 503);
      if (busy) fail('busy', 503);
      cleanup();
      // Consume a known session on every decrypt attempt, including malformed scope/signature.
      let session: Session | undefined;
      if (request.url === '/decrypt' && typeof body.sessionId === 'string') {
        session = sessions.get(body.sessionId);
        sessions.delete(body.sessionId);
      }
      busy = true;
      try {
        if (evmRoute) {
          send(response, 200, await options.evm!.handle(request.url!, body));
        } else if (request.url === '/encrypt') {
          fields(body, ['contract', 'user', 'value']);
          const contract = address(body.contract), user = address(body.user);
          if (typeof body.value !== 'string' || !/^(0|[1-9]\d{0,19})$/.test(body.value) || BigInt(body.value) > MAX_UINT64) fail('invalid_uint64');
          const result = await operation('/encrypt', () => sdk.encrypt(contract, user, BigInt(body.value as string)));
          send(response, 200, { handle: result.handle, inputProof: result.inputProof });
        } else if (request.url === '/encrypt-redemption') {
          fields(body, ['contract', 'user', 'amount', 'destination']);
          const contract = address(body.contract), user = address(body.user);
          if (typeof body.amount !== 'string' || !/^(0|[1-9]\d{0,19})$/.test(body.amount) || BigInt(body.amount) > MAX_UINT64) fail('invalid_uint64');
          if (!Array.isArray(body.destination) || body.destination.length !== 3 || body.destination.some(v => typeof v !== 'string' || !/^(0|[1-9]\d{0,77})$/.test(v) || BigInt(v) >= (1n << 256n))) fail('invalid_uint256');
          const destination = body.destination.map(v => BigInt(v)) as [bigint, bigint, bigint];
          const result = await operation('/encrypt-redemption', () => sdk.encryptRedemption(contract, user, BigInt(body.amount as string), destination));
          send(response, 200, result);
        } else if (request.url === '/decrypt-request') {
          fields(body, ['contract', 'user', 'handle', 'width']);
          const requestedWidth = width(body.width);
          const contract = address(body.contract), user = address(body.user), ciphertext = handle(body.handle);
          if (contract === user) fail('invalid_user');
          if (sessions.size >= capacity) fail('session_capacity', 503);
          const permit = await operation('/decrypt-request', () => sdk.prepare(contract, user));
          if (closed) fail('sdk_unavailable', 503);
          const sessionId = randomBytes(32).toString('hex');
          const expires = Date.now() + ttl;
          sessions.set(sessionId, { contract, user, handle: ciphertext, width: requestedWidth, expires, permit });
          send(response, 200, { sessionId, contract, user, handle: ciphertext, width: requestedWidth, expiresAt: String(expires),
            publicKey: permit.publicKey, startTimestamp: permit.startTimestamp, typedData: permit.eip712, digest: permit.digest });
        } else {
          if (typeof body.sessionId !== 'string' || !/^[0-9a-f]{64}$/.test(body.sessionId)) fail('invalid_session');
          if (!session) fail('session_unavailable', 410);
          fields(body, ['sessionId', 'contract', 'user', 'handle', 'width', 'signature']);
          const requestedWidth = width(body.width);
          const contract = address(body.contract), user = address(body.user), ciphertext = handle(body.handle);
          if (session.contract !== contract || session.user !== user || session.handle !== ciphertext || session.width !== requestedWidth) fail('session_scope_mismatch', 403);
          if (typeof body.signature !== 'string' || !/^0x[0-9a-fA-F]{130}$/.test(body.signature)) fail('invalid_signature');
          const signature = body.signature;
          const activeSession = session;
          const value = await operation('/decrypt', () => sdk.decrypt({ contract, user, handle: ciphertext, width: requestedWidth,
            keypair: activeSession.permit.keypair, eip712: activeSession.permit.eip712 }, signature));
          if (typeof value !== 'bigint' || value < 0n || value >= (1n << BigInt(requestedWidth === 'uint64' ? 64 : 256))) fail('decrypt_failed', 502);
          send(response, 200, { width: requestedWidth, value: value.toString() });
        }
      } finally { busy = false; }
    })().catch((error: unknown) => {
      if (error instanceof EvmError) send(response, error.status, { error: { code: error.code } });
      else if (error instanceof HttpError) send(response, error.status, { error: { code: error.code } });
      else if (error instanceof SdkError && Object.hasOwn(sdkErrors, error.code)) send(response, sdkErrors[error.code]!, { error: { code: error.code } });
      else send(response, 502, { error: { code: 'sdk_failed' } });
    });
  });
  server.maxConnections = 64;
  server.headersTimeout = 10_000;
  server.requestTimeout = 15_000;
  server.timeout = timeout + 15_000;
  server.keepAliveTimeout = 1_000;
  server.maxRequestsPerSocket = 1;
  server.on('close', () => { closed = true; sessions.clear(); clearInterval(timer); });
  return server;
}
