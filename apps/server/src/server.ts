import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomUUID } from 'node:crypto'
import { isIP } from 'node:net'
import { z } from 'zod'
import { deviceRegistrationRequestSchema, deviceRefreshRequestSchema, parseWireJson } from '@dsh-remote/protocol'
import { ApiError, Store, equal, hash, secret } from './store.js'
import { Gateway, peerKey } from './gateway.js'
import { buildIceServers, parseIceConfig, type IceConfig } from './ice.js'
import { Logger, type LogLevel } from './logger.js'
import {
  FORCE_TERMINATE_GRACE_MS_RANGE,
  HEARTBEAT_DISCONNECT_MS_MAX,
  HELLO_TIMEOUT_MS_RANGE,
  HEARTBEAT_INTERVAL_MS_RANGE,
  MAX_FRAMES_PER_SEC_RANGE,
  normalizeForceTerminateGraceMs,
  normalizeGatewayOptions,
  normalizeHeartbeatDisconnectMs,
  normalizeHeartbeatIntervalMs,
  normalizeHelloTimeoutMs,
  normalizeMaxFramesPerSec,
} from './config.js'

export interface Config {
  account: string
  password: string
  /** Invite code for POST /api/v1/auth/register. Omit or leave empty to keep registration closed. */
  registrationCode?: string
  dataFile: string
  publicUrl: string
  trustedProxyIps?: readonly string[]
  helloTimeoutMs?: number
  heartbeatIntervalMs?: number
  heartbeatDisconnectMs?: number
  forceTerminateGraceMs?: number
  maxFramesPerSec?: number
  /** Bytes of queued relay to one peer before the sender is paused. */
  relayQueueSoftBytes?: number
  /** Bytes of queued relay to one peer that a sender pulse will not pass. */
  relayQueueHardBytes?: number
  logLevel?: LogLevel
  ice?: IceConfig
}

/**
 * Timing configuration is normalized in one place (`config.ts`) so the CLI and
 * programmatic callers share the same bounds and fallbacks. These wrappers keep
 * the env-var parsing API used by `main.ts` and the tests, and never echo the
 * offending input in their warnings.
 */
export function parseHelloTimeout(val: string | undefined): number {
  return normalizeHelloTimeoutMs(val)
}

export function parseHeartbeatInterval(val: string | undefined): number {
  return normalizeHeartbeatIntervalMs(val)
}

export function parseHeartbeatDisconnect(val: string | undefined, heartbeatIntervalMs: number = HEARTBEAT_INTERVAL_MS_RANGE.fallback): number {
  return normalizeHeartbeatDisconnectMs(val, heartbeatIntervalMs)
}

export function parseForceTerminateGrace(val: string | undefined): number {
  return normalizeForceTerminateGraceMs(val)
}

export function parseMaxFramesPerSec(val: string | undefined): number {
  return normalizeMaxFramesPerSec(val)
}

export {
  normalizeGatewayOptions,
  normalizeHelloTimeoutMs,
  normalizeHeartbeatIntervalMs,
  normalizeHeartbeatDisconnectMs,
  normalizeForceTerminateGraceMs,
  normalizeMaxFramesPerSec,
  HELLO_TIMEOUT_MS_RANGE,
  HEARTBEAT_INTERVAL_MS_RANGE,
  HEARTBEAT_DISCONNECT_MS_MAX,
  FORCE_TERMINATE_GRACE_MS_RANGE,
  MAX_FRAMES_PER_SEC_RANGE,
}
export type { GatewayTimingOptions, NormalizedGatewayOptions } from './config.js'

const loginSchema = z.object({ email: z.string().min(1).max(254), password: z.string().min(1).max(1024) }).strict()
const registerSchema = loginSchema.extend({ code: z.string().min(1).max(256) }).strict()
const MAX_SESSIONS = 4096
const MAX_SESSIONS_PER_ACCOUNT = 64
const publicDir = fileURLToPath(new URL('../dist/public/', import.meta.url))
function readAssets(): Map<string, Buffer> {
  if (!existsSync(publicDir)) return new Map()
  const assets = new Map<string, Buffer>()
  for (const entry of readdirSync(publicDir, { recursive: true, withFileTypes: true })) {
    if (!entry.isFile()) continue
    const file = join(entry.parentPath, entry.name)
    const path = file.slice(publicDir.length).replaceAll('\\', '/')
    assets.set(path, readFileSync(file))
  }
  return assets
}
async function body(req: IncomingMessage): Promise<unknown> {
  if (!req.headers['content-type']?.toLowerCase().startsWith('application/json')) throw new ApiError('INVALID_MESSAGE', 415)
  let length = 0
  const chunks: Buffer[] = []
  for await (const chunk of req) {
    length += chunk.length
    if (length > 16384) throw new ApiError('FRAME_TOO_LARGE', 413)
    chunks.push(chunk)
  }
  try { return parseWireJson(Buffer.concat(chunks)) } catch { throw new ApiError('INVALID_MESSAGE') }
}
/**
 * Normalize one bare IPv4/IPv6 literal to a single canonical form. IPv4-mapped
 * IPv6 addresses (e.g. ::ffff:127.0.0.1) collapse to plain IPv4, so a peer
 * observed through a dual-stack socket and a config entry compare equal.
 * Returns null for anything that is not a single IP literal: hostnames, ports,
 * CIDR ranges, comma-separated lists, bracketed hosts and zone identifiers.
 */
export function normalizeIp(value: string): string | null {
  const family = isIP(value)
  if (family === 4) return value.toLowerCase()
  if (family !== 6) return null
  let canonical: string
  try {
    canonical = new URL(`http://[${value}]/`).hostname.slice(1, -1)
  } catch { return null }
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(canonical)
  if (!mapped) return canonical
  const high = Number.parseInt(mapped[1]!, 16), low = Number.parseInt(mapped[2]!, 16)
  return `${high >>> 8}.${high & 0xff}.${low >>> 8}.${low & 0xff}`
}
/** Validate and normalize the trusted proxy list at startup. Empty means disabled. */
export function normalizeTrustedProxyIps(values: readonly string[] = []): ReadonlySet<string> {
  const result = new Set<string>()
  for (const raw of values) {
    const value = raw.trim()
    const normalized = value === '' ? null : normalizeIp(value)
    if (normalized === null) throw new Error(`Invalid DSH_SERVER_TRUSTED_PROXY_IPS entry "${raw}": expected a bare IPv4/IPv6 address (no port, CIDR or hostname).`)
    result.add(normalized)
  }
  return result
}
function readSingleForwardedFor(req: IncomingMessage): string {
  let value: string | undefined
  let count = 0
  const raw = req.rawHeaders
  for (let i = 0; i + 1 < raw.length; i += 2) {
    if (raw[i]!.toLowerCase() !== 'x-forwarded-for') continue
    count++
    value = raw[i + 1]
  }
  if (count !== 1) throw new ApiError('INVALID_MESSAGE')
  return value!
}
/**
 * Resolve the address used for rate limiting. X-Forwarded-For is honored only
 * when the socket peer is a configured trusted proxy; that peer must send one
 * header holding exactly one IP literal, otherwise the request is rejected.
 */
export function clientAddress(req: IncomingMessage, trustedProxyIps: ReadonlySet<string>): string {
  const peer = normalizeIp(req.socket.remoteAddress ?? '')
  if (peer === null) throw new ApiError('INVALID_MESSAGE')
  if (!trustedProxyIps.has(peer)) return peer
  const forwarded = normalizeIp(readSingleForwardedFor(req))
  if (forwarded === null) throw new ApiError('INVALID_MESSAGE')
  return forwarded
}
export function createRemoteServer(config: Config) {
  if (!config.account.trim() || config.password.length < 12) throw new Error('DSH_SERVER_ACCOUNT and DSH_SERVER_PASSWORD (at least 12 characters) are required.')
  const registrationCode = config.registrationCode?.trim() ?? ''
  if (registrationCode && registrationCode.length < 12) throw new Error('DSH_SERVER_REGISTRATION_CODE must be at least 12 characters when set.')
  const registrationEnabled = registrationCode.length >= 12
  const url = new URL(config.publicUrl)
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('DSH_SERVER_PUBLIC_URL must be an HTTP(S) origin.')
  const trustedProxyIps = normalizeTrustedProxyIps(config.trustedProxyIps)
  const ice = config.ice ?? parseIceConfig({})
  const store = new Store(config.dataFile, config.account.trim(), config.password)
  const assets = readAssets()
  const sessions = new Map<string, { accountKey: string; expires: number }>()
  const limits = new Map<string, { count: number; until: number }>()
  function rate(key: string, max: number) {
    for (const [k, v] of limits) if (v.until < Date.now()) limits.delete(k)
    let entry = limits.get(key)
    if (!entry) { if (limits.size >= 4096) throw new ApiError('RATE_LIMITED', 429); entry = { count: 0, until: Date.now() + 60_000 }; limits.set(key, entry) }
    if (++entry.count > max) throw new ApiError('RATE_LIMITED', 429)
  }
  function token(req: IncomingMessage): string {
    const authorization = req.headers.authorization
    if (authorization) return authorization.startsWith('Bearer ') ? authorization.slice(7) : ''
    return /(?:^|;\s*)dsh_session=([A-Za-z0-9_-]+)/.exec(req.headers.cookie ?? '')?.[1] ?? ''
  }
  function accountAuth(req: IncomingMessage): string {
    const key = hash(token(req))
    const session = sessions.get(key)
    if (!session || session.expires <= Date.now()) { sessions.delete(key); throw new ApiError('ACCOUNT_AUTH_REQUIRED', 401) }
    return session.accountKey
  }
  function openSession(accountKey: string): { value: string; expiresAt: number } {
    for (const [key, session] of sessions) if (session.expires <= Date.now()) sessions.delete(key)
    if (sessions.size >= MAX_SESSIONS) throw new ApiError('RATE_LIMITED', 429)
    let mine = 0
    for (const session of sessions.values()) if (session.accountKey === accountKey) mine += 1
    if (mine >= MAX_SESSIONS_PER_ACCOUNT) throw new ApiError('RATE_LIMITED', 429)
    const value = secret()
    const expiresAt = Date.now() + 8 * 3600_000
    sessions.set(hash(value), { accountKey, expires: expiresAt })
    return { value, expiresAt }
  }
  function publicProfile(account: string) {
    return { account, profile: { displayName: account }, isAdmin: false as const }
  }
  function deviceAuth(req: IncomingMessage) {
    if (!req.headers.authorization?.startsWith('Bearer ')) throw new ApiError('AUTH_REQUIRED', 401)
    return store.authenticate(req.headers.authorization.slice(7))
  }
  function cookie(value: string, age: number): string { return `dsh_session=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${age}${url.protocol === 'https:' ? '; Secure' : ''}` }
  const server = createServer({ requestTimeout: 15000, headersTimeout: 10000 }, (req, res) => {
    res.setHeader('Cache-Control', 'no-store')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Referrer-Policy', 'no-referrer')
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
    void route(req, res).catch(error => {
      if (res.headersSent || res.destroyed) return
      const e = error instanceof ApiError ? error : error instanceof z.ZodError ? new ApiError('INVALID_MESSAGE') : new ApiError('INTERNAL_ERROR', 500)
      if (e.status === 429) res.setHeader('Retry-After', '60')
      json(res, e.status, { error: { code: e.code, message: e.code, requestId: randomUUID(), retryable: e.status === 429 || e.status >= 500 } })
    })
  })
  const logger = new Logger('server', config.logLevel ?? 'info')
  // Normalize at this boundary as well: a programmatic caller may pass NaN,
  // Infinity or a negative value straight through the Config object.
  const timing = normalizeGatewayOptions({
    helloTimeoutMs: config.helloTimeoutMs,
    heartbeatIntervalMs: config.heartbeatIntervalMs,
    heartbeatDisconnectMs: config.heartbeatDisconnectMs,
    forceTerminateGraceMs: config.forceTerminateGraceMs,
  })
  const gateway = new Gateway(server, store, url.origin, {
    ...timing,
    maxFramesPerSec: normalizeMaxFramesPerSec(config.maxFramesPerSec),
    relayQueueSoftBytes: config.relayQueueSoftBytes,
    relayQueueHardBytes: config.relayQueueHardBytes,
    logLevel: config.logLevel,
    logger: logger.child('gateway'),
    turnEnabled: ice.turnUrls.length > 0,
  })
  function descriptor(accountKey: string, d: ReturnType<Store['get']>) {
    return { ...d.descriptor, membershipId: store.membershipId(accountKey), online: gateway.peers.has(peerKey(accountKey, d.descriptor.deviceId)), lastSeenAt: d.lastSeenAt }
  }
  async function route(req: IncomingMessage, res: ServerResponse) {
    const requestUrl = new URL(req.url ?? '/', url)
    const path = requestUrl.pathname
    const method = req.method
    if (req.headers.origin && req.headers.origin !== url.origin) throw new ApiError('AUTH_INVALID', 403)
    if (req.headers['sec-fetch-site'] === 'cross-site') throw new ApiError('AUTH_INVALID', 403)
    const staticAsset = path.startsWith('/assets/') || ['/icon.png', '/brand-whale.webp', '/landing-atmosphere.webp'].includes(path)
    // SPA fallback: any GET that is not API / WebSocket / health-check returns index.html.
    // Without this, refreshing a client route such as /app/remote hits the unknown-method branch and yields METHOD_NOT_FOUND.
    const spaRoute = method === 'GET' && !staticAsset && !path.startsWith('/api/') && !path.startsWith('/ws/') && !['/health', '/healthz', '/ready'].includes(path)
    if (method === 'GET' && (spaRoute || staticAsset)) {
      const name = staticAsset ? path.slice(1) : 'index.html'
      const asset = assets.get(name)
      if (!asset) throw new ApiError('METHOD_NOT_FOUND', 404)
      const contentType = name.endsWith('.js') ? 'text/javascript; charset=utf-8' : name.endsWith('.css') ? 'text/css; charset=utf-8' : name.endsWith('.png') ? 'image/png' : name.endsWith('.webp') ? 'image/webp' : 'text/html; charset=utf-8'
      if (!staticAsset) res.setHeader('Cache-Control', 'no-cache')
      res.setHeader('Content-Type', contentType)
      res.end(asset); return
    }
    if (method === 'GET' && (path === '/health' || path === '/healthz' || path === '/ready')) { json(res, 200, { status: 'ok' }); return }
    const client = clientAddress(req, trustedProxyIps)
    rate(`api:${client}`, 240)
    if (method === 'GET' && path === '/api/v1/auth/registration') {
      json(res, 200, { enabled: registrationEnabled }); return
    }
    if (method === 'POST' && path === '/api/v1/auth/register') {
      if (!registrationEnabled) throw new ApiError('METHOD_NOT_FOUND', 404)
      rate(`register:${client}`, 10)
      const credentials = registerSchema.parse(await body(req))
      if (!equal(credentials.code, registrationCode)) throw new ApiError('AUTH_INVALID', 401)
      if (credentials.password.length < 12) throw new ApiError('INVALID_MESSAGE')
      const user = store.registerAccount(credentials.email, credentials.password)
      const session = openSession(user.accountKey)
      res.setHeader('Set-Cookie', cookie(session.value, 8 * 3600))
      json(res, 200, { ...publicProfile(user.account), token: session.value, expiresAt: session.expiresAt }); return
    }
    if (method === 'POST' && path === '/api/v1/auth/login') {
      rate(`login:${client}`, 20)
      const credentials = loginSchema.parse(await body(req))
      const user = store.login(credentials.email, credentials.password)
      const session = openSession(user.accountKey)
      res.setHeader('Set-Cookie', cookie(session.value, 8 * 3600))
      json(res, 200, { ...publicProfile(user.account), token: session.value, expiresAt: session.expiresAt }); return
    }
    if (method === 'GET' && path === '/api/v1/auth/me') {
      json(res, 200, publicProfile(store.displayName(accountAuth(req)))); return
    }
    if (method === 'POST' && path === '/api/v1/auth/logout') {
      sessions.delete(hash(token(req))); res.setHeader('Set-Cookie', cookie('', 0)); json(res, 200, { status: 'ok' }); return
    }
    if (method === 'GET' && path === '/api/v1/account/devices') {
      const accountKey = accountAuth(req)
      json(res, 200, { items: store.list(accountKey).map(d => descriptor(accountKey, d)), serverUrl: url.origin, transport: 'webrtc' }); return
    }
    if (method === 'POST' && (path === '/api/v1/devices/register' || path === '/api/v1/devices/register-owned-role')) {
      const source = path.endsWith('register-owned-role') ? deviceAuth(req) : undefined
      const accountKey = source ? source.accountKey : accountAuth(req)
      const { device } = deviceRegistrationRequestSchema.parse(await body(req))
      if (source && (source.descriptor.deviceId === device.deviceId || source.descriptor.role === device.role)) throw new ApiError('INVALID_MESSAGE', 409)
      json(res, 200, store.register(device, accountKey)); return
    }
    if (method === 'POST' && path === '/api/v1/auth/refresh') {
      const data = deviceRefreshRequestSchema.parse(await body(req))
      json(res, 200, store.refresh(data.deviceId, data.refreshToken)); return
    }
    if (method === 'DELETE' && path === '/api/v1/devices/self') {
      const current = deviceAuth(req)
      store.revoke(current.descriptor.deviceId, current.accountKey); json(res, 200, { status: 'revoked' }); return
    }
    if (method === 'GET' && path === '/api/v1/me') {
      const current = deviceAuth(req); json(res, 200, descriptor(current.accountKey, current)); return
    }
    if (method === 'GET' && path === '/api/v1/turn/credentials') {
      const source = deviceAuth(req)
      const connectionId = requestUrl.searchParams.get('connection_id') ?? ''
      if (!connectionId || connectionId.length > 128) throw new ApiError('INVALID_MESSAGE')
      if (!gateway.authorizeIce(source.accountKey, source.descriptor.deviceId, connectionId)) throw new ApiError('CONNECTION_NOT_FOUND', 404)
      json(res, 200, { iceServers: buildIceServers(ice, source.descriptor.deviceId) }); return
    }
    if (method === 'GET' && path === '/api/v1/devices') {
      const source = deviceAuth(req)
      if (source.descriptor.role !== 'client') throw new ApiError('MEMBERSHIP_REQUIRED', 403)
      const items = store.list(source.accountKey).filter(d => d.descriptor.role === 'host').map(d => {
        const { identityKey: _key, ...item } = descriptor(source.accountKey, d)
        return item
      })
      json(res, 200, { items, nextCursor: null }); return
    }
    const renameMatch = /^\/api\/v1\/devices\/([^/]+)\/name$/.exec(path)
    if (method === 'POST' && renameMatch) {
      const accountKey = accountAuth(req)
      const { name } = z.object({ name: z.string().trim().min(1).max(80) }).parse(await body(req))
      store.rename(renameMatch[1]!, name, accountKey)
      json(res, 200, descriptor(accountKey, store.get(renameMatch[1]!, accountKey))); return
    }
    const match = /^\/api\/v1\/devices\/([^/]+)(\/presence)?$/.exec(path)
    if (method === 'GET' && match) {
      const source = deviceAuth(req), target = store.get(match[1]!, source.accountKey)
      if (source.descriptor.role === target.descriptor.role) throw new ApiError('MEMBERSHIP_REQUIRED', 403)
      const d = descriptor(source.accountKey, target)
      json(res, 200, match[2] ? { deviceId: d.deviceId, online: d.online, lastSeenAt: d.lastSeenAt } : d); return
    }
    throw new ApiError('METHOD_NOT_FOUND', 404)
  }
  return { server, store, gateway, logger, close: async () => { gateway.close(); server.closeAllConnections(); await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())) } }
}
function json(res: ServerResponse, status: number, value: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(value))
}
