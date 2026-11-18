import { randomUUID } from 'node:crypto'
import type { Server } from 'node:http'
import type { Socket } from 'node:net'
import { WebSocket, WebSocketServer } from 'ws'
import {
  createControlFrame,
  decodeControlFrame,
  MAX_CONTROL_FRAME_BYTES,
  MAX_RELAY_FRAME_BYTES,
  SERVER_SHUTDOWN_CLOSE_CODE,
  SERVER_SHUTDOWN_CLOSE_REASON,
  RELAY2_CAPABILITY,
  type ControlFrame,
  type HelloPayload,
  type ConnectRequestPayload,
  type SecureHandshakePayload,
  type RelayPayload,
  type TransportSelectedPayload,
} from '@dsh-remote/protocol'
import { ApiError, Store } from './store.js'
import { Logger, type LogLevel } from './logger.js'
import { Relay2Hub } from './relay2.js'
import { normalizeGatewayOptions, normalizeMaxFramesPerSec, type GatewayTimingOptions } from './config.js'

export interface GatewayOptions extends GatewayTimingOptions {
  maxFramesPerSec?: number
  logLevel?: LogLevel
  logger?: Logger
  /** Advertise `transport.turn` (and accept TURN credential requests). */
  turnEnabled?: boolean
  /** Start pausing a fast sender once one peer's queued relay exceeds this. */
  relayQueueSoftBytes?: number
  /** Refuse to grow one peer's queued relay past this. The socket stays open. */
  relayQueueHardBytes?: number
}

/**
 * Connection lifecycle. Frames are only ever interpreted in `awaiting_hello`
 * or `authenticated`; `closing`/`closed` exists so a hello that loses the race
 * against the handshake deadline can never authenticate, register a peer,
 * touch the store or replace a healthy socket.
 */
type ConnectionState = 'awaiting_hello' | 'authenticated' | 'closing' | 'closed'

type QueuedFrame = { raw: string; bytes: number }
type Peer = {
  key: string
  accountKey: string
  ws: WebSocket
  id: string
  role: 'host' | 'client'
  relayBase: string
  capabilities: string[]
  version: string
  lastPong: number
  /** Advanced when this socket receives a frame or accepts more outbound bytes. */
  lastProgressAt: number
  nonce?: string
  evictedTombstoneUntil?: number
  urgent: QueuedFrame[]
  bulk: QueuedFrame[]
  urgentBytes: number
  bulkBytes: number
  pumping: boolean
  drainArmed: boolean
  held: boolean
  heldAt: number
  pulseBudget: number
  heldFor?: Peer
  waiters: Set<Peer>
}
type Link = { id: string; accountKey: string; host: string; client: string; hostKey: string; clientKey: string; stage: 'pending' | 'accepted' | 'handshake' | 'ready'; created: number; counters: Map<string, number>; preferredTransports: TransportName[]; iceCandidates: number }
type DroppedLink = { accountKey: string; host: string; client: string; hostKey: string; clientKey: string; expiresAt: number; droppedFrames: number }

/** One account must not replace or address another account's socket, even when device ids collide. */
export function peerKey(accountKey: string, deviceId: string): string {
  return `${accountKey}\u0000${deviceId}`
}
const MAX_SOCKETS = 4096
const MAX_PEERS_PER_ACCOUNT = 256
const MAX_LINKS_PER_ACCOUNT = 256
const MAX_LINKS = 4096

/** Keep tombstones long enough for late in-flight frames to drain without CONNECTION_NOT_FOUND storms. */
const DROPPED_LINK_TTL_MS = 300_000
const MAX_DROPPED_LINKS_PER_HOST = 64
const MAX_DROPPED_LINKS = 16_384

/** Protocol v1 default: at most 256 ICE candidates per logical connection. */
export const MAX_ICE_CANDIDATES_PER_CONNECTION = 256
/** Mirrors docs/protocol.md: Clients use max(server, local) and default to 12 s. */
const WEBRTC_FALLBACK_TIMEOUT_MS = 12_000
/** Keep the kernel buffer small so a ping is not stuck behind a multi-megabyte relay write. */
const URGENT_WRITE_WINDOW_BYTES = 256 * 1024
const BULK_WRITE_WINDOW_BYTES = 64 * 1024
const DEFAULT_RELAY_QUEUE_SOFT_BYTES = 32 * 1024 * 1024
const DEFAULT_RELAY_QUEUE_HARD_BYTES = 256 * 1024 * 1024
const RELAY_PULSE_INTERVAL_MS = 2_000
const RELAY_PULSE_BYTES = 1024 * 1024

function normalizeQueueBytes(value: unknown, fallback: number): number {
  const parsed = typeof value === 'number' ? value : Number.NaN
  if (!Number.isFinite(parsed) || parsed < 1024) return fallback
  return Math.min(Math.floor(parsed), 1024 * 1024 * 1024)
}

function peerSocket(ws: WebSocket): Socket | undefined {
  const socket = (ws as WebSocket & { _socket?: Socket | null })._socket
  return socket ?? undefined
}
const SUPPORTED_TRANSPORTS = ['transport.lan', 'transport.p2p', 'transport.turn', 'transport.relay', RELAY2_CAPABILITY] as const
const TRANSPORT_NAMES = ['lan', 'p2p', 'turn', 'relay'] as const
type TransportName = (typeof TRANSPORT_NAMES)[number]

function modernHost(version: string): boolean {
  const match = /^v?(\d+)\.(\d+)\.(\d+)(?:\+.*)?$/.exec(version)
  if (!match) return false
  const [major, minor, patch] = match.slice(1).map(Number)
  return major! > 0 || (minor! > 2 || (minor === 2 && patch! >= 15))
}

const SAFE_TEXT = /^[A-Za-z0-9_.:-]+$/
const SAFE_PATH = /^[A-Za-z0-9/._~-]*$/
const SAFE_ADDRESS = /^[0-9a-fA-F:.]{2,45}$/
const SAFE_ERROR_NAME = /^[A-Za-z][A-Za-z0-9]{0,31}$/
const SAFE_ERROR_CODE = /^[A-Z0-9_]{1,32}$/

/** Diagnostics must never echo client-supplied text verbatim. */
function safeText(value: unknown, max = 64): string | undefined {
  return typeof value === 'string' && SAFE_TEXT.test(value) ? value.slice(0, max) : undefined
}

/** Parse the upgrade request path, dropping the query string (it may carry a token). */
function requestPath(rawUrl: string | undefined): string {
  if (typeof rawUrl !== 'string' || rawUrl === '') return ''
  const end = rawUrl.search(/[?#]/)
  const path = end === -1 ? rawUrl : rawUrl.slice(0, end)
  return SAFE_PATH.test(path) ? path.slice(0, 64) : '<invalid>'
}

function socketAddress(socket: unknown): string | undefined {
  try {
    const address = (socket as { remoteAddress?: unknown } | null)?.remoteAddress
    return typeof address === 'string' && SAFE_ADDRESS.test(address) ? address : undefined
  } catch {
    return undefined
  }
}

function errorName(error: unknown): string {
  try {
    const name = error instanceof Error ? error.name : undefined
    return typeof name === 'string' && SAFE_ERROR_NAME.test(name) ? name : 'Error'
  } catch {
    return 'Error'
  }
}

function errorCode(error: unknown): string | undefined {
  try {
    const code = (error as { code?: unknown } | null | undefined)?.code
    return typeof code === 'string' && SAFE_ERROR_CODE.test(code) ? code : undefined
  } catch {
    return undefined
  }
}

export class Gateway {
  readonly peers = new Map<string, Peer>()
  private links = new Map<string, Link>()
  private droppedLinks = new Map<string, DroppedLink>()
  private wss = new WebSocketServer({ noServer: true, maxPayload: MAX_RELAY_FRAME_BYTES, perMessageDeflate: false })
  private heartbeat: ReturnType<typeof setInterval>
  private closed = false
  readonly turnEnabled: boolean
  readonly helloTimeoutMs: number
  readonly heartbeatIntervalMs: number
  readonly heartbeatDisconnectMs: number
  readonly forceTerminateGraceMs: number
  readonly maxFramesPerSec: number
  readonly logger: Logger
  private readonly relayQueueSoftBytes: number
  private readonly relayQueueHardBytes: number
  private readonly relayQueueGlobalSoftBytes: number
  private readonly relayQueueGlobalHardBytes: number
  private readonly relay2: Relay2Hub
  private queuedBytes = 0
  private maintainTimer: ReturnType<typeof setInterval>

  constructor(server: Server, private store: Store, origin: string, options: GatewayOptions = {}) {
    // One normalization path for CLI and programmatic callers: NaN, Infinity,
    // negatives and out-of-range values degrade to documented defaults instead
    // of becoming 1ms timers.
    const timing = normalizeGatewayOptions(options)
    this.helloTimeoutMs = timing.helloTimeoutMs
    this.heartbeatIntervalMs = timing.heartbeatIntervalMs
    this.heartbeatDisconnectMs = timing.heartbeatDisconnectMs
    this.forceTerminateGraceMs = timing.forceTerminateGraceMs
    this.maxFramesPerSec = normalizeMaxFramesPerSec(options.maxFramesPerSec)
    this.relayQueueSoftBytes = normalizeQueueBytes(options.relayQueueSoftBytes, DEFAULT_RELAY_QUEUE_SOFT_BYTES)
    this.relayQueueHardBytes = Math.max(this.relayQueueSoftBytes, normalizeQueueBytes(options.relayQueueHardBytes, DEFAULT_RELAY_QUEUE_HARD_BYTES))
    this.relayQueueGlobalSoftBytes = Math.min(1024 * 1024 * 1024, this.relayQueueSoftBytes * 8)
    this.relayQueueGlobalHardBytes = Math.min(1024 * 1024 * 1024, Math.max(this.relayQueueGlobalSoftBytes, this.relayQueueHardBytes * 4))
    this.logger = options.logger ?? new Logger('gateway', options.logLevel ?? 'info')
    this.turnEnabled = options.turnEnabled === true
    this.relay2 = new Relay2Hub(origin)

    store.onInvalidate = (accountKey, deviceId) => this.disconnect(peerKey(accountKey, deviceId), 'AUTH_INVALID')
    server.on('upgrade', (req, socket, head) => {
      const path = requestPath(req.url)
      // The route still requires an exact match: a query string is rejected
      // (exactly as before) but only its parsed pathname is ever logged.
      const connectPath = req.url === '/ws/v1/connect'
      const relay2Path = req.url === '/ws/v1/relay2'
      const pathRejected = !connectPath && !relay2Path
      const originRejected = Boolean(req.headers.origin) && req.headers.origin !== origin
      if (pathRejected || originRejected || this.wss.clients.size >= MAX_SOCKETS) {
        this.logger.warn('ws_upgrade_rejected', {
          // Parsed pathname only: the raw URL may carry credentials in its query.
          path: path === '' ? 'unknown' : path,
          reason: pathRejected
            ? 'invalid_url'
            : originRejected
              ? 'origin_mismatch'
              : 'connection_limit_reached',
          clientCount: this.wss.clients.size,
          hasOrigin: Boolean(req.headers.origin),
          remoteAddress: socketAddress(socket),
        })
        socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n')
        return
      }
      const rawSocket = socket as unknown as { setNoDelay?: (noDelay: boolean) => void }
      rawSocket.setNoDelay?.(true)
      if (req.url === '/ws/v1/relay2') {
        this.relay2.handleUpgrade(req, socket, head)
        return
      }
      this.wss.handleUpgrade(req, socket, head, ws => this.accept(ws, this.relay2.endpointFor(req)))
    })
    this.heartbeat = setInterval(() => {
      if (this.closed) return
      for (const peer of this.peers.values()) {
        if (this.stale(peer)) {
          this.logger.warn('ws_heartbeat_timeout', {
            peerId: peer.id,
            role: peer.role,
            lastPong: peer.lastPong,
            elapsedMs: Date.now() - peer.lastPong,
            thresholdMs: this.heartbeatDisconnectMs,
          })
          this.disconnect(peer.key, 'CONNECTION_FAILED')
          continue
        }
        peer.nonce = randomUUID()
        this.send(peer, createControlFrame('ping', { nonce: peer.nonce }))
      }
      for (const link of this.links.values()) {
        if (link.stage !== 'ready' && Date.now() - link.created > 30_000) this.drop(link, 'CONNECTION_FAILED')
      }
      this.pruneDroppedLinks(Date.now())
    }, this.heartbeatIntervalMs)
    this.heartbeat.unref()
    this.maintainTimer = setInterval(() => this.maintain(), 1_000)
    this.maintainTimer.unref()
  }

  /** A slow reader is still alive while outbound bytes keep moving. An idle silent socket is not. */
  private stale(peer: Peer): boolean {
    if (Date.now() - peer.lastPong <= this.heartbeatDisconnectMs) return false
    const backlog = peer.bulkBytes + peer.urgentBytes + (peer.ws.readyState === WebSocket.OPEN ? peer.ws.bufferedAmount : 0)
    return !(backlog > 0 && Date.now() - peer.lastProgressAt <= this.heartbeatDisconnectMs)
  }

  private pruneDroppedLinks(now: number): void {
    for (const [id, entry] of this.droppedLinks) {
      if (entry.expiresAt <= now) this.droppedLinks.delete(id)
    }
  }

  private evictDroppedLink(id: string, entry: DroppedLink, now: number): void {
    this.droppedLinks.delete(id)
    if (entry.expiresAt <= now) return
    for (const key of [entry.hostKey, entry.clientKey]) {
      const p = this.peers.get(key)
      if (p) p.evictedTombstoneUntil = Math.max(p.evictedTombstoneUntil ?? 0, entry.expiresAt)
    }
  }

  private recordDroppedLink(link: Link): void {
    const now = Date.now()
    this.pruneDroppedLinks(now)
    this.droppedLinks.delete(link.id)
    let hostCount = 0
    let oldestForHost: [string, DroppedLink] | undefined
    for (const [id, entry] of this.droppedLinks) {
      if (entry.hostKey === link.hostKey) {
        if (oldestForHost === undefined) oldestForHost = [id, entry]
        hostCount += 1
      }
    }
    if (hostCount >= MAX_DROPPED_LINKS_PER_HOST && oldestForHost !== undefined) {
      this.evictDroppedLink(oldestForHost[0], oldestForHost[1], now)
    }
    while (this.droppedLinks.size >= MAX_DROPPED_LINKS) {
      const oldest = this.droppedLinks.entries().next().value as [string, DroppedLink] | undefined
      if (oldest === undefined) break
      this.evictDroppedLink(oldest[0], oldest[1], now)
    }
    this.droppedLinks.set(link.id, {
      accountKey: link.accountKey,
      host: link.host,
      client: link.client,
      hostKey: link.hostKey,
      clientKey: link.clientKey,
      expiresAt: now + DROPPED_LINK_TTL_MS,
      droppedFrames: 0,
    })
  }

  private isDroppedLinkFrame(peer: Peer, frame: ControlFrame): boolean {
    if (frame.type === 'ping' || frame.type === 'pong' || frame.type === 'connect.request') return false
    const p = frame.payload as Record<string, unknown>
    const id = p.connectionId
    if (typeof id !== 'string' || this.links.has(id)) return false
    const now = Date.now()
    const dropped = this.droppedLinks.get(id)
    if (!dropped) {
      return peer.evictedTombstoneUntil !== undefined && now < peer.evictedTombstoneUntil
    }
    if (dropped.expiresAt <= now) {
      this.droppedLinks.delete(id)
      return false
    }
    if (peer.accountKey !== dropped.accountKey) return false
    if (peer.id !== dropped.host && peer.id !== dropped.client) return false
    dropped.droppedFrames += 1
    if (dropped.droppedFrames === 1) {
      this.logger.debug('ws_stale_link_frames_dropped', {
        peerId: peer.id,
        role: peer.role,
        connectionId: safeText(id),
      })
    }
    return true
  }

  droppedLinkFrameCount(connectionId: string): number {
    return this.droppedLinks.get(connectionId)?.droppedFrames ?? 0
  }

  private send(peer: Peer, frame: ControlFrame, source?: Peer): void {
    if (this.peers.get(peer.key) !== peer || peer.ws.readyState !== WebSocket.OPEN) return
    const raw = JSON.stringify(frame)
    const item = { raw, bytes: Buffer.byteLength(raw) }
    // Relay is the bulk path. Everything else (heartbeat, signaling, handshake,
    // errors) stays ahead of it so a large transfer cannot hide a ping.
    if (frame.type === 'relay') {
      peer.bulk.push(item)
      peer.bulkBytes += item.bytes
    } else {
      peer.urgent.push(item)
      peer.urgentBytes += item.bytes
    }
    this.queuedBytes += item.bytes
    this.pump(peer)
    if (source && frame.type === 'relay') this.noteCongestion(peer, source, item.bytes)
  }

  private pump(peer: Peer): void {
    if (peer.pumping || this.peers.get(peer.key) !== peer || peer.ws.readyState !== WebSocket.OPEN) return
    const urgent = peer.urgent.length > 0
    const queue = urgent ? peer.urgent : peer.bulk
    if (queue.length === 0) return
    if (peer.ws.bufferedAmount > (urgent ? URGENT_WRITE_WINDOW_BYTES : BULK_WRITE_WINDOW_BYTES) && this.armDrain(peer)) return
    const item = queue.shift()
    if (!item) return
    if (urgent) peer.urgentBytes -= item.bytes
    else peer.bulkBytes -= item.bytes
    this.queuedBytes = Math.max(0, this.queuedBytes - item.bytes)
    peer.pumping = true
    let finished = false
    const finish = () => {
      if (finished) return
      finished = true
      peer.pumping = false
      if (this.peers.get(peer.key) !== peer) return
      peer.lastProgressAt = Date.now()
      this.releaseWaiters(peer)
      this.pump(peer)
    }
    try {
      peer.ws.send(item.raw, () => finish())
    } catch {
      peer.pumping = false
    }
  }

  private armDrain(peer: Peer): boolean {
    if (peer.drainArmed) return true
    const socket = peerSocket(peer.ws)
    if (!socket) return false
    peer.drainArmed = true
    const onDrain = () => {
      socket.off('drain', onDrain)
      peer.drainArmed = false
      peer.lastProgressAt = Date.now()
      this.pump(peer)
    }
    socket.on('drain', onDrain)
    return true
  }

  private noteCongestion(destination: Peer, source: Peer, bytes: number): void {
    if (source.pulseBudget > 0) source.pulseBudget = Math.max(0, source.pulseBudget - bytes)
    const overHard = destination.bulkBytes > this.relayQueueHardBytes || this.queuedBytes > this.relayQueueGlobalHardBytes
    const overSoft = destination.bulkBytes > this.relayQueueSoftBytes || this.queuedBytes > this.relayQueueGlobalSoftBytes
    if (source.pulseBudget > 0 && !overHard) return
    if (!overSoft && !overHard) return
    if (source.held) return
    source.held = true
    source.heldAt = Date.now()
    source.heldFor = destination
    destination.waiters.add(source)
    if (source.ws.readyState === WebSocket.OPEN) source.ws.pause()
  }

  private releaseWaiters(destination: Peer): void {
    if (destination.bulkBytes > this.relayQueueSoftBytes / 2) return
    if (this.queuedBytes > this.relayQueueGlobalSoftBytes / 2) return
    for (const source of destination.waiters) {
      source.held = false
      source.pulseBudget = 0
      source.heldFor = undefined
      if (source.ws.readyState === WebSocket.OPEN) source.ws.resume()
    }
    destination.waiters.clear()
  }

  /** Let a paused sender move a little data so its own 10s write timeout does not fire. */
  private maintain(): void {
    if (this.closed) return
    const now = Date.now()
    for (const peer of this.peers.values()) {
      if ((peer.urgent.length > 0 || peer.bulk.length > 0) && !peer.pumping) this.pump(peer)
      if (!peer.held || !peer.heldFor) continue
      if (peer.heldFor.bulkBytes > this.relayQueueHardBytes || this.queuedBytes > this.relayQueueGlobalHardBytes) continue
      if (now - peer.heldAt < RELAY_PULSE_INTERVAL_MS) continue
      peer.pulseBudget = RELAY_PULSE_BYTES
      peer.held = false
      peer.heldAt = now
      if (peer.ws.readyState === WebSocket.OPEN) peer.ws.resume()
    }
  }

  private discardOutbound(peer: Peer): void {
    this.queuedBytes = Math.max(0, this.queuedBytes - peer.bulkBytes - peer.urgentBytes)
    peer.bulk = []
    peer.urgent = []
    peer.bulkBytes = 0
    peer.urgentBytes = 0
    for (const source of peer.waiters) {
      source.held = false
      source.pulseBudget = 0
      source.heldFor = undefined
      if (source.ws.readyState === WebSocket.OPEN) source.ws.resume()
    }
    peer.waiters.clear()
    for (const other of this.peers.values()) {
      if (!other.waiters.delete(peer)) continue
      peer.held = false
      peer.pulseBudget = 0
      peer.heldFor = undefined
    }
  }
  private relay2Fields(link: Link, role: 'host' | 'client'): { relay2Endpoint?: string; relay2Ticket?: string } {
    const self = this.peers.get(role === 'host' ? link.hostKey : link.clientKey)
    const other = this.peers.get(role === 'host' ? link.clientKey : link.hostKey)
    if (self === undefined || other === undefined) return {}
    if (!self.capabilities.includes(RELAY2_CAPABILITY) || !other.capabilities.includes(RELAY2_CAPABILITY)) return {}
    if (self.relayBase.length === 0) return {}
    return {
      relay2Endpoint: self.relayBase,
      relay2Ticket: this.relay2.issue(link.id, role, self.accountKey),
    }
  }

  private withRelay2(link: Link, role: 'host' | 'client', frame: ControlFrame): ControlFrame {
    const extra = this.relay2Fields(link, role)
    if (extra.relay2Ticket === undefined) return frame
    return { ...frame, payload: { ...(frame.payload as Record<string, unknown>), ...extra } }
  }

  private drop(link: Link, code: string): void {
    this.links.delete(link.id)
    this.relay2.closeConnection(link.id)
    this.recordDroppedLink(link)
    for (const key of [link.hostKey, link.clientKey]) {
      const p = this.peers.get(key)
      if (p && (p.role === 'client' || modernHost(p.version))) this.send(p, createControlFrame('error', { code, message: code, connectionId: link.id, retryable: true }))
    }
  }
  disconnect(key: string, code: string): void {
    const peer = this.peers.get(key)
    this.peers.delete(key)
    if (peer) this.discardOutbound(peer)
    for (const link of this.links.values()) if (link.hostKey === key || link.clientKey === key) this.drop(link, code)
    if (!peer) return
    this.logger.info('ws_peer_disconnected', { peerId: peer.id, code })
    try {
      peer.ws.close(code === 'CONNECTION_REPLACED' ? 4003 : 4001, code)
    } catch {
      // Socket already closing: the grace below still forces termination.
    }
    const timer = setTimeout(() => {
      if (peer.ws.readyState !== WebSocket.CLOSED) peer.ws.terminate()
    }, this.forceTerminateGraceMs)
    timer.unref()
  }

  /**
   * Authorize a REST `/api/v1/turn/credentials` request. Only the two devices
   * of an active logical connection may obtain credentials, and only while
   * that connection is still being established.
   */
  authorizeIce(accountKey: string, deviceId: string, connectionId: string): boolean {
    const link = this.links.get(connectionId)
    if (link === undefined || link.accountKey !== accountKey) return false
    if (link.host !== deviceId && link.client !== deviceId) return false
    if (link.stage !== 'accepted' && link.stage !== 'handshake') return false
    return this.peers.has(link.hostKey) && this.peers.has(link.clientKey)
  }
  private find(accountKey: string, deviceId: string): Peer | undefined {
    return this.peers.get(peerKey(accountKey, deviceId))
  }
  private supportedCapabilities(): string[] {
    return SUPPORTED_TRANSPORTS.filter(capability => capability !== 'transport.turn' || this.turnEnabled)
  }
  private negotiatedCapabilities(offered: readonly string[]): string[] {
    return this.supportedCapabilities().filter(capability => offered.includes(capability))
  }

  private accept(ws: WebSocket, relayBase: string): void {
    let state: ConnectionState = 'awaiting_hello'
    let peer: Peer | undefined
    let deadline: ReturnType<typeof setTimeout> | undefined
    let graceTimer: ReturnType<typeof setTimeout> | undefined

    // Timer cleanup is idempotent: every path (auth, timeout, close) can call
    // it any number of times without leaving a scheduled callback behind.
    const clearDeadline = (): void => {
      if (deadline === undefined) return
      clearTimeout(deadline)
      deadline = undefined
    }
    const clearGrace = (): void => {
      if (graceTimer === undefined) return
      clearTimeout(graceTimer)
      graceTimer = undefined
    }
    const terminateSoon = (target: WebSocket): void => {
      clearGrace()
      graceTimer = setTimeout(() => {
        graceTimer = undefined
        if (target.readyState !== WebSocket.CLOSED) target.terminate()
      }, this.forceTerminateGraceMs)
      graceTimer.unref()
    }

    this.logger.debug('ws_connection_accepted', { clientCount: this.wss.clients.size })

    deadline = setTimeout(() => {
      deadline = undefined
      if (state !== 'awaiting_hello') return
      // Close the door before closing the socket: any hello still in flight is
      // then discarded by the frame guard instead of authenticating late.
      state = 'closing'
      this.logger.warn('ws_hello_timeout', { timeoutMs: this.helloTimeoutMs, readyState: ws.readyState })
      if (ws.readyState === WebSocket.OPEN) {
        try {
          const frame = createControlFrame('error', {
            code: 'HELLO_TIMEOUT',
            message: `Hello handshake timed out after ${this.helloTimeoutMs}ms`,
            retryable: true,
          })
          ws.send(JSON.stringify(frame))
        } catch (error) {
          this.logger.warn('ws_hello_timeout_send_failed', { errorName: errorName(error) })
        }
      }
      try {
        ws.close(4001, 'CONNECTION_FAILED')
      } catch {
        // ws might not be closable in some edge states; the grace below terminates it.
      }
      terminateSoon(ws)
    }, this.helloTimeoutMs)
    deadline.unref()

    let windowStart = Date.now(), frames = 0, bytes = 0, droppedFrames = 0, droppedBytes = 0
    ws.on('error', (error) => {
      // Error messages can embed payload fragments: log the class and errno only.
      this.logger.warn('ws_socket_error', {
        peerId: peer?.id,
        errorName: errorName(error),
        errorCode: errorCode(error),
      })
    })
    ws.on('close', (code, reason) => {
      state = 'closed'
      clearDeadline()
      clearGrace()
      this.logger.info('ws_connection_closed', {
        ...(peer ? { peerId: peer.id, role: peer.role } : {}),
        code,
        // The close reason is arbitrary client text: report only its presence.
        hasReason: Buffer.isBuffer(reason) ? reason.length > 0 : false,
      })
      if (peer && this.peers.get(peer.key) === peer) this.disconnect(peer.key, 'CONNECTION_FAILED')
    })
    ws.on('message', (raw, binary) => {
      // Frames arriving after the handshake deadline are dropped before any
      // parsing, authentication or store access can happen.
      if (state !== 'awaiting_hello' && state !== 'authenticated') return
      if (ws.readyState !== WebSocket.OPEN) return
      let frame: ControlFrame | undefined
      try {
        if (binary) throw new ApiError('INVALID_MESSAGE')
        const text = raw.toString()
        const frameBytes = Buffer.byteLength(text)
        if (Date.now() - windowStart >= 1000) {
          windowStart = Date.now()
          frames = 0
          bytes = 0
          droppedFrames = 0
          droppedBytes = 0
        }
        const maxDroppedFrames = Math.max(this.maxFramesPerSec * 2, 1024)
        const maxDroppedBytes = 8 * MAX_RELAY_FRAME_BYTES
        if (frames + droppedFrames + 1 > this.maxFramesPerSec + maxDroppedFrames
          || bytes + droppedBytes + frameBytes > 16 * MAX_RELAY_FRAME_BYTES + maxDroppedBytes) {
          throw new ApiError('RATE_LIMITED')
        }
        if (state === 'awaiting_hello' && (++frames > this.maxFramesPerSec || (bytes += frameBytes) > 16 * MAX_RELAY_FRAME_BYTES)) {
          throw new ApiError('RATE_LIMITED')
        }
        const envelope = JSON.parse(text) as { v?: unknown }
        if (envelope && envelope.v !== 1) throw new ApiError('UNSUPPORTED_VERSION')
        frame = decodeControlFrame(text)
        if (state === 'awaiting_hello') {
          if (frame.type !== 'hello') throw new ApiError('AUTH_REQUIRED')
          const p = frame.payload as HelloPayload
          const authenticated = this.store.authenticate(p.accessToken)
          const device = authenticated.descriptor
          if (device.deviceId !== p.deviceId || device.role !== p.role) throw new ApiError('AUTH_INVALID')
          if (!p.protocols.includes(1)) throw new ApiError('UNSUPPORTED_VERSION')
          // Re-assert the state: if the deadline fired while credentials were
          // checked, the timeout wins and none of the side effects below run.
          if (state !== 'awaiting_hello') return
          const key = peerKey(authenticated.accountKey, device.deviceId)
          let accountPeers = 0
          for (const existing of this.peers.values()) if (existing.accountKey === authenticated.accountKey && existing.key !== key) accountPeers += 1
          if (accountPeers >= MAX_PEERS_PER_ACCOUNT) throw new ApiError('RATE_LIMITED')
          state = 'authenticated'
          clearDeadline()
          this.disconnect(key, 'CONNECTION_REPLACED')
          // Keep the negotiated set (what hello.ack advertises), so a link can
          // never coordinate a transport this Server did not offer — e.g. TURN
          // while no TURN deployment is configured.
          const now = Date.now()
          peer = {
            key, accountKey: authenticated.accountKey, ws, id: device.deviceId, role: device.role,
            capabilities: this.negotiatedCapabilities(p.capabilities), version: p.clientVersion ?? device.clientVersion,
            relayBase,
            lastPong: now, lastProgressAt: now, urgent: [], bulk: [], urgentBytes: 0, bulkBytes: 0,
            pumping: false, drainArmed: false, held: false, heldAt: 0, pulseBudget: 0, waiters: new Set(),
          }
          this.peers.set(peer.key, peer)
          this.store.touch(peer.accountKey, peer.id, p.clientVersion, p.harnessVersion)
          this.logger.info('ws_hello_authenticated', {
            deviceId: safeText(peer.id),
            role: peer.role,
            clientVersion: safeText(peer.version),
            capabilities: peer.capabilities.filter(capability => typeof capability === 'string' && SAFE_TEXT.test(capability)).slice(0, 8),
          })
          this.send(peer, createControlFrame('hello.ack', {
            protocol: 1,
            serverVersion: 'self-hosted/0.1.0',
            connectionSessionId: randomUUID(),
            heartbeatIntervalMs: this.heartbeatIntervalMs,
            maxControlFrameBytes: MAX_CONTROL_FRAME_BYTES,
            maxRelayFrameBytes: MAX_RELAY_FRAME_BYTES,
            capabilities: this.negotiatedCapabilities(p.capabilities),
            webrtcEnabled: true,
            webrtcFallbackTimeoutMs: WEBRTC_FALLBACK_TIMEOUT_MS,
          }))
          return
        }
        if (frame.type === 'hello') throw new ApiError('INVALID_MESSAGE')
        if (!peer || this.peers.get(peer.key) !== peer) throw new ApiError('AUTH_INVALID')
        this.store.get(peer.id, peer.accountKey)
        if (this.isDroppedLinkFrame(peer, frame)) {
          if (++droppedFrames > maxDroppedFrames || (droppedBytes += frameBytes) > maxDroppedBytes) {
            throw new ApiError('RATE_LIMITED')
          }
          return
        }
        // Authenticated session traffic is queued, not rejected. The previous
        // per-second cap closed the socket once a reload exceeded it, and both
        // directions then had nothing left to load.
        peer.lastProgressAt = Date.now()
        this.handle(peer, frame)
      } catch (error) {
        const code = error instanceof ApiError ? error.code : 'INVALID_MESSAGE'
        this.logger.warn('ws_message_error', {
          code,
          peerId: peer?.id,
          // Never log error.message: JSON parse failures echo the payload.
          errorName: errorName(error),
        })
        // Valid connection-scoped failures must not close the Host's other clients.
        const connectionId = (frame?.payload as { connectionId?: unknown } | undefined)?.connectionId
        if (peer && typeof connectionId === 'string' && code !== 'RATE_LIMITED') {
          const link = this.links.get(connectionId)
          if (link && link.accountKey === peer.accountKey && (link.host === peer.id || link.client === peer.id)) { this.drop(link, code); return }
          this.send(peer, createControlFrame('error', { code, message: code, connectionId, retryable: false }))
          return
        }
        state = 'closing'
        clearDeadline()
        if (ws.readyState === WebSocket.OPEN) {
          try { ws.send(JSON.stringify(createControlFrame('error', { code, message: code, retryable: false }))) } catch { /* closing anyway */ }
        }
        if (peer) this.disconnect(peer.key, code)
        else {
          try { ws.close(4001, code) } catch { /* terminate below */ }
          terminateSoon(ws)
        }
      }
    })
  }
  private handle(peer: Peer, frame: ControlFrame): void {
    const p = frame.payload as Record<string, unknown>
    if (frame.type === 'ping') { this.send(peer, createControlFrame('pong', { nonce: p.nonce })); return }
    if (frame.type === 'pong') {
      if (peer.nonce && p.nonce === peer.nonce) { peer.lastPong = Date.now(); peer.nonce = undefined }
      return
    }
    if (frame.type === 'connect.request') {
      const request = frame.payload as ConnectRequestPayload
      if (peer.role !== 'client') throw new ApiError('MEMBERSHIP_REQUIRED')
      const candidateHost = this.find(peer.accountKey, request.hostDeviceId)
      if (candidateHost && this.stale(candidateHost)) {
        this.logger.warn('ws_heartbeat_timeout', {
          peerId: candidateHost.id,
          role: candidateHost.role,
          lastPong: candidateHost.lastPong,
          elapsedMs: Date.now() - candidateHost.lastPong,
          thresholdMs: this.heartbeatDisconnectMs,
        })
        this.disconnect(candidateHost.key, 'CONNECTION_FAILED')
      }
      const host = this.find(peer.accountKey, request.hostDeviceId)
      if (!host || host.role !== 'host' || host.accountKey !== peer.accountKey) { this.send(peer, createControlFrame('error', { code: 'HOST_OFFLINE', message: 'Host is offline.', retryable: true })); return }
      this.store.get(host.id, host.accountKey)
      if (!request.preferredTransports.includes('relay') || !peer.capabilities.includes('transport.relay') || !host.capabilities.includes('transport.relay')) throw new ApiError('CAPABILITY_NOT_SUPPORTED')
      // The link coordinates only transports both peers actually advertised;
      // the Host receives the same intersection so it never sees a transport
      // it could not have negotiated.
      const preferredTransports = [...new Set(request.preferredTransports)].filter(transport =>
        peer.capabilities.includes(`transport.${transport}`) && host.capabilities.includes(`transport.${transport}`))
      if (preferredTransports.length === 0) throw new ApiError('CAPABILITY_NOT_SUPPORTED')
      for (const old of this.links.values()) if (old.accountKey === peer.accountKey && (old.clientKey === peer.key || (old.hostKey === host.key && !modernHost(host.version)))) this.drop(old, 'CONNECTION_REPLACED')
      let accountLinks = 0
      for (const existing of this.links.values()) if (existing.accountKey === peer.accountKey) accountLinks += 1
      if (accountLinks >= MAX_LINKS_PER_ACCOUNT || this.links.size >= MAX_LINKS) throw new ApiError('RATE_LIMITED')
      const link: Link = {
        id: randomUUID(),
        accountKey: peer.accountKey,
        host: host.id,
        client: peer.id,
        hostKey: host.key,
        clientKey: peer.key,
        stage: 'pending',
        created: Date.now(),
        counters: new Map(),
        preferredTransports,
        iceCandidates: 0,
      }
      this.links.set(link.id, link)
      this.send(host, createControlFrame('connect.incoming', {
        connectionId: link.id,
        clientDeviceId: peer.id,
        clientIdentityKey: this.store.get(peer.id, peer.accountKey).descriptor.identityKey,
        authorization: 'account',
        preferredTransports: link.preferredTransports,
        ...this.relay2Fields(link, 'host'),
      }))
      return
    }
    const id = p.connectionId
    const link = typeof id === 'string' ? this.links.get(id) : undefined
    if (!link || link.accountKey !== peer.accountKey || (peer.id !== link.host && peer.id !== link.client)) throw new ApiError('CONNECTION_NOT_FOUND')
    const otherId = peer.id === link.host ? link.client : link.host
    const otherKey = peer.key === link.hostKey ? link.clientKey : link.hostKey
    const other = this.peers.get(otherKey)
    this.store.get(otherId, link.accountKey)
    if (!other) throw new ApiError('CONNECTION_FAILED')
    if (frame.type === 'connect.accepted' || frame.type === 'connect.rejected') {
      if (peer.id !== link.host || link.stage !== 'pending') throw new ApiError('INVALID_MESSAGE')
      if (frame.type === 'connect.rejected') {
        this.links.delete(link.id)
        this.relay2.closeConnection(link.id)
        this.recordDroppedLink(link)
      }
      else link.stage = 'accepted'
      this.send(other, frame.type === 'connect.accepted' ? this.withRelay2(link, 'client', frame) : frame, peer)
      return
    }
    if (p.targetDeviceId !== otherId || link.stage === 'pending') throw new ApiError('CONNECTION_NOT_FOUND')
    if (frame.type.startsWith('signal.')) {
      this.forwardSignal(link, peer, other, frame)
      return
    }
    if (frame.type === 'transport.selected') {
      this.forwardTransportSelected(link, peer, other, frame.payload as TransportSelectedPayload)
      return
    }
    if (frame.type === 'secure.handshake') {
      const step = (frame.payload as SecureHandshakePayload).step
      if (step === 1 && peer.id === link.client && link.stage === 'accepted') link.stage = 'handshake'
      else if (step === 2 && peer.id === link.host && link.stage === 'handshake') link.stage = 'ready'
      else throw new ApiError('INVALID_MESSAGE')
    } else if (frame.type === 'relay') {
      const counter = (frame.payload as RelayPayload).counter
      if (link.stage !== 'ready' || counter <= (link.counters.get(peer.id) ?? -1)) throw new ApiError('INVALID_MESSAGE')
      link.counters.set(peer.id, counter)
    } else throw new ApiError('INVALID_MESSAGE')
    this.send(other, frame, peer)
  }
  /**
   * Forward WebRTC signaling only while the logical connection is being
   * established, and only for a transport this link actually negotiated. A
   * relay-only link has no data plane to coordinate — the Host treats
   * unsolicited signaling as a protocol violation that closes its whole
   * Control connection and every tunnel on it, so such frames are dropped for
   * the Client to time out and fall back to Relay.
   */
  private forwardSignal(link: Link, peer: Peer, other: Peer, frame: ControlFrame): void {
    if (link.stage === 'ready') return
    if (!link.preferredTransports.some(transport => transport !== 'relay')) return
    if (frame.type === 'signal.offer') {
      if (peer.id !== link.client) throw new ApiError('INVALID_MESSAGE')
    } else if (frame.type === 'signal.answer') {
      if (peer.id !== link.host) throw new ApiError('INVALID_MESSAGE')
    } else if (frame.type === 'signal.ice') {
      if (++link.iceCandidates > MAX_ICE_CANDIDATES_PER_CONNECTION) throw new ApiError('INVALID_MESSAGE')
    } else {
      throw new ApiError('INVALID_MESSAGE')
    }
    this.send(other, frame, peer)
  }
  /**
   * Forward the initiator's transport choice, gated on the transports the
   * link negotiated. `lan` is downgraded to `p2p` only when the link did not
   * negotiate `transport.lan` (old RC2 peers), as required by
   * docs/protocol.md. Relay keeps the legacy compatibility gate.
   */
  private forwardTransportSelected(link: Link, peer: Peer, other: Peer, payload: TransportSelectedPayload): void {
    // The protocol only lets the initiator (Client) select the transport. A
    // responder (Host) may also announce its own selection after its RTC data
    // channel opens; clients ignore it, so ignoring here is compatibility, not
    // a protocol violation. Throwing would drop the whole link and prevent the
    // Noise handshake from completing.
    if (peer.id !== link.client) return
    if (link.stage !== 'accepted' && link.stage !== 'handshake') throw new ApiError('INVALID_MESSAGE')
    const transport: TransportName = payload.transport
    if (!TRANSPORT_NAMES.includes(transport)) throw new ApiError('INVALID_MESSAGE')
    const selected = transport === 'lan'
      && !link.preferredTransports.includes('lan')
      && link.preferredTransports.includes('p2p')
      ? 'p2p'
      : transport
    if (!link.preferredTransports.includes(selected)) throw new ApiError('CAPABILITY_NOT_SUPPORTED')
    if (selected === 'relay' && !modernHost(other.version)) return
    this.send(other, selected === transport
      ? createControlFrame('transport.selected', { ...payload })
      : createControlFrame('transport.selected', { ...payload, transport: selected }), peer)
  }
  close(): void {
    if (this.closed) return
    this.closed = true
    clearInterval(this.heartbeat)
    clearInterval(this.maintainTimer)
    this.relay2.close()
    this.logger.info('ws_gateway_closing', { clientCount: this.wss.clients.size })
    for (const ws of this.wss.clients) {
      // Give resumable clients an explicit, unambiguous shutdown signal. A
      // process restart is different from heartbeat failure (4001) and from
      // replacement/authentication failures, so clients can retain only the
      // bounded lease-backed session state.
      try {
        if (ws.readyState === WebSocket.OPEN) ws.close(SERVER_SHUTDOWN_CLOSE_CODE, SERVER_SHUTDOWN_CLOSE_REASON)
        else ws.terminate()
      } catch {
        // Force termination below.
      }
      const timer = setTimeout(() => { if (ws.readyState !== WebSocket.CLOSED) ws.terminate() }, this.forceTerminateGraceMs)
      timer.unref()
    }
    this.wss.close()
  }
}
