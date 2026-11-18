import { randomBytes } from 'node:crypto'
import type { IncomingMessage } from 'node:http'
import type { Duplex } from 'node:stream'
import type { Socket } from 'node:net'
import { WebSocket, WebSocketServer } from 'ws'
import { MAX_RELAY_FRAME_BYTES } from '@dsh-remote/protocol'

const TICKET_TTL_MS = 30_000
const HIGH_WATER_BYTES = 2 * 1024 * 1024

interface Ticket {
  connectionId: string
  role: 'host' | 'client'
  accountKey: string
  expires: number
}

interface Side {
  ws: WebSocket
  drainArmed: boolean
}

interface Pair {
  accountKey: string
  host?: Side
  client?: Side
}

/**
 * Binary splice for one connection. Control frames stay on the other socket.
 * A slow reader pauses the sender; the sockets stay open and bytes are not dropped.
 */
export class Relay2Hub {
  private readonly wss = new WebSocketServer({ noServer: true, maxPayload: MAX_RELAY_FRAME_BYTES + 64 })
  private readonly tickets = new Map<string, Ticket>()
  private readonly pairs = new Map<string, Pair>()

  constructor(private readonly origin: string) {}

  endpointFor(req: IncomingMessage): string {
    const advertised = new URL(this.origin)
    const loopback = advertised.hostname === 'localhost' || advertised.hostname === '127.0.0.1'
    const hostHeader = typeof req.headers.host === 'string' ? req.headers.host : ''
    const host = loopback && hostHeader.length > 0 ? hostHeader : advertised.host
    const forwarded = req.headers['x-forwarded-proto']
    const forwardedProto = typeof forwarded === 'string' ? forwarded.split(',')[0]?.trim() : ''
    const secure = advertised.protocol === 'https:' || forwardedProto === 'https'
    return `${secure ? 'wss:' : 'ws:'}//${host}/ws/v1/relay2`
  }

  issue(connectionId: string, role: 'host' | 'client', accountKey: string): string {
    const ticket = randomBytes(32).toString('base64url')
    this.tickets.set(ticket, { connectionId, role, accountKey, expires: Date.now() + TICKET_TTL_MS })
    return ticket
  }

  handleUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): void {
    const raw = socket as { setNoDelay?: (noDelay: boolean) => void }
    raw.setNoDelay?.(true)
    this.wss.handleUpgrade(req, socket, head, ws => this.accept(ws))
  }

  closeConnection(connectionId: string): void {
    for (const [ticket, info] of this.tickets) {
      if (info.connectionId === connectionId) this.tickets.delete(ticket)
    }
    const pair = this.pairs.get(connectionId)
    this.pairs.delete(connectionId)
    this.closeSide(pair?.host)
    this.closeSide(pair?.client)
  }

  close(): void {
    this.tickets.clear()
    for (const id of [...this.pairs.keys()]) this.closeConnection(id)
    this.wss.close()
  }

  private accept(ws: WebSocket): void {
    let paired = false
    const fail = (): void => {
      try { ws.close(4001, 'CONNECTION_FAILED') } catch { /* already closing */ }
    }
    ws.once('message', (data, isBinary) => {
      if (!isBinary) { fail(); return }
      const bytes = toBuffer(data)
      if (bytes.byteLength < 2 || bytes[0] !== 1) { fail(); return }
      let parsed: { ticket?: unknown; connectionId?: unknown }
      try {
        parsed = JSON.parse(bytes.subarray(1).toString('utf8')) as { ticket?: unknown; connectionId?: unknown }
      } catch {
        fail()
        return
      }
      if (typeof parsed.ticket !== 'string' || typeof parsed.connectionId !== 'string') { fail(); return }
      const ticket = this.tickets.get(parsed.ticket)
      this.tickets.delete(parsed.ticket)
      if (ticket === undefined || ticket.expires < Date.now() || ticket.connectionId !== parsed.connectionId) {
        fail()
        return
      }
      const pair = this.pairs.get(ticket.connectionId) ?? { accountKey: ticket.accountKey }
      if (pair.accountKey !== ticket.accountKey || pair[ticket.role] !== undefined) { fail(); return }
      const side: Side = { ws, drainArmed: false }
      pair[ticket.role] = side
      this.pairs.set(ticket.connectionId, pair)
      paired = true
      ws.on('message', (next, nextBinary) => {
        if (!nextBinary) { this.closeConnection(ticket.connectionId); return }
        this.forward(ticket.connectionId, ticket.role, toBuffer(next))
      })
      ws.on('close', () => {
        const current = this.pairs.get(ticket.connectionId)
        if (current?.[ticket.role]?.ws === ws) this.closeConnection(ticket.connectionId)
      })
      ws.on('error', () => {
        if (this.pairs.get(ticket.connectionId)?.[ticket.role]?.ws === ws) this.closeConnection(ticket.connectionId)
      })
      if (pair.host && pair.client) {
        this.sendReady(pair.host.ws)
        this.sendReady(pair.client.ws)
      }
    })
    ws.on('close', () => {
      if (!paired) return
    })
  }

  private forward(connectionId: string, role: 'host' | 'client', data: Buffer): void {
    const pair = this.pairs.get(connectionId)
    const source = pair?.[role]
    const destination = role === 'host' ? pair?.client : pair?.host
    if (source === undefined || destination === undefined || data.byteLength < 1 || data[0] === 1 || data[0] === 2) return
    if (destination.ws.readyState !== WebSocket.OPEN) {
      this.closeConnection(connectionId)
      return
    }
    destination.ws.send(data, { binary: true })
    if (destination.ws.bufferedAmount <= HIGH_WATER_BYTES || source.ws.readyState !== WebSocket.OPEN) return
    source.ws.pause()
    this.armDrain(destination, source)
  }

  private armDrain(destination: Side, source: Side): void {
    if (destination.drainArmed) return
    const socket = (destination.ws as WebSocket & { _socket?: Socket | null })._socket
    if (!socket) {
      if (source.ws.readyState === WebSocket.OPEN) source.ws.resume()
      return
    }
    destination.drainArmed = true
    const onDrain = (): void => {
      socket.off('drain', onDrain)
      destination.drainArmed = false
      if (source.ws.readyState === WebSocket.OPEN) source.ws.resume()
    }
    socket.on('drain', onDrain)
  }

  private sendReady(ws: WebSocket): void {
    if (ws.readyState === WebSocket.OPEN) ws.send(Buffer.from([2]), { binary: true })
  }

  private closeSide(side: Side | undefined): void {
    if (side === undefined || side.ws.readyState === WebSocket.CLOSED) return
    try { side.ws.close(4001, 'CONNECTION_FAILED') } catch { /* already closing */ }
  }
}

function toBuffer(data: Buffer | ArrayBuffer | Buffer[]): Buffer {
  if (Buffer.isBuffer(data)) return data
  if (Array.isArray(data)) return Buffer.concat(data)
  return Buffer.from(data)
}
