import { sha256Hex } from './sha256.js'

const MAX_RELAY2_CIPHERTEXT_BYTES = 1024 * 1024

/** Offered in hello by clients that can use the binary relay socket. */
export const RELAY2_CAPABILITY = 'transport.relay2'

const ATTACH = 1
const READY = 2
const DATA = 3

export interface Relay2Attach {
  ticket: string
  connectionId: string
  deviceId: string
}

export type Relay2Frame =
  | { type: 'attach'; ticket: string; connectionId: string; deviceId: string }
  | { type: 'ready' }
  | { type: 'data'; counter: number; ciphertext: Uint8Array }

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

export function encodeRelay2Attach(attach: Relay2Attach): Uint8Array {
  const body = textEncoder.encode(JSON.stringify({
    ticket: attach.ticket,
    connectionId: attach.connectionId,
    deviceId: attach.deviceId,
  }))
  if (body.byteLength > 4096) throw new Error('Relay2 attach is too large.')
  const frame = new Uint8Array(1 + body.byteLength)
  frame[0] = ATTACH
  frame.set(body, 1)
  return frame
}

export function encodeRelay2Ready(): Uint8Array {
  return Uint8Array.of(READY)
}

export function encodeRelay2Data(counter: number, ciphertext: Uint8Array): Uint8Array {
  if (!Number.isSafeInteger(counter) || counter < 0 || counter > 0xffffffff) {
    throw new Error('Relay2 counter is out of range.')
  }
  if (ciphertext.byteLength > MAX_RELAY2_CIPHERTEXT_BYTES) throw new Error('Relay2 frame is too large.')
  const frame = new Uint8Array(5 + ciphertext.byteLength)
  frame[0] = DATA
  new DataView(frame.buffer).setUint32(1, counter)
  frame.set(ciphertext, 5)
  return frame
}

export function decodeRelay2Frame(data: Uint8Array): Relay2Frame {
  if (data.byteLength < 1) throw new Error('Relay2 frame is empty.')
  const type = data[0]
  if (type === READY) {
    if (data.byteLength !== 1) throw new Error('Relay2 ready frame is malformed.')
    return { type: 'ready' }
  }
  if (type === ATTACH) {
    let parsed: unknown
    try {
      parsed = JSON.parse(textDecoder.decode(data.subarray(1)))
    } catch {
      throw new Error('Relay2 attach is malformed.')
    }
    if (typeof parsed !== 'object' || parsed === null) throw new Error('Relay2 attach is malformed.')
    const record = parsed as { ticket?: unknown; connectionId?: unknown; deviceId?: unknown }
    if (typeof record.ticket !== 'string' || record.ticket.length < 16 || record.ticket.length > 128) {
      throw new Error('Relay2 attach ticket is malformed.')
    }
    if (typeof record.connectionId !== 'string' || record.connectionId.length < 1 || record.connectionId.length > 128) {
      throw new Error('Relay2 attach connection is malformed.')
    }
    if (typeof record.deviceId !== 'string' || record.deviceId.length < 1 || record.deviceId.length > 128) {
      throw new Error('Relay2 attach device is malformed.')
    }
    return { type: 'attach', ticket: record.ticket, connectionId: record.connectionId, deviceId: record.deviceId }
  }
  if (type === DATA) {
    if (data.byteLength < 5 || data.byteLength > MAX_RELAY2_CIPHERTEXT_BYTES + 5) throw new Error('Relay2 data frame is malformed.')
    return {
      type: 'data',
      counter: new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(1),
      ciphertext: data.subarray(5),
    }
  }
  throw new Error('Relay2 frame type is unknown.')
}

function stableStringify(value: unknown): string {
  if (value === undefined) return 'null'
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null'
  if (Array.isArray(value)) return `[${value.map(item => stableStringify(item)).join(',')}]`
  const record = value as Record<string, unknown>
  const keys = Object.keys(record).filter(key => record[key] !== undefined).sort()
  return `{${keys.map(key => `${JSON.stringify(key)}:${stableStringify(record[key])}`).join(',')}}`
}

/**
 * Identity of the bulky transcript. Projections and the live assistant stream
 * stay off the hash so a permission or token update does not resend history.
 */
export function followSnapshotHash(snapshot: {
  records?: unknown
  header?: unknown
}): string {
  return sha256Hex(textEncoder.encode(stableStringify({
    records: snapshot.records ?? null,
    header: snapshot.header ?? null,
  })))
}

export interface FollowResume {
  hash: string
  cursor: number
}

/** Replace a snapshot the phone already has with a tiny unchanged marker. */
export function resumeFollowSnapshot(snapshot: Record<string, unknown>, resume?: FollowResume): Record<string, unknown> {
  if (snapshot.type !== 'snapshot' || resume === undefined) return snapshot
  if (!Number.isSafeInteger(resume.cursor) || resume.cursor < 0) return snapshot
  if (!/^[a-f0-9]{64}$/.test(resume.hash)) return snapshot
  if (followSnapshotHash(snapshot) !== resume.hash) return snapshot
  return {
    type: 'snapshot',
    unchanged: true,
    cursor: snapshot.cursor,
    hasMore: snapshot.hasMore === true,
    ...(snapshot.projections === undefined ? {} : { projections: snapshot.projections }),
    ...(snapshot.header === undefined ? {} : { header: snapshot.header }),
    ...(snapshot.assistantStream === undefined ? {} : { assistantStream: snapshot.assistantStream }),
  }
}
