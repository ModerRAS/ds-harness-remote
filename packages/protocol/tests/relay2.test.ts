import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { decodeRelay2Frame, encodeRelay2Attach, encodeRelay2Data, encodeRelay2Ready, followSnapshotHash, resumeFollowSnapshot } from '../src/index.js'
import { sha256 } from '../src/sha256.js'

describe('relay2', () => {
  it('matches node sha256', () => {
    const samples = [new Uint8Array(), new TextEncoder().encode('abc'), crypto.getRandomValues(new Uint8Array(1000))]
    for (const sample of samples) {
      expect(Buffer.from(sha256(sample)).toString('hex')).toBe(createHash('sha256').update(sample).digest('hex'))
    }
  })

  it('round-trips attach, ready and data frames', () => {
    const attach = encodeRelay2Attach({ ticket: 'a'.repeat(32), connectionId: 'connection-1', deviceId: 'device-1' })
    expect(decodeRelay2Frame(attach)).toEqual({ type: 'attach', ticket: 'a'.repeat(32), connectionId: 'connection-1', deviceId: 'device-1' })
    expect(decodeRelay2Frame(encodeRelay2Ready())).toEqual({ type: 'ready' })
    const body = new Uint8Array([1, 2, 3, 9])
    const data = decodeRelay2Frame(encodeRelay2Data(7, body))
    expect(data).toMatchObject({ type: 'data', counter: 7 })
    if (data.type === 'data') expect(data.ciphertext).toEqual(body)
  })

  it('replaces an unchanged follow snapshot and keeps a changed one', () => {
    const snapshot = { type: 'snapshot', cursor: 4, hasMore: false, records: [{ seq: 4, text: '你好' }], projections: { values: { inbox: [] } } }
    const hash = followSnapshotHash(snapshot)
    expect(resumeFollowSnapshot(snapshot, { hash, cursor: 4 })).toEqual({
      type: 'snapshot', unchanged: true, cursor: 4, hasMore: false,
      projections: { values: { inbox: [] } },
    })
    expect(resumeFollowSnapshot({ ...snapshot, cursor: 9, projections: { values: { inbox: [1] } } }, { hash, cursor: 4 })).toEqual({
      type: 'snapshot', unchanged: true, cursor: 9, hasMore: false,
      projections: { values: { inbox: [1] } },
    })
    expect(resumeFollowSnapshot({ ...snapshot, records: [{ seq: 5 }] }, { hash, cursor: 4 }).unchanged).toBeUndefined()
  })
})
