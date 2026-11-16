import { createHash, createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { accountDeviceDescriptorSchema, type AccountDeviceDescriptor } from '@dsh-remote/protocol'
import { z } from 'zod'

export class ApiError extends Error {
  constructor(readonly code: string, readonly status = 400) { super(code) }
}
export const hash = (value: string): string => createHash('sha256').update(value).digest('hex')
export const secret = (): string => randomBytes(32).toString('base64url')
export const equal = (left: string, right: string): boolean => timingSafeEqual(Buffer.from(hash(left)), Buffer.from(hash(right)))

/** Login names are case-insensitive. The stored display string is what membership hashes. */
export function accountKey(name: string): string {
  return name.trim().toLowerCase()
}

const MAX_DEVICES_PER_ACCOUNT = 256
const MAX_TOKENS_PER_ACCOUNT = 16384
const MAX_ACCOUNTS = 128

const tokenCoreSchema = z.object({
  kind: z.enum(['access', 'refresh']), deviceId: z.string(), expires: z.number(), used: z.boolean(),
  recovery: z.object({ nonce: z.string().regex(/^[A-Za-z0-9_-]{43}$/), accessExpires: z.number().int().positive() }).optional(),
})
const tokenSchema = tokenCoreSchema.extend({ accountKey: z.string().min(1).max(254) })
const savedDeviceSchema = z.object({ descriptor: accountDeviceDescriptorSchema, revoked: z.boolean(), lastSeenAt: z.number() })
const accountSchema = z.object({
  account: z.string().min(1).max(254),
  salt: z.string(),
  verifier: z.string(),
  devices: z.record(z.string(), savedDeviceSchema),
})
const stateV1Schema = z.object({
  version: z.literal(1),
  account: z.string().min(1).max(254),
  salt: z.string(),
  verifier: z.string(),
  devices: z.record(z.string(), savedDeviceSchema),
  tokens: z.record(z.string(), tokenCoreSchema),
})
const stateSchema = z.object({
  version: z.literal(2),
  accounts: z.record(z.string(), accountSchema),
  tokens: z.record(z.string(), tokenSchema),
})
type SavedDevice = z.infer<typeof savedDeviceSchema>
type SavedToken = z.infer<typeof tokenSchema>
type State = z.infer<typeof stateSchema>

// Domain-separated HMACs keyed by the presented bearer, NOT its stored digest.
// The nonce alone cannot recover credentials from a copy of state.json.
function successor(token: string, nonce: string, deviceId: string) {
  const derive = (kind: string) => createHmac('sha256', token)
    .update(JSON.stringify(['ds-harness-remote/refresh/v1', deviceId, nonce, kind])).digest('base64url')
  return { accessToken: derive('access'), refreshToken: derive('refresh') }
}

function migrateV1(raw: unknown): State {
  const v1 = stateV1Schema.parse(raw)
  const key = accountKey(v1.account)
  if (!key) throw new Error('Invalid stored account.')
  const tokens: State['tokens'] = {}
  for (const [id, token] of Object.entries(v1.tokens)) tokens[id] = { ...token, accountKey: key }
  return {
    version: 2,
    accounts: {
      [key]: { account: v1.account.trim(), salt: v1.salt, verifier: v1.verifier, devices: v1.devices },
    },
    tokens,
  }
}

function loadState(file: string): State | undefined {
  if (!existsSync(file)) return undefined
  const raw = JSON.parse(readFileSync(file, 'utf8')) as { version?: unknown }
  if (raw?.version === 1) return migrateV1(raw)
  return stateSchema.parse(raw)
}

/** Single-process store. Only token digests and public identities reach disk. */
export class Store {
  private state: State
  /** Seed account used by direct store calls and by DSH_SERVER_ACCOUNT. */
  readonly seedKey: string
  onInvalidate: (accountKey: string, deviceId: string) => void = () => {}
  private readonly dummySalt = secret()
  private readonly dummyVerifier: string
  constructor(private readonly file: string, account: string, password: string) {
    this.dummyVerifier = scryptSync('unused-login-padding', this.dummySalt, 32).toString('hex')
    this.seedKey = accountKey(account)
    if (!this.seedKey) throw new Error('DSH_SERVER_ACCOUNT is required.')
    this.state = loadState(file) ?? { version: 2, accounts: {}, tokens: {} }
    this.upsertSeed(account.trim(), password)
    this.save()
  }
  private save(): void {
    mkdirSync(dirname(this.file), { recursive: true, mode: 0o700 })
    const tmp = `${this.file}.tmp`
    writeFileSync(tmp, JSON.stringify(this.state), { mode: 0o600 })
    renameSync(tmp, this.file)
  }
  private upsertSeed(display: string, password: string): void {
    const existing = this.state.accounts[this.seedKey]
    if (!existing) {
      const salt = secret()
      this.state.accounts[this.seedKey] = {
        account: display, salt, verifier: scryptSync(password, salt, 32).toString('hex'), devices: {},
      }
      return
    }
    const verifier = scryptSync(password, existing.salt, 32).toString('hex')
    if (equal(existing.verifier, verifier)) return
    existing.verifier = verifier
    for (const [key, value] of Object.entries(this.state.tokens)) {
      if (value.accountKey === this.seedKey) delete this.state.tokens[key]
    }
  }
  private record(key: string) {
    const account = Object.hasOwn(this.state.accounts, key) ? this.state.accounts[key] : undefined
    if (!account) throw new ApiError('DEVICE_NOT_FOUND', 404)
    return account
  }
  /** Stable membership id for one account. Distinct accounts never share it. */
  membershipId(key: string): string {
    return `account:${hash(this.record(key).account).slice(0, 16)}`
  }
  displayName(key: string): string {
    return this.record(key).account
  }
  login(email: string, password: string): { accountKey: string; account: string } {
    const key = accountKey(email)
    const account = key ? this.state.accounts[key] : undefined
    if (!account) {
      equal(scryptSync(password, this.dummySalt, 32).toString('hex'), this.dummyVerifier)
      throw new ApiError('AUTH_INVALID', 401)
    }
    const verifier = scryptSync(password, account.salt, 32).toString('hex')
    if (!equal(verifier, account.verifier)) throw new ApiError('AUTH_INVALID', 401)
    return { accountKey: key, account: account.account }
  }
  registerAccount(email: string, password: string): { accountKey: string; account: string } {
    const display = email.trim()
    const key = accountKey(display)
    if (!key || display.length > 254 || password.length < 12 || password.length > 1024) throw new ApiError('INVALID_MESSAGE')
    if (this.state.accounts[key]) throw new ApiError('ACCOUNT_EXISTS', 409)
    if (Object.keys(this.state.accounts).length >= MAX_ACCOUNTS) throw new ApiError('RATE_LIMITED', 429)
    const salt = secret()
    this.state.accounts[key] = {
      account: display, salt, verifier: scryptSync(password, salt, 32).toString('hex'), devices: {},
    }
    this.save()
    return { accountKey: key, account: display }
  }
  get(id: string, key = this.seedKey): SavedDevice {
    const account = this.record(key)
    const d = Object.hasOwn(account.devices, id) ? account.devices[id] : undefined
    if (!d) throw new ApiError('DEVICE_NOT_FOUND', 404)
    if (d.revoked) throw new ApiError('DEVICE_REVOKED', 403)
    return d
  }
  list(key = this.seedKey): SavedDevice[] {
    return Object.values(this.record(key).devices).filter(d => !d.revoked)
  }
  register(descriptor: AccountDeviceDescriptor, key = this.seedKey): ReturnType<Store['issue']> {
    const account = this.record(key)
    const old = account.devices[descriptor.deviceId]
    if (old?.revoked) throw new ApiError('DEVICE_REVOKED', 403)
    if (old && (old.descriptor.identityKey !== descriptor.identityKey || old.descriptor.role !== descriptor.role)) throw new ApiError('PEER_IDENTITY_MISMATCH', 409)
    if (!old && Object.keys(account.devices).length >= MAX_DEVICES_PER_ACCOUNT) throw new ApiError('RATE_LIMITED', 429)
    account.devices[descriptor.deviceId] = { descriptor, revoked: false, lastSeenAt: old?.lastSeenAt ?? 0 }
    this.invalidate(key, descriptor.deviceId)
    return this.issue(key, descriptor.deviceId)
  }
  private tokenCount(key: string, tokens: State['tokens']): number {
    let count = 0
    for (const value of Object.values(tokens)) if (value.accountKey === key) count += 1
    return count
  }
  private issue(key: string, deviceId: string, refreshTokenExpiresAt = Date.now() + 30 * 86400_000, previous?: { token: string; record: SavedToken }) {
    const tokens = { ...this.state.tokens }
    for (const [id, value] of Object.entries(tokens)) if (value.expires <= Date.now()) delete tokens[id]
    if (this.tokenCount(key, tokens) + 2 > MAX_TOKENS_PER_ACCOUNT) throw new ApiError('RATE_LIMITED', 429)
    const accessTokenExpiresAt = Date.now() + 60 * 60_000
    const nonce = secret()
    const { accessToken, refreshToken } = previous
      ? successor(previous.token, nonce, deviceId)
      : { accessToken: secret(), refreshToken: secret() }
    if (previous) tokens[hash(previous.token)] = {
      ...previous.record, used: true, recovery: { nonce, accessExpires: accessTokenExpiresAt },
    }
    tokens[hash(accessToken)] = { kind: 'access', deviceId, accountKey: key, expires: accessTokenExpiresAt, used: false }
    tokens[hash(refreshToken)] = { kind: 'refresh', deviceId, accountKey: key, expires: refreshTokenExpiresAt, used: false }
    const before = this.state.tokens
    this.state.tokens = tokens
    // Commit consumption, recovery metadata and the successor together. A failed
    // write must leave the previous token usable both in memory and after restart.
    try { this.save() } catch (error) { this.state.tokens = before; throw error }
    return { accessToken, refreshToken, accessTokenExpiresAt, refreshTokenExpiresAt }
  }
  authenticate(token: string): SavedDevice & { accountKey: string } {
    const record = this.state.tokens[hash(token)]
    if (!record || record.kind !== 'access') throw new ApiError('AUTH_INVALID', 401)
    if (record.expires <= Date.now()) throw new ApiError('TOKEN_EXPIRED', 401)
    return { ...this.get(record.deviceId, record.accountKey), accountKey: record.accountKey }
  }
  refresh(deviceId: string, token: string) {
    const record = this.state.tokens[hash(token)]
    if (!record || record.kind !== 'refresh' || record.deviceId !== deviceId) throw new ApiError('AUTH_INVALID', 401)
    this.get(deviceId, record.accountKey)
    if (record.expires <= Date.now()) throw new ApiError('TOKEN_EXPIRED', 401)
    if (!record.used) return this.issue(record.accountKey, deviceId, record.expires, { token, record })
    // Legacy consumed tokens have no recovery record. Reject them without
    // invalidating credentials that may already be in use by this device.
    if (!record.recovery) throw new ApiError('AUTH_INVALID', 401)
    const pair = successor(token, record.recovery.nonce, deviceId)
    const next = this.state.tokens[hash(pair.refreshToken)]
    if (!next || next.kind !== 'refresh' || next.accountKey !== record.accountKey || next.deviceId !== deviceId || next.expires !== record.expires) {
      throw new ApiError('INTERNAL_ERROR', 503)
    }
    if (next.used) throw new ApiError('AUTH_INVALID', 401)
    const access = this.state.tokens[hash(pair.accessToken)]
    if (access ? access.kind !== 'access' || access.accountKey !== record.accountKey || access.deviceId !== deviceId || access.expires !== record.recovery.accessExpires
      : record.recovery.accessExpires > Date.now()) throw new ApiError('INTERNAL_ERROR', 503)
    // Return the original expiry, including an expired access bearer. The
    // recovered, still-valid refresh token can then rotate normally.
    return { ...pair, accessTokenExpiresAt: record.recovery.accessExpires, refreshTokenExpiresAt: next.expires }
  }
  invalidate(key: string, deviceId: string): void {
    for (const [id, value] of Object.entries(this.state.tokens)) {
      if (value.accountKey === key && value.deviceId === deviceId) delete this.state.tokens[id]
    }
    this.onInvalidate(key, deviceId)
    this.save()
  }
  revoke(id: string, key = this.seedKey): void { this.get(id, key).revoked = true; this.invalidate(key, id) }
  rename(id: string, name: string, key = this.seedKey): void {
    this.get(id, key).descriptor.name = name
    this.save()
  }
  touch(key: string, id: string, clientVersion?: string, harnessVersion?: string): void {
    const d = this.get(id, key)
    d.lastSeenAt = Date.now()
    if (clientVersion) d.descriptor.clientVersion = clientVersion.slice(0, 64)
    if (d.descriptor.role === 'host' && harnessVersion) d.descriptor.harnessVersion = harnessVersion.slice(0, 64)
    this.save()
  }
}
