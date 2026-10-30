import { describe, expect, it } from 'vitest'
import { GUARD_LOGOUT_PATH, guardIdentityEnabled, guardLoginURL } from './guard-auth'

describe('guardIdentityEnabled', () => {
  it('is on only when the server says so', () => {
    expect(guardIdentityEnabled({ 'auth.guard_identity': true })).toBe(true)
    expect(guardIdentityEnabled({ 'auth.guard_identity': false })).toBe(false)
    expect(guardIdentityEnabled({})).toBe(false)
    expect(guardIdentityEnabled(undefined)).toBe(false)
  })
})

describe('guardLoginURL', () => {
  it('returns to the requested path', () => {
    expect(guardLoginURL('/inboxes/assigned?x=1')).toBe(
      '/.well-known/bastion/login?return_to=%2Finboxes%2Fassigned%3Fx%3D1'
    )
  })

  it.each([undefined, '', 'inboxes', '//evil.test/', '/\\evil.test', 'https://evil.test/'])(
    'returns to / for %s',
    (next) => {
      expect(guardLoginURL(next)).toBe('/.well-known/bastion/login?return_to=%2F')
    }
  )

  it('signs out on the same host', () => {
    expect(GUARD_LOGOUT_PATH).toBe('/.well-known/bastion/logout')
  })
})
