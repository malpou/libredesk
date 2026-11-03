// metsa fork: sign-in and sign-out through guard, the edge proxy that owns the
// login when the server runs with auth.guard_identity (COR-1084).

export const GUARD_LOGIN_PATH = '/.well-known/bastion/login'
export const GUARD_LOGOUT_PATH = '/.well-known/bastion/logout'

// Whether the server signs agents in from guard's identity.
export const guardIdentityEnabled = (publicConfig) => publicConfig?.['auth.guard_identity'] === true

// Guard's login, returning to next when it is a path on this host.
export const guardLoginURL = (next) => {
  const path = typeof next === 'string' && /^\/(?![/\\])/.test(next) ? next : '/'
  return `${GUARD_LOGIN_PATH}?return_to=${encodeURIComponent(path)}`
}
