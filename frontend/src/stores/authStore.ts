import { create } from 'zustand'

// Access token stored in module-scope memory ONLY.
// Never localStorage, never sessionStorage.
// Page refresh clears the token — silent refresh via HttpOnly cookie.

interface AuthState {
  accessToken: string | null
  userId: string | null
  username: string | null
  isSuperAdmin: boolean
  roleIds: string[]
  expiresAt: Date | null

  setAuth: (token: string, payload: JwtPayload) => void
  clearAuth: () => void
  isAuthenticated: () => boolean
}

interface JwtPayload {
  sub: string
  name: string
  is_super_admin: string
  role_ids: string | string[]
  exp: number
}

export const useAuthStore = create<AuthState>((set, get) => ({
  accessToken: null,
  userId: null,
  username: null,
  isSuperAdmin: false,
  roleIds: [],
  expiresAt: null,

  setAuth: (token: string, payload: JwtPayload) => {
    set({
      accessToken: token,
      userId: payload.sub,
      username: payload.name,
      isSuperAdmin: payload.is_super_admin === 'true',
      roleIds: Array.isArray(payload.role_ids)
        ? payload.role_ids
        : payload.role_ids
          ? [payload.role_ids]
          : [],
      expiresAt: new Date(payload.exp * 1000),
    })
  },

  clearAuth: () => {
    set({
      accessToken: null,
      userId: null,
      username: null,
      isSuperAdmin: false,
      roleIds: [],
      expiresAt: null,
    })
  },

  isAuthenticated: () => {
    const { accessToken, expiresAt } = get()
    return !!accessToken && !!expiresAt && expiresAt > new Date()
  },
}))

/** Decodes a JWT payload without verification (verification is done server-side). */
export function decodeJwtPayload(token: string): JwtPayload | null {
  try {
    const [, payloadB64] = token.split('.')
    const json = atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/'))
    return JSON.parse(json) as JwtPayload
  } catch {
    return null
  }
}
