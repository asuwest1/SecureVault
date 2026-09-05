import { sessionSignal } from '@/session'
import { useAuthStore, decodeJwtPayload } from '@/stores/authStore'

const API_BASE = '/api/v1'

class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly data?: unknown,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

let isRefreshing = false
let refreshPromise: Promise<boolean> | null = null

/**
 * Silent token refresh via HttpOnly cookie.
 * Returns true if successful.
 * Exported so useAuth hook can delegate to this single implementation.
 */
export async function silentRefresh(): Promise<boolean> {
  if (isRefreshing && refreshPromise) return refreshPromise

  isRefreshing = true
  const signal = sessionSignal()
  refreshPromise = (async () => {
    try {
      const res = await fetch(`${API_BASE}/auth/refresh`, {
        method: 'POST',
        signal,
        credentials: 'include',  // Required for HttpOnly cookie
      })

      if (signal.aborted) return false
      if (!res.ok) {
        useAuthStore.getState().clearAuth()
        return false
      }

      const data = await res.json()
      if (signal.aborted) return false
      const payload = decodeJwtPayload(data.accessToken)
      if (payload) {
        useAuthStore.getState().setAuth(data.accessToken, payload)
      }
      return !!payload
    } catch {
      if (signal.aborted) return false
      useAuthStore.getState().clearAuth()
      return false
    } finally {
      isRefreshing = false
      refreshPromise = null
    }
  })()

  return refreshPromise
}

/**
 * Typed fetch wrapper with automatic silent refresh on 401.
 * Always sends credentials: 'include' for HttpOnly cookie.
 */
export async function apiRequest<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const { accessToken, userId } = useAuthStore.getState()
  const signal = sessionSignal()

  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
    ...options.headers,
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    signal,
    credentials: 'include',  // Always include for HttpOnly refresh cookie
    headers,
  })

  if (signal.aborted) throw new DOMException('Session changed', 'AbortError')

  // Silent refresh on 401 — retry once
  if (response.status === 401 && !['/auth/login', '/auth/mfa/verify'].includes(path)) {
    const refreshed = await silentRefresh()
    if (!refreshed) throw new ApiError(401, 'Session expired. Please log in again.')

    const { accessToken: newToken, userId: refreshedUserId } = useAuthStore.getState()
    if (userId && userId !== refreshedUserId) throw new DOMException('Account changed', 'AbortError')
    const retryResponse = await fetch(`${API_BASE}${path}`, {
      ...options,
      signal: sessionSignal(),
      credentials: 'include',
      headers: {
        ...headers,
        Authorization: `Bearer ${newToken}`,
      },
    })

    if (!retryResponse.ok) {
      const errorData = await retryResponse.json().catch(() => null)
      throw new ApiError(retryResponse.status, `Request failed: ${retryResponse.status}`, errorData)
    }

    return readResponse<T>(retryResponse)
  }

  if (!response.ok) {
    const errorData = await response.json().catch(() => null)
    throw new ApiError(response.status, `Request failed: ${response.status}`, errorData)
  }

  // Handle 204 No Content
  if (response.status === 204) return undefined as T

  return readResponse<T>(response)
}

async function readResponse<T>(response: Response): Promise<T> {
  if (response.status === 204) return undefined as T
  const body = await response.text()
  return body ? JSON.parse(body) as T : undefined as T
}

// ─────────────────────────────────────────────────────────────────────────────
// Auth API
// ─────────────────────────────────────────────────────────────────────────────

export const authApi = {
  login: (username: string, password: string) =>
    apiRequest<{
      accessToken: string
      expiresAt: string
      mfaRequired: boolean
      mfaToken?: string
    }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

  verifyMfa: (mfaToken: string, code: string) =>
    apiRequest<{ accessToken: string; expiresAt: string }>('/auth/mfa/verify', {
      method: 'POST',
      body: JSON.stringify({ mfaToken, code }),
    }),

  logout: () =>
    apiRequest<void>('/auth/logout', { method: 'POST' }),

  refresh: () =>
    fetch(`${API_BASE}/auth/refresh`, { method: 'POST', credentials: 'include' }),
}

// ─────────────────────────────────────────────────────────────────────────────
// Secrets API
// ─────────────────────────────────────────────────────────────────────────────

export interface SecretSummary {
  id: string
  name: string
  type: string
  folderId: string
  username?: string
  url?: string
  tags: string[]
  createdAt: string
  updatedAt: string
}

export interface SecretDetail extends SecretSummary {
  notes?: string
  createdByUserId: string
}

export const secretsApi = {
  list: (params?: Record<string, string | number | undefined>) => {
    const qs = params
      ? '?' + new URLSearchParams(
          Object.entries(params)
            .filter(([, v]) => v !== undefined)
            .map(([k, v]) => [k, String(v)])
        ).toString()
      : ''
    return apiRequest<{ items: SecretSummary[]; totalCount: number }>(`/secrets${qs}`)
  },

  get: (id: string) =>
    apiRequest<SecretDetail>(`/secrets/${id}`),

  getValue: (id: string) =>
    apiRequest<{ value: string }>(`/secrets/${id}/value`),

  create: (data: Record<string, unknown>) =>
    apiRequest<SecretDetail>('/secrets', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  update: (id: string, data: Record<string, unknown>) =>
    apiRequest<SecretDetail>(`/secrets/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  delete: (id: string) =>
    apiRequest<void>(`/secrets/${id}`, { method: 'DELETE' }),

  getVersions: (id: string) =>
    apiRequest<Array<{ id: string; versionNumber: number; createdAt: string }>>(`/secrets/${id}/versions`),
}

// ─────────────────────────────────────────────────────────────────────────────
// Folders API
// ─────────────────────────────────────────────────────────────────────────────

export interface FolderNode {
  id: string
  name: string
  parentFolderId?: string
  depth: number
  createdAt: string
  children: FolderNode[]
}

export const foldersApi = {
  list: () => apiRequest<FolderNode[]>('/folders'),
  get: (id: string) => apiRequest<FolderNode>(`/folders/${id}`),
  create: (data: { name: string; parentFolderId?: string }) =>
    apiRequest<FolderNode>('/folders', { method: 'POST', body: JSON.stringify(data) }),
  update: (id: string, data: { name: string }) =>
    apiRequest<FolderNode>(`/folders/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  delete: (id: string) =>
    apiRequest<void>(`/folders/${id}`, { method: 'DELETE' }),
}

// ─────────────────────────────────────────────────────────────────────────────
// Users API
// ─────────────────────────────────────────────────────────────────────────────

export const usersApi = {
  list: () => apiRequest<unknown[]>('/users'),
  get: (id: string) => apiRequest<unknown>(`/users/${id}`),
  create: (data: Record<string, unknown>) =>
    apiRequest<unknown>('/users', { method: 'POST', body: JSON.stringify(data) }),
  update: (id: string, data: Record<string, unknown>) =>
    apiRequest<unknown>(`/users/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  delete: (id: string) =>
    apiRequest<void>(`/users/${id}`, { method: 'DELETE' }),
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit API
// ─────────────────────────────────────────────────────────────────────────────

export const auditApi = {
  list: (params?: Record<string, string | number | undefined>) => {
    const qs = params
      ? '?' + new URLSearchParams(
          Object.entries(params)
            .filter(([, v]) => v !== undefined)
            .map(([k, v]) => [k, String(v)])
        ).toString()
      : ''
    return apiRequest<{ items: unknown[]; totalCount: number }>(`/audit${qs}`)
  },

  /**
   * Streams the audit log as CSV and triggers a browser download.
   * Uses the in-memory bearer token via apiRequest's auth flow — a plain
   * <a href> cannot attach the token, so the server would reject it with 401.
   */
  downloadCsv: async (filename = 'audit-log.csv'): Promise<void> => {
    const { accessToken, userId } = useAuthStore.getState()
    const signal = sessionSignal()
    const res = await fetch(`${API_BASE}/audit/export`, {
      signal,
      credentials: 'include',
      headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
    })

    if (signal.aborted) throw new DOMException('Session changed', 'AbortError')
    if (res.status === 401) {
      const refreshed = await silentRefresh()
      if (!refreshed) throw new ApiError(401, 'Session expired. Please log in again.')
      const { accessToken: newToken, userId: refreshedUserId } = useAuthStore.getState()
      if (userId !== refreshedUserId) throw new DOMException('Account changed', 'AbortError')
      const retry = await fetch(`${API_BASE}/audit/export`, {
        signal: sessionSignal(),
        credentials: 'include',
        headers: newToken ? { Authorization: `Bearer ${newToken}` } : {},
      })
      if (!retry.ok) throw new ApiError(retry.status, `Export failed: ${retry.status}`)
      return triggerDownload(await retry.blob(), filename)
    }

    if (!res.ok) throw new ApiError(res.status, `Export failed: ${res.status}`)
    return triggerDownload(await res.blob(), filename)
  },
}

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}
