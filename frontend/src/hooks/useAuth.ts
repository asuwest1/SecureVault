import { useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore, decodeJwtPayload } from '@/stores/authStore'
import { authApi } from '@/api'

export function useAuth() {
  const store = useAuthStore()
  const navigate = useNavigate()

  const login = useCallback(async (username: string, password: string) => {
    const result = await authApi.login(username, password)

    if (result.mfaRequired) {
      return { mfaRequired: true, mfaToken: result.mfaToken }
    }

    const payload = decodeJwtPayload(result.accessToken)
    if (!payload) throw new Error('Invalid token received')

    store.setAuth(result.accessToken, payload)
    navigate('/')
    return { mfaRequired: false }
  }, [store, navigate])

  const logout = useCallback(async () => {
    try {
      await authApi.logout()
    } finally {
      store.clearAuth()
      navigate('/login')
    }
  }, [store, navigate])

  const silentRefresh = useCallback(async (): Promise<boolean> => {
    try {
      const res = await authApi.refresh()
      if (!res.ok) {
        store.clearAuth()
        return false
      }
      const data = await res.json()
      const payload = decodeJwtPayload(data.accessToken)
      if (payload) store.setAuth(data.accessToken, payload)
      return true
    } catch {
      store.clearAuth()
      return false
    }
  }, [store])

  return {
    isAuthenticated: store.isAuthenticated(),
    userId: store.userId,
    username: store.username,
    isSuperAdmin: store.isSuperAdmin,
    roleIds: store.roleIds,
    login,
    logout,
    silentRefresh,
  }
}
