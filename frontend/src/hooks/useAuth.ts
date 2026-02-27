import { useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore, decodeJwtPayload } from '@/stores/authStore'
import { authApi, silentRefresh as apiSilentRefresh } from '@/api'

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

  // Delegate to the single silentRefresh implementation in the API module
  // to avoid duplicating token refresh logic.
  const silentRefresh = useCallback(() => apiSilentRefresh(), [])

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
