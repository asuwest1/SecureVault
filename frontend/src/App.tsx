import { useEffect, type ReactNode } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from '@/hooks/useAuth'
import { useIdleTimeout } from '@/hooks/useIdleTimeout'
import { LoginPage } from '@/pages/LoginPage'
import { VaultPage } from '@/pages/VaultPage'
import { SecretDetailPage } from '@/pages/SecretDetailPage'
import { AuditLogPage } from '@/pages/AuditLogPage'
import { AdminUsersPage } from '@/pages/AdminUsersPage'
import { FirstRunPage } from '@/pages/FirstRunPage'
import { NotFoundPage } from '@/pages/NotFoundPage'

function RequireAuth({ children }: { children: ReactNode }) {
  const { isAuthenticated } = useAuth()
  if (!isAuthenticated) return <Navigate to="/login" replace />
  return <>{children}</>
}

function RequireSuperAdmin({ children }: { children: ReactNode }) {
  const { isSuperAdmin } = useAuth()
  if (!isSuperAdmin) return <Navigate to="/" replace />
  return <>{children}</>
}

export default function App() {
  const { isAuthenticated, silentRefresh, logout } = useAuth()

  // Attempt silent refresh on mount (restore session after page refresh)
  useEffect(() => {
    if (!isAuthenticated) {
      silentRefresh()
    }
  }, [isAuthenticated, silentRefresh])

  // Idle timeout: 15 minutes → auto logout
  useIdleTimeout(
    () => {
      if (isAuthenticated) {
        logout()
      }
    },
    15 * 60 * 1000
  )

  return (
    <Routes>
      <Route path="/setup" element={<FirstRunPage />} />
      <Route path="/login" element={<LoginPage />} />

      <Route path="/" element={
        <RequireAuth>
          <VaultPage />
        </RequireAuth>
      } />

      <Route path="/secrets/:id" element={
        <RequireAuth>
          <SecretDetailPage />
        </RequireAuth>
      } />

      <Route path="/audit" element={
        <RequireAuth>
          <RequireSuperAdmin>
            <AuditLogPage />
          </RequireSuperAdmin>
        </RequireAuth>
      } />

      <Route path="/admin/users" element={
        <RequireAuth>
          <RequireSuperAdmin>
            <AdminUsersPage />
          </RequireSuperAdmin>
        </RequireAuth>
      } />

      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  )
}
