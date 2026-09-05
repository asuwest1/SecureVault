import { useEffect, useState, type ReactNode } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from '@/hooks/useAuth'
import { useIdleTimeout } from '@/hooks/useIdleTimeout'
import { LoginPage } from '@/pages/LoginPage'
import { VaultPage } from '@/pages/VaultPage'
import { SecretDetailPage } from '@/pages/SecretDetailPage'
import { AuditLogPage } from '@/pages/AuditLogPage'
import { AdminUsersPage } from '@/pages/AdminUsersPage'
import { FirstRunPage } from '@/pages/FirstRunPage'
import { SecretFormPage } from '@/pages/SecretFormPage'
import { AccountSecurityPage } from '@/pages/AccountSecurityPage'
import { NewUserPage } from '@/pages/NewUserPage'
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

  const [restoring, setRestoring] = useState(true)
  useEffect(() => {
    void silentRefresh().finally(() => setRestoring(false))
  }, [silentRefresh])

  // Idle timeout: 15 minutes → auto logout
  useIdleTimeout(
    () => {
      if (isAuthenticated) {
        logout()
      }
    },
    15 * 60 * 1000
  )

  if (restoring) return <p className="p-6">Restoring session...</p>

  return (
    <Routes>
      <Route path="/setup" element={<FirstRunPage />} />
      <Route path="/login" element={<LoginPage />} />

      <Route path="/" element={
        <RequireAuth>
          <VaultPage />
        </RequireAuth>
      } />

      <Route path="/secrets/new" element={<RequireAuth><SecretFormPage key="new" /></RequireAuth>} />
      <Route path="/secrets/:id/edit" element={<RequireAuth><SecretFormPage /></RequireAuth>} />
      <Route path="/account/security" element={<RequireAuth><AccountSecurityPage /></RequireAuth>} />
      <Route path="/admin/users/new" element={<RequireAuth><RequireSuperAdmin><NewUserPage /></RequireSuperAdmin></RequireAuth>} />
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
