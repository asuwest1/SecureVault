import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { apiRequest } from '@/api'
import { decodeJwtPayload, useAuthStore } from '@/stores/authStore'

interface Token { id: string; name: string; isRevoked: boolean; expiresAt?: string }
export function AccountSecurityPage() {
  const userId = useAuthStore(s => s.userId)
  const cache = useQueryClient()
  const [uri, setUri] = useState('')
  const [code, setCode] = useState('')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const profile = useQuery({ queryKey: ['profile', userId], queryFn: () => apiRequest<{ mfaEnabled: boolean }>(`/users/${userId}`) })
  const tokens = useQuery({ queryKey: ['api-tokens', userId], queryFn: () => apiRequest<Token[]>(`/users/${userId}/api-tokens`) })
  const setup = async () => {
    setBusy(true)
    try { setUri((await apiRequest<{ otpAuthUri: string }>('/auth/mfa/setup', { method: 'POST' })).otpAuthUri) }
    catch { setMessage('Unable to start MFA setup.') }
    finally { setBusy(false) }
  }
  const enable = async () => {
    setBusy(true)
    try {
      const result = await apiRequest<{ accessToken: string }>('/auth/mfa/enable', { method: 'POST', body: JSON.stringify({ code }) })
      const payload = decodeJwtPayload(result.accessToken)
      if (!payload) throw new Error('Invalid token')
      useAuthStore.getState().setAuth(result.accessToken, payload)
      setUri(''); setCode(''); setMessage('MFA enabled. Other sessions have been signed out.')
      await cache.invalidateQueries({ queryKey: ['profile', userId] })
    } catch { setMessage('Unable to enable MFA. Check the code and try again.') }
    finally { setBusy(false) }
  }
  const revoke = async (id: string) => {
    setBusy(true)
    try { await apiRequest(`/users/${userId}/api-tokens/${id}`, { method: 'DELETE' }); await cache.invalidateQueries({ queryKey: ['api-tokens', userId] }) }
    catch { setMessage('Unable to revoke token.') }
    finally { setBusy(false) }
  }
  return <main className="max-w-xl mx-auto p-6 space-y-4">
    <Link to="/">← Vault</Link><h1 className="text-2xl">Account security</h1>
    {message && <p role="status">{message}</p>}
    <h2 className="text-lg font-semibold">Authenticator app</h2>
    {profile.isError && <p role="alert">Unable to load MFA status.</p>}
    {profile.data?.mfaEnabled ? <p>MFA is enabled.</p> : profile.data && !uri && <button disabled={busy} onClick={setup} className="border rounded p-2">Set up MFA</button>}
    {uri && <div className="space-y-3">
      <p>Add an account manually in your authenticator app. Choose a time-based code and enter this setup key:</p>
      <code className="block break-all p-3 bg-muted">{new URL(uri).searchParams.get('secret')}</code>
      <p>Keep this key private. Store it securely if you need a recovery copy.</p>
      <label className="block">6-digit code<input value={code} onChange={e => setCode(e.target.value)} inputMode="numeric" maxLength={6} autoComplete="one-time-code" className="block border p-2" /></label>
      <button disabled={busy || !/^\d{6}$/.test(code)} onClick={enable} className="border rounded p-2">Enable MFA</button>
    </div>}
    <h2 className="text-lg font-semibold">API tokens</h2>
    {tokens.isError && <p role="alert">Unable to load tokens.</p>}
    {tokens.data?.length === 0 && <p>No API tokens.</p>}
    {tokens.data?.map(t => <div key={t.id} className="flex justify-between border rounded p-3">
      <span>{t.name}{t.isRevoked ? ' — revoked' : ''}</span>
      {!t.isRevoked && <button disabled={busy} onClick={() => revoke(t.id)}>Revoke</button>}
    </div>)}
  </main>
}
