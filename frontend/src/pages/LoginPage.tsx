import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useAuth } from '@/hooks/useAuth'
import { authApi } from '@/api'
import { decodeJwtPayload, useAuthStore } from '@/stores/authStore'
import { useNavigate } from 'react-router-dom'

const loginSchema = z.object({
  username: z.string().min(1, 'Username is required').max(100),
  password: z.string().min(1, 'Password is required'),
})

const mfaSchema = z.object({
  code: z.string().length(6, 'Code must be 6 digits').regex(/^\d+$/, 'Digits only'),
})

type LoginForm = z.infer<typeof loginSchema>
type MfaForm = z.infer<typeof mfaSchema>

export function LoginPage() {
  const [mfaRequired, setMfaRequired] = useState(false)
  const [mfaToken, setMfaToken] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const { login } = useAuth()
  const store = useAuthStore()
  const navigate = useNavigate()

  const loginForm = useForm<LoginForm>({ resolver: zodResolver(loginSchema) })
  const mfaForm = useForm<MfaForm>({ resolver: zodResolver(mfaSchema) })

  const onLogin = async (data: LoginForm) => {
    setError(null)
    try {
      const result = await login(data.username, data.password)
      if (result.mfaRequired && result.mfaToken) {
        setMfaRequired(true)
        setMfaToken(result.mfaToken)
      }
    } catch {
      setError('Invalid credentials.')
    }
  }

  const onMfaVerify = async (data: MfaForm) => {
    if (!mfaToken) return
    setError(null)
    try {
      const result = await authApi.verifyMfa(mfaToken, data.code)
      const payload = decodeJwtPayload(result.accessToken)
      if (payload) {
        store.setAuth(result.accessToken, payload)
        navigate('/')
      }
    } catch {
      setError('Invalid MFA code.')
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <div className="w-full max-w-sm p-8 rounded-lg border border-border shadow-sm">
        <div className="mb-8 text-center">
          <h1 className="text-2xl font-bold">SecureVault</h1>
          <p className="text-muted-foreground text-sm mt-1">
            {mfaRequired ? 'Enter your MFA code' : 'Sign in to your vault'}
          </p>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded bg-destructive/10 text-destructive text-sm" role="alert">
            {error}
          </div>
        )}

        {!mfaRequired ? (
          <form onSubmit={loginForm.handleSubmit(onLogin)} className="space-y-4">
            <div>
              <label htmlFor="username" className="block text-sm font-medium mb-1">
                Username
              </label>
              <input
                id="username"
                type="text"
                autoComplete="username"
                className="w-full px-3 py-2 border border-input rounded-md text-sm
                           focus:outline-none focus:ring-2 focus:ring-ring"
                {...loginForm.register('username')}
              />
              {loginForm.formState.errors.username && (
                <p className="text-destructive text-xs mt-1">
                  {loginForm.formState.errors.username.message}
                </p>
              )}
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium mb-1">
                Password
              </label>
              <input
                id="password"
                type="password"
                autoComplete="current-password"
                className="w-full px-3 py-2 border border-input rounded-md text-sm
                           focus:outline-none focus:ring-2 focus:ring-ring"
                {...loginForm.register('password')}
              />
              {loginForm.formState.errors.password && (
                <p className="text-destructive text-xs mt-1">
                  {loginForm.formState.errors.password.message}
                </p>
              )}
            </div>

            <button
              type="submit"
              disabled={loginForm.formState.isSubmitting}
              className="w-full py-2 px-4 bg-primary text-primary-foreground rounded-md
                         text-sm font-medium hover:bg-primary/90 disabled:opacity-50
                         focus:outline-none focus:ring-2 focus:ring-ring"
            >
              {loginForm.formState.isSubmitting ? 'Signing in...' : 'Sign In'}
            </button>
          </form>
        ) : (
          <form onSubmit={mfaForm.handleSubmit(onMfaVerify)} className="space-y-4">
            <div>
              <label htmlFor="code" className="block text-sm font-medium mb-1">
                6-digit code
              </label>
              <input
                id="code"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                className="w-full px-3 py-2 border border-input rounded-md text-sm
                           text-center font-mono tracking-widest
                           focus:outline-none focus:ring-2 focus:ring-ring"
                {...mfaForm.register('code')}
              />
              {mfaForm.formState.errors.code && (
                <p className="text-destructive text-xs mt-1 text-center">
                  {mfaForm.formState.errors.code.message}
                </p>
              )}
            </div>

            <button
              type="submit"
              disabled={mfaForm.formState.isSubmitting}
              className="w-full py-2 px-4 bg-primary text-primary-foreground rounded-md
                         text-sm font-medium hover:bg-primary/90 disabled:opacity-50"
            >
              {mfaForm.formState.isSubmitting ? 'Verifying...' : 'Verify'}
            </button>

            <button
              type="button"
              onClick={() => { setMfaRequired(false); setMfaToken(null) }}
              className="w-full text-sm text-muted-foreground hover:underline"
            >
              Back to login
            </button>
          </form>
        )}
      </div>
    </div>
  )
}
