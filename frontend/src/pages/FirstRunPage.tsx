import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Shield, CheckCircle } from 'lucide-react'
import { useNavigate } from 'react-router-dom'

const initSchema = z.object({
  adminUsername: z.string().min(3).max(100),
  adminEmail: z.string().email(),
  adminPassword: z.string()
    .min(12, 'At least 12 characters')
    .regex(/[A-Z]/, 'Must contain uppercase')
    .regex(/[a-z]/, 'Must contain lowercase')
    .regex(/[0-9]/, 'Must contain digit')
    .regex(/[^A-Za-z0-9]/, 'Must contain special character'),
  confirmPassword: z.string(),
}).refine((d) => d.adminPassword === d.confirmPassword, {
  message: "Passwords don't match",
  path: ['confirmPassword'],
})

type InitForm = z.infer<typeof initSchema>

const STEPS = ['Welcome', 'Credentials', 'Review', 'Done']

export function FirstRunPage() {
  const [step, setStep] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const navigate = useNavigate()

  const form = useForm<InitForm>({
    resolver: zodResolver(initSchema),
  })

  const onSubmit = async (data: InitForm) => {
    setIsSubmitting(true)
    setError(null)
    try {
      const res = await fetch('/api/v1/setup/initialize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          adminUsername: data.adminUsername,
          adminEmail: data.adminEmail,
          adminPassword: data.adminPassword,
        }),
      })

      if (!res.ok) {
        const err = await res.json()
        throw new Error(err.error ?? 'Initialization failed')
      }

      setStep(3)  // Success step
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Initialization failed')
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <div className="min-h-screen bg-background flex items-center justify-center">
      <div className="w-full max-w-lg p-8">
        <div className="text-center mb-8">
          <Shield size={48} className="mx-auto text-primary mb-3" />
          <h1 className="text-2xl font-bold">SecureVault Setup</h1>
          <p className="text-muted-foreground text-sm mt-1">
            First-time configuration wizard
          </p>
        </div>

        {/* Step indicator */}
        <div className="flex items-center justify-between mb-8">
          {STEPS.map((s, i) => (
            <div key={s} className="flex items-center">
              <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-medium
                ${i <= step ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground'}`}>
                {i < step ? '✓' : i + 1}
              </div>
              {i < STEPS.length - 1 && (
                <div className={`h-0.5 w-12 mx-1 ${i < step ? 'bg-primary' : 'bg-muted'}`} />
              )}
            </div>
          ))}
        </div>

        {error && (
          <div className="mb-4 p-3 rounded bg-destructive/10 text-destructive text-sm" role="alert">
            {error}
          </div>
        )}

        {step === 0 && (
          <div className="space-y-4">
            <h2 className="text-lg font-semibold">Welcome to SecureVault</h2>
            <p className="text-sm text-muted-foreground">
              This wizard creates the initial Super Admin account.
            </p>
            <div className="p-4 bg-amber-50 border border-amber-200 rounded text-sm text-amber-800">
              <strong>Prerequisite:</strong> The Master Encryption Key and JWT
              signing key must already be provisioned by your operator (see
              the installation guide). They are loaded by the application at
              startup and are not configured here.
            </div>
            <button
              onClick={() => setStep(1)}
              className="w-full py-2 px-4 bg-primary text-primary-foreground rounded font-medium
                         hover:bg-primary/90"
            >
              Begin Setup
            </button>
          </div>
        )}

        {step === 1 && (
          <form className="space-y-4">
            <h2 className="text-lg font-semibold">Administrator Account</h2>
            <div>
              <label className="block text-sm font-medium mb-1">Username</label>
              <input type="text" className="w-full px-3 py-2 border border-input rounded text-sm"
                     {...form.register('adminUsername')} />
              {form.formState.errors.adminUsername && (
                <p className="text-destructive text-xs mt-1">
                  {form.formState.errors.adminUsername.message}
                </p>
              )}
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Email</label>
              <input type="email" className="w-full px-3 py-2 border border-input rounded text-sm"
                     {...form.register('adminEmail')} />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Password</label>
              <input type="password" className="w-full px-3 py-2 border border-input rounded text-sm"
                     {...form.register('adminPassword')} />
              {form.formState.errors.adminPassword && (
                <p className="text-destructive text-xs mt-1">
                  {form.formState.errors.adminPassword.message}
                </p>
              )}
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Confirm Password</label>
              <input type="password" className="w-full px-3 py-2 border border-input rounded text-sm"
                     {...form.register('confirmPassword')} />
              {form.formState.errors.confirmPassword && (
                <p className="text-destructive text-xs mt-1">
                  {form.formState.errors.confirmPassword.message}
                </p>
              )}
            </div>
            <div className="flex gap-3">
              <button type="button" onClick={() => setStep(0)}
                      className="flex-1 py-2 border border-border rounded text-sm hover:bg-accent">
                Back
              </button>
              <button type="button"
                      onClick={() => form.trigger(['adminUsername', 'adminEmail', 'adminPassword', 'confirmPassword'])
                        .then((valid) => { if (valid) setStep(2) })}
                      className="flex-1 py-2 bg-primary text-primary-foreground rounded text-sm hover:bg-primary/90">
                Next
              </button>
            </div>
          </form>
        )}

        {step === 2 && (
          <div className="space-y-4">
            <h2 className="text-lg font-semibold">Review Configuration</h2>
            <dl className="space-y-2 text-sm">
              <div className="flex justify-between">
                <dt className="text-muted-foreground">Admin Username</dt>
                <dd className="font-medium">{form.getValues('adminUsername')}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-muted-foreground">Admin Email</dt>
                <dd className="font-medium">{form.getValues('adminEmail')}</dd>
              </div>
            </dl>
            <div className="flex gap-3">
              <button onClick={() => setStep(1)}
                      className="flex-1 py-2 border border-border rounded text-sm hover:bg-accent">
                Back
              </button>
              <button
                onClick={form.handleSubmit(onSubmit)}
                disabled={isSubmitting}
                className="flex-1 py-2 bg-primary text-primary-foreground rounded text-sm
                           hover:bg-primary/90 disabled:opacity-50"
              >
                {isSubmitting ? 'Initializing...' : 'Initialize SecureVault'}
              </button>
            </div>
          </div>
        )}

        {step === 3 && (
          <div className="text-center space-y-4">
            <CheckCircle size={48} className="mx-auto text-green-500" />
            <h2 className="text-lg font-semibold">Setup Complete</h2>
            <p className="text-sm text-muted-foreground">
              SecureVault has been initialized successfully.
              You can now sign in with your administrator account.
            </p>
            <button
              onClick={() => navigate('/login')}
              className="w-full py-2 px-4 bg-primary text-primary-foreground rounded font-medium
                         hover:bg-primary/90"
            >
              Sign In
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
