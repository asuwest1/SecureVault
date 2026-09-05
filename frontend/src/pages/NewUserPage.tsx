import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { usersApi } from '@/api'

export function NewUserPage() {
  const navigate = useNavigate()
  const cache = useQueryClient()
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)
  const save = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    setSaving(true)
    try {
      await usersApi.create({ username: form.get('username'), email: form.get('email'), password: form.get('password'), isSuperAdmin: form.has('admin') })
      await cache.invalidateQueries({ queryKey: ['users'] })
      navigate('/admin/users')
    } catch { setError('Unable to create user. Check that the username and email are unique and the password is at least 12 characters.') }
    finally { setSaving(false) }
  }
  return <main className="max-w-lg mx-auto p-6">
    <Link to="/admin/users">← Users</Link><h1 className="text-2xl my-4">New user</h1>
    {error && <p role="alert" className="text-destructive">{error}</p>}
    <form onSubmit={save} className="space-y-4">
      <label className="block">Username<input name="username" required maxLength={100} className="w-full border rounded p-2" /></label>
      <label className="block">Email<input name="email" type="email" required className="w-full border rounded p-2" /></label>
      <label className="block">Password<input name="password" type="password" autoComplete="new-password" required minLength={12} className="w-full border rounded p-2" /></label>
      <label className="block"><input name="admin" type="checkbox" /> Super administrator</label>
      <button disabled={saving} className="px-4 py-2 bg-primary text-primary-foreground rounded">{saving ? 'Creating...' : 'Create user'}</button>
    </form>
  </main>
}
