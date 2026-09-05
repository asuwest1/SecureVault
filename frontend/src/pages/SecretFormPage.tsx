import { useState, type FormEvent } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { foldersApi, secretsApi, type FolderNode, type SecretDetail } from '@/api'

const inputClass = 'w-full rounded border border-input p-2 bg-background'
function flatten(nodes: FolderNode[], prefix = ''): { id: string; label: string }[] {
  return nodes.flatMap(n => [{ id: n.id, label: prefix + n.name }, ...flatten(n.children, prefix + n.name + ' / ')])
}
export function SecretFormPage() {
  const { id } = useParams()
  const folders = useQuery({ queryKey: ['folders'], queryFn: () => foldersApi.list() })
  const secret = useQuery({ queryKey: ['secret', id], queryFn: () => secretsApi.get(id!), enabled: !!id })
  if (folders.isLoading || (id && secret.isLoading)) return <p className="p-6">Loading...</p>
  if (folders.isError || (id && !secret.data)) return <p className="p-6">Unable to load this form. <Link to="/">Back to vault</Link></p>
  return <SecretForm key={id ?? 'new'} secret={secret.data} folders={flatten(folders.data ?? [])} />
}
function SecretForm({ secret, folders }: { secret?: SecretDetail; folders: { id: string; label: string }[] }) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)
  const save = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    setSaving(true)
    setError('')
    const data = Object.fromEntries(form.entries())
    const value = String(data.value)
    const payload = { ...data, value: secret && !value ? undefined : value,
      tags: String(data.tags).split(',').map(t => t.trim()).filter(Boolean) }
    try {
      const result = secret ? await secretsApi.update(secret.id, payload) : await secretsApi.create(payload)
      await queryClient.invalidateQueries({ queryKey: ['secrets'] })
      await queryClient.invalidateQueries({ queryKey: ['secret', result.id] })
      navigate(`/secrets/${result.id}`)
    } catch { setError('Unable to save. Check the fields and your folder permissions.') }
    finally { setSaving(false) }
  }
  return <main className="max-w-2xl mx-auto p-6">
    <Link to={secret ? `/secrets/${secret.id}` : '/'}>← Cancel</Link>
    <h1 className="text-2xl font-semibold my-4">{secret ? 'Edit secret' : 'New secret'}</h1>
    {error && <p role="alert" className="text-destructive mb-4">{error}</p>}
    <form onSubmit={save} className="space-y-4" autoComplete="off">
      <label className="block">Name<input name="name" required maxLength={255} defaultValue={secret?.name} className={inputClass} /></label>
      <label className="block">Folder<select name="folderId" required defaultValue={secret?.folderId ?? ''} className={inputClass}>
        <option value="" disabled>Select a folder</option>{folders.map(f => <option key={f.id} value={f.id}>{f.label}</option>)}
      </select></label>
      <label className="block">Type<select name="type" defaultValue={secret?.type ?? 'Password'} className={inputClass}>
        {['Password', 'ApiKey', 'Certificate', 'SshKey', 'Note'].map(t => <option key={t}>{t}</option>)}
      </select></label>
      <label className="block">{secret ? 'New value (leave blank to keep current value)' : 'Value'}<textarea name="value" required={!secret} rows={3} className={inputClass} /></label>
      <label className="block">Username<input name="username" defaultValue={secret?.username} className={inputClass} /></label>
      <label className="block">URL<input name="url" type="url" defaultValue={secret?.url} className={inputClass} /></label>
      <label className="block">Notes<textarea name="notes" rows={3} defaultValue={secret?.notes} className={inputClass} /></label>
      <label className="block">Tags (comma separated)<input name="tags" defaultValue={secret?.tags.join(', ')} className={inputClass} /></label>
      <button disabled={saving} className="px-4 py-2 rounded bg-primary text-primary-foreground">{saving ? 'Saving...' : 'Save secret'}</button>
    </form>
  </main>
}
