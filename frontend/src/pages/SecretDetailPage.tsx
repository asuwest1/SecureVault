import { useState } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Trash2, Edit2 } from 'lucide-react'
import { secretsApi } from '@/api'
import { RevealButton } from '@/components/vault/RevealButton'

export function SecretDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [error, setError] = useState<string | null>(null)

  const { data: secret, isLoading } = useQuery({
    queryKey: ['secret', id],
    queryFn: () => secretsApi.get(id!),
    enabled: !!id,
  })

  const deleteMutation = useMutation({
    mutationFn: () => secretsApi.delete(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['secrets'] })
      navigate('/')
    },
    onError: () => setError('Failed to delete secret.'),
  })

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <p className="text-muted-foreground">Loading...</p>
      </div>
    )
  }

  if (!secret) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <p className="text-muted-foreground">Secret not found.</p>
          <Link to="/" className="text-primary text-sm hover:underline mt-2 block">
            Back to vault
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-2xl mx-auto p-6">
        <div className="flex items-center gap-3 mb-6">
          <Link to="/" className="text-muted-foreground hover:text-foreground">
            <ArrowLeft size={20} />
          </Link>
          <h1 className="text-xl font-semibold">{secret.name}</h1>
          <div className="ml-auto flex gap-2">
            <Link
              to={`/secrets/${id}/edit`}
              className="flex items-center gap-1 px-3 py-1.5 rounded text-sm
                         border border-border hover:bg-accent"
            >
              <Edit2 size={14} /> Edit
            </Link>
            <button
              onClick={() => {
                if (confirm('Delete this secret? It will be recoverable for 30 days.')) {
                  deleteMutation.mutate()
                }
              }}
              className="flex items-center gap-1 px-3 py-1.5 rounded text-sm
                         border border-destructive text-destructive hover:bg-destructive/10"
            >
              <Trash2 size={14} /> Delete
            </button>
          </div>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded bg-destructive/10 text-destructive text-sm" role="alert">
            {error}
          </div>
        )}

        <div className="rounded-lg border border-border overflow-hidden">
          <dl className="divide-y divide-border">
            <div className="px-4 py-3 flex items-center justify-between">
              <dt className="text-sm font-medium text-muted-foreground w-32">Type</dt>
              <dd className="text-sm">{secret.type}</dd>
            </div>

            {secret.username && (
              <div className="px-4 py-3 flex items-center justify-between">
                <dt className="text-sm font-medium text-muted-foreground w-32">Username</dt>
                <dd className="text-sm font-mono">{secret.username}</dd>
              </div>
            )}

            {secret.url && (
              <div className="px-4 py-3 flex items-center justify-between">
                <dt className="text-sm font-medium text-muted-foreground w-32">URL</dt>
                <dd className="text-sm">
                  <a href={secret.url} target="_blank" rel="noopener noreferrer"
                     className="text-primary hover:underline truncate max-w-xs block">
                    {secret.url}
                  </a>
                </dd>
              </div>
            )}

            <div className="px-4 py-3 flex items-center justify-between">
              <dt className="text-sm font-medium text-muted-foreground w-32">Value</dt>
              <dd>
                <RevealButton
                  secretId={id!}
                  onError={(msg) => setError(msg)}
                />
              </dd>
            </div>

            {secret.notes && (
              <div className="px-4 py-3">
                <dt className="text-sm font-medium text-muted-foreground mb-2">Notes</dt>
                <dd className="text-sm text-muted-foreground whitespace-pre-wrap">{secret.notes}</dd>
              </div>
            )}

            {secret.tags.length > 0 && (
              <div className="px-4 py-3 flex items-center justify-between">
                <dt className="text-sm font-medium text-muted-foreground w-32">Tags</dt>
                <dd className="flex flex-wrap gap-1">
                  {secret.tags.map((tag) => (
                    <span key={tag}
                          className="px-2 py-0.5 bg-secondary text-secondary-foreground
                                     rounded-full text-xs">
                      #{tag}
                    </span>
                  ))}
                </dd>
              </div>
            )}

            <div className="px-4 py-3 flex items-center justify-between">
              <dt className="text-sm font-medium text-muted-foreground w-32">Created</dt>
              <dd className="text-sm text-muted-foreground">
                {new Date(secret.createdAt).toLocaleString()}
              </dd>
            </div>

            <div className="px-4 py-3 flex items-center justify-between">
              <dt className="text-sm font-medium text-muted-foreground w-32">Updated</dt>
              <dd className="text-sm text-muted-foreground">
                {new Date(secret.updatedAt).toLocaleString()}
              </dd>
            </div>
          </dl>
        </div>
      </div>
    </div>
  )
}
