import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Search, Plus, LogOut, Shield, Users, FileText } from 'lucide-react'
import { secretsApi, foldersApi } from '@/api'
import { useAuth } from '@/hooks/useAuth'

export function VaultPage() {
  const { username, isSuperAdmin, logout } = useAuth()
  const [search, setSearch] = useState('')
  const [selectedFolder, setSelectedFolder] = useState<string | undefined>()

  const { data: folders } = useQuery({
    queryKey: ['folders'],
    queryFn: () => foldersApi.list(),
  })

  const { data: secrets, isLoading } = useQuery({
    queryKey: ['secrets', search, selectedFolder],
    queryFn: () => secretsApi.list({
      query: search || undefined,
      folderId: selectedFolder,
    }),
    staleTime: 10_000,
  })

  return (
    <div className="min-h-screen bg-background flex">
      {/* Sidebar */}
      <aside className="w-64 border-r border-border bg-card flex flex-col">
        <div className="p-4 border-b border-border">
          <div className="flex items-center gap-2">
            <Shield size={20} className="text-primary" />
            <span className="font-semibold">SecureVault</span>
          </div>
          <p className="text-xs text-muted-foreground mt-1">Welcome, {username}</p>
        </div>

        <nav className="flex-1 p-2 overflow-y-auto">
          <div className="text-xs font-medium text-muted-foreground px-2 py-1 mb-1">FOLDERS</div>
          <button
            onClick={() => setSelectedFolder(undefined)}
            className={`w-full text-left px-2 py-1.5 rounded text-sm hover:bg-accent ${!selectedFolder ? 'bg-accent' : ''}`}
          >
            All Secrets
          </button>
          {folders?.map((folder) => (
            <button
              key={folder.id}
              onClick={() => setSelectedFolder(folder.id)}
              className={`w-full text-left px-2 py-1.5 rounded text-sm hover:bg-accent ${
                selectedFolder === folder.id ? 'bg-accent' : ''
              }`}
            >
              {folder.name}
            </button>
          ))}
        </nav>

        {isSuperAdmin && (
          <div className="p-2 border-t border-border space-y-1">
            <div className="text-xs font-medium text-muted-foreground px-2 py-1">ADMIN</div>
            <Link to="/admin/users"
              className="flex items-center gap-2 px-2 py-1.5 rounded text-sm hover:bg-accent">
              <Users size={14} /> Users
            </Link>
            <Link to="/audit"
              className="flex items-center gap-2 px-2 py-1.5 rounded text-sm hover:bg-accent">
              <FileText size={14} /> Audit Log
            </Link>
          </div>
        )}

        <div className="p-2 border-t border-border">
          <button
            onClick={() => logout()}
            className="flex items-center gap-2 w-full px-2 py-1.5 rounded text-sm
                       text-muted-foreground hover:text-foreground hover:bg-accent"
          >
            <LogOut size={14} /> Sign Out
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 flex flex-col">
        <header className="border-b border-border p-4 flex items-center gap-4">
          <div className="relative flex-1 max-w-md">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <input
              type="search"
              placeholder="Search secrets..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-2 border border-input rounded-md text-sm
                         focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </div>
          <Link to="/secrets/new"
            className="flex items-center gap-1.5 px-3 py-2 bg-primary text-primary-foreground
                       rounded-md text-sm font-medium hover:bg-primary/90">
            <Plus size={14} /> New Secret
          </Link>
        </header>

        <div className="flex-1 p-4 overflow-y-auto">
          {isLoading ? (
            <div className="text-center text-muted-foreground py-8">Loading...</div>
          ) : secrets?.items.length === 0 ? (
            <div className="text-center text-muted-foreground py-8">
              No secrets found. Create your first secret.
            </div>
          ) : (
            <div className="space-y-2">
              {secrets?.items.map((secret) => (
                <Link
                  key={secret.id}
                  to={`/secrets/${secret.id}`}
                  className="block p-4 rounded-lg border border-border hover:border-primary/50
                             hover:bg-accent/50 transition-colors"
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <h3 className="font-medium text-sm">{secret.name}</h3>
                      {secret.username && (
                        <p className="text-xs text-muted-foreground mt-0.5">{secret.username}</p>
                      )}
                      {secret.url && (
                        <p className="text-xs text-muted-foreground truncate max-w-xs">{secret.url}</p>
                      )}
                    </div>
                    <div className="flex flex-col items-end gap-1">
                      <span className="text-xs bg-secondary text-secondary-foreground px-2 py-0.5 rounded">
                        {secret.type}
                      </span>
                      {secret.tags.map((tag) => (
                        <span key={tag} className="text-xs text-muted-foreground">#{tag}</span>
                      ))}
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  )
}
