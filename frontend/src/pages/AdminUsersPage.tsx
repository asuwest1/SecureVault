import { Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Plus, UserX, UserCheck } from 'lucide-react'
import { usersApi } from '@/api'

interface UserResponse {
  id: string
  username: string
  email: string
  isActive: boolean
  isSuperAdmin: boolean
  isLdapUser: boolean
  mfaEnabled: boolean
  createdAt: string
  roleIds: string[]
}

export function AdminUsersPage() {
  const queryClient = useQueryClient()

  const { data: users, isLoading } = useQuery({
    queryKey: ['users'],
    queryFn: () => usersApi.list() as Promise<UserResponse[]>,
  })

  const toggleActiveMutation = useMutation({
    mutationFn: ({ id, isActive }: { id: string; isActive: boolean }) =>
      usersApi.update(id, { isActive }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }),
  })

  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-5xl mx-auto p-6">
        <div className="flex items-center gap-3 mb-6">
          <Link to="/" className="text-muted-foreground hover:text-foreground">
            <ArrowLeft size={20} />
          </Link>
          <h1 className="text-xl font-semibold">User Management</h1>
          <div className="ml-auto">
            <Link to="/admin/users/new"
              className="flex items-center gap-1.5 px-3 py-1.5 bg-primary text-primary-foreground
                         rounded text-sm font-medium hover:bg-primary/90">
              <Plus size={14} /> New User
            </Link>
          </div>
        </div>

        {isLoading ? (
          <div className="text-center text-muted-foreground py-8">Loading...</div>
        ) : (
          <div className="rounded-lg border border-border overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-muted">
                <tr>
                  <th className="px-4 py-3 text-left font-medium text-muted-foreground">Username</th>
                  <th className="px-4 py-3 text-left font-medium text-muted-foreground">Email</th>
                  <th className="px-4 py-3 text-left font-medium text-muted-foreground">Status</th>
                  <th className="px-4 py-3 text-left font-medium text-muted-foreground">Roles</th>
                  <th className="px-4 py-3 text-left font-medium text-muted-foreground">Auth</th>
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {users?.map((user) => (
                  <tr key={user.id} className="hover:bg-muted/50">
                    <td className="px-4 py-3 font-medium">
                      {user.username}
                      {user.isSuperAdmin && (
                        <span className="ml-1.5 text-xs bg-amber-100 text-amber-800 px-1 rounded">
                          admin
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-muted-foreground">{user.email}</td>
                    <td className="px-4 py-3">
                      <span className={`text-xs px-2 py-0.5 rounded-full ${
                        user.isActive
                          ? 'bg-green-100 text-green-800'
                          : 'bg-red-100 text-red-800'
                      }`}>
                        {user.isActive ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-muted-foreground text-xs">
                      {user.roleIds.length} role{user.roleIds.length !== 1 ? 's' : ''}
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">
                      {user.isLdapUser ? 'LDAP' : 'Local'}
                      {user.mfaEnabled && ' + MFA'}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => toggleActiveMutation.mutate({
                          id: user.id,
                          isActive: !user.isActive
                        })}
                        className="text-muted-foreground hover:text-foreground"
                        title={user.isActive ? 'Deactivate' : 'Activate'}
                      >
                        {user.isActive ? <UserX size={16} /> : <UserCheck size={16} />}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
