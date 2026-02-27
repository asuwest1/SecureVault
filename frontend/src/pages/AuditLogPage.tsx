import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ArrowLeft, Download } from 'lucide-react'
import { auditApi } from '@/api'

export function AuditLogPage() {
  const [page, setPage] = useState(1)

  const { data, isLoading } = useQuery({
    queryKey: ['audit', page],
    queryFn: () => auditApi.list({ page, pageSize: 100 }),
  })

  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-6xl mx-auto p-6">
        <div className="flex items-center gap-3 mb-6">
          <Link to="/" className="text-muted-foreground hover:text-foreground">
            <ArrowLeft size={20} />
          </Link>
          <h1 className="text-xl font-semibold">Audit Log</h1>
          <div className="ml-auto">
            <a
              href={auditApi.exportUrl()}
              download
              className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-border
                         text-sm hover:bg-accent"
            >
              <Download size={14} /> Export CSV
            </a>
          </div>
        </div>

        {isLoading ? (
          <div className="text-center text-muted-foreground py-8">Loading...</div>
        ) : (
          <div className="rounded-lg border border-border overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-muted">
                  <tr>
                    <th className="px-4 py-2 text-left font-medium text-muted-foreground">Time</th>
                    <th className="px-4 py-2 text-left font-medium text-muted-foreground">Action</th>
                    <th className="px-4 py-2 text-left font-medium text-muted-foreground">Actor</th>
                    <th className="px-4 py-2 text-left font-medium text-muted-foreground">Target</th>
                    <th className="px-4 py-2 text-left font-medium text-muted-foreground">IP</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {(data?.items as Array<{
                    id: number
                    eventTime: string
                    action: string
                    actorUsername?: string
                    targetType?: string
                    targetId?: string
                    ipAddress?: string
                  }>)?.map((entry) => (
                    <tr key={entry.id} className="hover:bg-muted/50">
                      <td className="px-4 py-2 font-mono text-xs text-muted-foreground whitespace-nowrap">
                        {new Date(entry.eventTime).toLocaleString()}
                      </td>
                      <td className="px-4 py-2">
                        <span className="text-xs bg-secondary px-1.5 py-0.5 rounded">
                          {entry.action}
                        </span>
                      </td>
                      <td className="px-4 py-2 text-xs">{entry.actorUsername ?? '—'}</td>
                      <td className="px-4 py-2 text-xs text-muted-foreground">
                        {entry.targetType ? `${entry.targetType} ${entry.targetId?.slice(0, 8)}...` : '—'}
                      </td>
                      <td className="px-4 py-2 font-mono text-xs text-muted-foreground">
                        {entry.ipAddress ?? '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {data && (data as {totalCount?: number}).totalCount && (data as {totalCount: number}).totalCount > 100 && (
              <div className="flex items-center justify-between p-4 border-t border-border">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="px-3 py-1 text-sm border border-border rounded hover:bg-accent disabled:opacity-50"
                >
                  Previous
                </button>
                <span className="text-sm text-muted-foreground">Page {page}</span>
                <button
                  onClick={() => setPage((p) => p + 1)}
                  className="px-3 py-1 text-sm border border-border rounded hover:bg-accent"
                >
                  Next
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
