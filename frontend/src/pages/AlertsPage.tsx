import { useEffect, useState } from 'react'
import { Bell, CheckCircle2, Trash2, RefreshCw, AlertOctagon, Loader2 } from 'lucide-react'
import { Card, CardHeader, CardContent } from '@/components/ui/card'
import { Badge, attackVariant, severityVariant } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table'
import { apiGet, apiPost, apiDelete } from '@/api/client'
import { formatDate } from '@/lib/utils'

interface AuthState { token: string; user: { id: number; email: string; role: string; organization_id: number } }

// Match real API response field names
interface Alert {
  _id: string
  alert_type: string
  severity: string
  source_ip: string
  destination_ip: string
  confidence: number
  description: string
  acknowledged: boolean          // API uses 'acknowledged' not 'is_acknowledged'
  acknowledged_by?: number | null
  acknowledged_at?: string | null
  timestamp: string              // API uses 'timestamp' not 'created_at'
}

const SEVERITIES = ['all', 'critical', 'high', 'medium', 'low'] as const
type SeverityFilter = (typeof SEVERITIES)[number]

export function AlertsPage({ auth }: { auth: AuthState }) {
  const [alerts, setAlerts]       = useState<Alert[]>([])
  const [total, setTotal]         = useState(0)
  const [loading, setLoading]     = useState(true)
  const [severity, setSeverity]   = useState<SeverityFilter>('all')
  const [search, setSearch]       = useState('')
  const [page, setPage]           = useState(0)
  const [ackingId, setAckingId]   = useState<string | null>(null)
  const [deletingId, setDeletingId] = useState<string | null>(null)
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null)
  const [feedback, setFeedback]   = useState<{ id: string; type: 'ack' | 'del'; ok: boolean } | null>(null)
  const limit = 15

  async function loadAlerts() {
    setLoading(true)
    try {
      const params = new URLSearchParams({ limit: String(limit), offset: String(page * limit) })
      if (severity !== 'all') params.set('severity', severity)
      const res = await apiGet<{ data: Alert[]; total: number }>(`/api/v1/alerts?${params}`, auth.token)
      setAlerts(res.data ?? [])
      setTotal(res.total ?? 0)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadAlerts() }, [severity, page])

  function showFeedback(id: string, type: 'ack' | 'del', ok: boolean) {
    setFeedback({ id, type, ok })
    setTimeout(() => setFeedback(null), 2000)
  }

  async function acknowledge(id: string) {
    setAckingId(id)
    try {
      await apiPost(`/api/v1/alerts/${id}/acknowledge`, {}, auth.token)
      setAlerts(prev => prev.map(a => a._id === id ? { ...a, acknowledged: true } : a))
      showFeedback(id, 'ack', true)
    } catch {
      showFeedback(id, 'ack', false)
    } finally {
      setAckingId(null)
    }
  }

  async function deleteAlert(id: string) {
    setDeletingId(id)
    setConfirmDeleteId(null)
    try {
      await apiDelete(`/api/v1/alerts/${id}`, auth.token)
      setAlerts(prev => prev.filter(a => a._id !== id))
      setTotal(t => t - 1)
      showFeedback(id, 'del', true)
    } catch {
      showFeedback(id, 'del', false)
    } finally {
      setDeletingId(null)
    }
  }

  const filtered = search
    ? alerts.filter(a =>
        a.source_ip?.includes(search) ||
        a.destination_ip?.includes(search) ||
        a.alert_type?.includes(search) ||
        a.description?.toLowerCase().includes(search.toLowerCase()),
      )
    : alerts

  const totalPages = Math.ceil(total / limit)

  return (
    <div className="flex flex-col h-full overflow-auto bg-slate-950 cyber-grid">

      {/* ── Delete confirmation modal ─────────────────────────── */}
      {confirmDeleteId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="rounded-xl border border-red-500/40 bg-slate-900 p-6 shadow-2xl w-80">
            <div className="flex items-center gap-2 mb-3">
              <Trash2 className="h-5 w-5 text-red-400" />
              <h3 className="font-semibold text-slate-100">Delete Alert?</h3>
            </div>
            <p className="text-sm text-slate-400 mb-5">
              This action cannot be undone. The alert will be permanently removed.
            </p>
            <div className="flex gap-2 justify-end">
              <Button variant="outline" size="sm" onClick={() => setConfirmDeleteId(null)}>
                Cancel
              </Button>
              <Button
                size="sm"
                className="bg-red-600 hover:bg-red-700 text-white"
                onClick={() => deleteAlert(confirmDeleteId)}
              >
                Delete
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* ── Header ───────────────────────────────────────────── */}
      <div className="sticky top-0 z-10 border-b border-slate-800/60 bg-slate-950/80 backdrop-blur-sm px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Bell className="h-5 w-5 text-amber-400" />
          <div>
            <h1 className="text-lg font-semibold text-slate-100">Alerts</h1>
            <p className="text-xs text-slate-500">{total} total alerts</p>
          </div>
        </div>
        <Button variant="ghost" size="sm" onClick={loadAlerts}>
          <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
        </Button>
      </div>

      <div className="flex-1 p-6 space-y-4">
        {/* ── Filters ──────────────────────────────────────────── */}
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <Input
            placeholder="Search by IP, type, description…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="max-w-sm"
          />
          <div className="flex gap-1.5 flex-wrap">
            {SEVERITIES.map((s) => (
              <button
                key={s}
                onClick={() => { setSeverity(s); setPage(0) }}
                className={`rounded-full border px-3 py-1 text-xs font-medium capitalize transition-all ${
                  severity === s
                    ? 'border-cyan-500/50 bg-cyan-500/15 text-cyan-300'
                    : 'border-slate-700 text-slate-500 hover:border-slate-500 hover:text-slate-300'
                }`}
              >
                {s === 'all' ? 'All' : s}
              </button>
            ))}
          </div>
        </div>

        {/* ── Table ────────────────────────────────────────────── */}
        <Card>
          <CardContent className="px-0 pb-0">
            {loading ? (
              <div className="py-20 text-center">
                <RefreshCw className="mx-auto mb-3 h-6 w-6 animate-spin text-cyan-500" />
                <p className="text-sm text-slate-500">Loading alerts…</p>
              </div>
            ) : filtered.length === 0 ? (
              <div className="py-20 text-center">
                <AlertOctagon className="mx-auto mb-3 h-8 w-8 text-slate-700" />
                <p className="text-sm text-slate-500">No alerts found</p>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Source IP</TableHead>
                    <TableHead>Destination IP</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Confidence</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.map((a) => {
                    const isAcking   = ackingId   === a._id
                    const isDeleting = deletingId === a._id
                    const fb = feedback?.id === a._id ? feedback : null

                    return (
                      <TableRow
                        key={a._id}
                        className={`transition-colors ${
                          isDeleting ? 'opacity-40' :
                          a.severity === 'critical' && !a.acknowledged ? 'bg-red-500/5' : ''
                        }`}
                      >
                        {/* Time */}
                        <TableCell className="font-mono text-xs text-slate-500 whitespace-nowrap">
                          {formatDate(a.timestamp)}
                        </TableCell>

                        {/* Type */}
                        <TableCell>
                          <Badge variant={attackVariant(a.alert_type)}>{a.alert_type}</Badge>
                        </TableCell>

                        {/* IPs */}
                        <TableCell className="font-mono text-xs">{a.source_ip || '—'}</TableCell>
                        <TableCell className="font-mono text-xs">{a.destination_ip || '—'}</TableCell>

                        {/* Severity */}
                        <TableCell>
                          <Badge variant={severityVariant(a.severity)}>{a.severity}</Badge>
                        </TableCell>

                        {/* Confidence bar */}
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <div className="h-1.5 w-16 rounded-full bg-slate-800">
                              <div
                                className="h-1.5 rounded-full bg-cyan-500"
                                style={{ width: `${(a.confidence ?? 0) * 100}%` }}
                              />
                            </div>
                            <span className="text-xs text-slate-500 tabular-nums">
                              {((a.confidence ?? 0) * 100).toFixed(0)}%
                            </span>
                          </div>
                        </TableCell>

                        {/* Status */}
                        <TableCell>
                          {a.acknowledged ? (
                            <span className="flex items-center gap-1 text-xs text-emerald-400">
                              <CheckCircle2 className="h-3 w-3" /> Acknowledged
                            </span>
                          ) : (
                            <span className="text-xs text-amber-400 font-medium">Pending</span>
                          )}
                        </TableCell>

                        {/* Action buttons */}
                        <TableCell>
                          <div className="flex items-center gap-1">

                            {/* Acknowledge button */}
                            {!a.acknowledged && (
                              <button
                                onClick={() => acknowledge(a._id)}
                                disabled={isAcking || isDeleting}
                                title="Acknowledge alert"
                                className={`
                                  flex h-7 w-7 items-center justify-center rounded-lg border transition-all
                                  ${fb?.type === 'ack' && fb.ok
                                    ? 'border-emerald-500/60 bg-emerald-500/20 text-emerald-400'
                                    : 'border-slate-700/50 hover:border-emerald-500/50 hover:bg-emerald-500/10 text-slate-400 hover:text-emerald-400'
                                  }
                                  disabled:opacity-40 disabled:cursor-not-allowed
                                `}
                              >
                                {isAcking
                                  ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                  : <CheckCircle2 className="h-3.5 w-3.5" />
                                }
                              </button>
                            )}

                            {/* Delete button */}
                            <button
                              onClick={() => setConfirmDeleteId(a._id)}
                              disabled={isDeleting || isAcking}
                              title="Delete alert"
                              className={`
                                flex h-7 w-7 items-center justify-center rounded-lg border transition-all
                                ${fb?.type === 'del' && !fb.ok
                                  ? 'border-red-500/60 bg-red-500/20 text-red-400'
                                  : 'border-slate-700/50 hover:border-red-500/50 hover:bg-red-500/10 text-slate-400 hover:text-red-400'
                                }
                                disabled:opacity-40 disabled:cursor-not-allowed
                              `}
                            >
                              {isDeleting
                                ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                : <Trash2 className="h-3.5 w-3.5" />
                              }
                            </button>

                          </div>
                        </TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </Table>
            )}
          </CardContent>

          {/* Pagination */}
          {totalPages > 1 && (
            <CardHeader>
              <div className="flex items-center justify-between">
                <p className="text-xs text-slate-500">
                  Page {page + 1} of {totalPages} · {total} total
                </p>
                <div className="flex gap-1">
                  <Button variant="outline" size="sm" onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}>
                    Prev
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1}>
                    Next
                  </Button>
                </div>
              </div>
            </CardHeader>
          )}
        </Card>
      </div>
    </div>
  )
}
