import { type FormEvent, useEffect, useState } from 'react'
import { Ban, Shield, Plus, Unlock, RefreshCw, X, Flame, Trash2, Loader2 } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Badge, severityVariant } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table'
import { apiGet, apiPost, apiDelete } from '@/api/client'
import { formatDate } from '@/lib/utils'

interface AuthState { token: string; user: { id: number; email: string; role: string; organization_id: number } }

interface BlockedIP {
  id: number
  ip_address: string
  reason: string
  threat_level: string
  is_active: boolean
  blocked_at: string
  unblock_at: string | null
  is_permanent: boolean
}

interface FirewallRule {
  id: number
  rule_name: string
  source_ip: string | null
  destination_port: number | null
  protocol: string
  action: string
  priority: number
  is_active: boolean
  created_at: string
}

type Tab = 'blocked' | 'rules'

// ── Confirmation modal ──────────────────────────────────────────────────
function ConfirmModal({
  title,
  message,
  confirmLabel = 'Delete',
  onConfirm,
  onCancel,
}: {
  title: string
  message: string
  confirmLabel?: string
  onConfirm: () => void
  onCancel: () => void
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="rounded-xl border border-red-500/40 bg-slate-900 p-6 shadow-2xl w-96">
        <div className="flex items-center gap-2 mb-3">
          <Trash2 className="h-5 w-5 text-red-400" />
          <h3 className="font-semibold text-slate-100">{title}</h3>
        </div>
        <p className="text-sm text-slate-400 mb-5">{message}</p>
        <div className="flex gap-2 justify-end">
          <Button variant="outline" size="sm" onClick={onCancel}>Cancel</Button>
          <Button size="sm" className="bg-red-600 hover:bg-red-700 text-white" onClick={onConfirm}>
            {confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  )
}

export function IPSPage({ auth }: { auth: AuthState }) {
  const [tab, setTab]             = useState<Tab>('blocked')
  const [blockedIPs, setBlockedIPs] = useState<BlockedIP[]>([])
  const [rules, setRules]         = useState<FirewallRule[]>([])
  const [loading, setLoading]     = useState(true)
  const [showForm, setShowForm]   = useState(false)

  // per-row action state
  const [unbockingIP, setUnblockingIP]   = useState<string | null>(null)
  const [deletingIPId, setDeletingIPId]  = useState<number | null>(null)
  const [deletingRuleId, setDeletingRuleId] = useState<number | null>(null)

  // delete-all state
  const [deletingAllIPs, setDeletingAllIPs]     = useState(false)
  const [deletingAllRules, setDeletingAllRules] = useState(false)

  // confirm dialogs
  const [confirmDeleteIPId, setConfirmDeleteIPId]       = useState<number | null>(null)
  const [confirmDeleteRuleId, setConfirmDeleteRuleId]   = useState<number | null>(null)
  const [confirmDeleteAllIPs, setConfirmDeleteAllIPs]   = useState(false)
  const [confirmDeleteAllRules, setConfirmDeleteAllRules] = useState(false)

  // Block IP form
  const [blockIP, setBlockIP]         = useState('')
  const [blockReason, setBlockReason] = useState('')
  const [blockLevel, setBlockLevel]   = useState<'low' | 'medium' | 'high' | 'critical'>('medium')
  const [blockDuration, setBlockDuration] = useState('24')
  const [blocking, setBlocking]       = useState(false)
  const [blockError, setBlockError]   = useState('')
  const [blockSuccess, setBlockSuccess] = useState('')

  async function loadBlocked() {
    setLoading(true)
    try {
      const res = await apiGet<{ data: BlockedIP[] }>('/api/v1/ips/blocked-ips', auth.token)
      setBlockedIPs(res.data ?? [])
    } finally {
      setLoading(false)
    }
  }

  async function loadRules() {
    setLoading(true)
    try {
      const res = await apiGet<{ data: FirewallRule[] }>('/api/v1/ips/firewall-rules', auth.token)
      setRules(res.data ?? [])
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (tab === 'blocked') loadBlocked()
    else loadRules()
  }, [tab])

  async function handleBlock(e: FormEvent) {
    e.preventDefault()
    setBlockError('')
    setBlockSuccess('')
    setBlocking(true)
    try {
      await apiPost('/api/v1/ips/block-ip', {
        ip_address: blockIP,
        reason: blockReason || 'Manual block',
        threat_level: blockLevel,
        duration_hours: parseInt(blockDuration) || 24,
      }, auth.token)
      setBlockSuccess(`IP ${blockIP} blocked successfully`)
      setBlockIP('')
      setBlockReason('')
      await loadBlocked()
    } catch (err) {
      setBlockError(err instanceof Error ? err.message : 'Failed to block IP')
    } finally {
      setBlocking(false)
    }
  }

  async function unblock(ip: string) {
    setUnblockingIP(ip)
    try {
      // Route is POST /ips/unblock-ip/:ip_address
      await apiPost(`/api/v1/ips/unblock-ip/${encodeURIComponent(ip)}`, {}, auth.token)
      setBlockedIPs(prev => prev.filter(b => b.ip_address !== ip))
    } catch { /* ignore */ } finally {
      setUnblockingIP(null)
    }
  }

  async function deleteBlockedIP(id: number) {
    setConfirmDeleteIPId(null)
    setDeletingIPId(id)
    try {
      await apiDelete(`/api/v1/ips/blocked-ips/${id}`, auth.token)
      setBlockedIPs(prev => prev.filter(b => b.id !== id))
    } catch { /* ignore */ } finally {
      setDeletingIPId(null)
    }
  }

  async function deleteAllBlockedIPs() {
    setConfirmDeleteAllIPs(false)
    setDeletingAllIPs(true)
    try {
      await apiDelete('/api/v1/ips/blocked-ips', auth.token)
      setBlockedIPs([])
    } catch { /* ignore */ } finally {
      setDeletingAllIPs(false)
    }
  }

  async function deleteRule(id: number) {
    setConfirmDeleteRuleId(null)
    setDeletingRuleId(id)
    try {
      await apiDelete(`/api/v1/ips/firewall-rules/${id}`, auth.token)
      setRules(prev => prev.filter(r => r.id !== id))
    } catch { /* ignore */ } finally {
      setDeletingRuleId(null)
    }
  }

  async function deleteAllRules() {
    setConfirmDeleteAllRules(false)
    setDeletingAllRules(true)
    try {
      await apiDelete('/api/v1/ips/firewall-rules', auth.token)
      setRules([])
    } catch { /* ignore */ } finally {
      setDeletingAllRules(false)
    }
  }

  const tabs = [
    { id: 'blocked' as Tab, label: 'Blocked IPs',    icon: Ban,    count: blockedIPs.length },
    { id: 'rules'   as Tab, label: 'Firewall Rules',  icon: Shield, count: rules.filter(r => r.is_active).length },
  ]

  return (
    <div className="flex flex-col h-full overflow-auto bg-slate-950 cyber-grid">

      {/* ── Confirm modals ─────────────────────────────────────────── */}
      {confirmDeleteIPId !== null && (
        <ConfirmModal
          title="Delete Blocked IP?"
          message="This record will be permanently removed from the block list."
          onConfirm={() => deleteBlockedIP(confirmDeleteIPId)}
          onCancel={() => setConfirmDeleteIPId(null)}
        />
      )}
      {confirmDeleteRuleId !== null && (
        <ConfirmModal
          title="Delete Firewall Rule?"
          message="This firewall rule will be permanently deleted."
          onConfirm={() => deleteRule(confirmDeleteRuleId)}
          onCancel={() => setConfirmDeleteRuleId(null)}
        />
      )}
      {confirmDeleteAllIPs && (
        <ConfirmModal
          title="Delete ALL Blocked IPs?"
          message={`All ${blockedIPs.length} blocked IP records will be permanently removed. This cannot be undone.`}
          confirmLabel="Delete All"
          onConfirm={deleteAllBlockedIPs}
          onCancel={() => setConfirmDeleteAllIPs(false)}
        />
      )}
      {confirmDeleteAllRules && (
        <ConfirmModal
          title="Delete ALL Firewall Rules?"
          message={`All ${rules.length} firewall rules will be permanently deleted. This cannot be undone.`}
          confirmLabel="Delete All"
          onConfirm={deleteAllRules}
          onCancel={() => setConfirmDeleteAllRules(false)}
        />
      )}

      {/* ── Header ─────────────────────────────────────────────────── */}
      <div className="sticky top-0 z-10 border-b border-slate-800/60 bg-slate-950/80 backdrop-blur-sm px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Flame className="h-5 w-5 text-orange-400" />
          <div>
            <h1 className="text-lg font-semibold text-slate-100">IPS Management</h1>
            <p className="text-xs text-slate-500">IP blocking & firewall rules</p>
          </div>
        </div>
        <div className="flex gap-2 items-center">
          <Button variant="ghost" size="sm" onClick={() => tab === 'blocked' ? loadBlocked() : loadRules()}>
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </Button>

          {/* Delete All button */}
          {tab === 'blocked' && blockedIPs.length > 0 && (
            <Button
              variant="ghost"
              size="sm"
              className="text-red-400 hover:text-red-300 hover:bg-red-500/10"
              onClick={() => setConfirmDeleteAllIPs(true)}
              disabled={deletingAllIPs}
            >
              {deletingAllIPs
                ? <Loader2 className="h-4 w-4 animate-spin" />
                : <Trash2 className="h-4 w-4" />}
              <span className="ml-1.5 text-xs">Delete All</span>
            </Button>
          )}
          {tab === 'rules' && rules.length > 0 && (
            <Button
              variant="ghost"
              size="sm"
              className="text-red-400 hover:text-red-300 hover:bg-red-500/10"
              onClick={() => setConfirmDeleteAllRules(true)}
              disabled={deletingAllRules}
            >
              {deletingAllRules
                ? <Loader2 className="h-4 w-4 animate-spin" />
                : <Trash2 className="h-4 w-4" />}
              <span className="ml-1.5 text-xs">Delete All</span>
            </Button>
          )}

          {tab === 'blocked' && (
            <Button size="sm" onClick={() => setShowForm(s => !s)}>
              {showForm ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" />}
              {showForm ? 'Cancel' : 'Block IP'}
            </Button>
          )}
        </div>
      </div>

      <div className="flex-1 p-6 space-y-4">
        {/* ── Block IP form ───────────────────────────────────────── */}
        {showForm && tab === 'blocked' && (
          <Card className="border-cyan-500/20 animate-fade-in">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Ban className="h-3.5 w-3.5 text-red-400" />
                Block IP Address
              </CardTitle>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleBlock} className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <div className="space-y-1.5">
                  <Label htmlFor="ip">IP Address *</Label>
                  <Input id="ip" placeholder="192.168.1.100" value={blockIP}
                    onChange={(e) => setBlockIP(e.target.value)} required className="font-mono" />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="reason">Reason</Label>
                  <Input id="reason" placeholder="Suspicious activity" value={blockReason}
                    onChange={(e) => setBlockReason(e.target.value)} />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="level">Threat Level</Label>
                  <select id="level" value={blockLevel}
                    onChange={(e) => setBlockLevel(e.target.value as 'low' | 'medium' | 'high' | 'critical')}
                    className="flex h-9 w-full rounded-md border border-slate-700 bg-slate-800/50 px-3 py-1 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="duration">Duration (hours)</Label>
                  <Input id="duration" type="number" min="1" max="720" value={blockDuration}
                    onChange={(e) => setBlockDuration(e.target.value)} />
                </div>
                <div className="sm:col-span-2 lg:col-span-4 flex items-center gap-3">
                  <Button type="submit" variant="destructive" disabled={blocking}>
                    {blocking
                      ? <><span className="h-3.5 w-3.5 rounded-full border-2 border-red-400/30 border-t-red-400 animate-spin" /> Blocking…</>
                      : <><Ban className="h-4 w-4" /> Block IP</>}
                  </Button>
                  {blockSuccess && <p className="text-xs text-emerald-400">{blockSuccess}</p>}
                  {blockError   && <p className="text-xs text-red-400">{blockError}</p>}
                </div>
              </form>
            </CardContent>
          </Card>
        )}

        {/* ── Tabs ────────────────────────────────────────────────── */}
        <div className="flex gap-1 rounded-lg border border-slate-800 bg-slate-900 p-1 w-fit">
          {tabs.map(({ id, label, icon: Icon, count }) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className={`flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-all ${
                tab === id ? 'bg-slate-800 text-slate-100 shadow-sm' : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              <Icon className="h-3.5 w-3.5" />
              {label}
              <span className={`rounded-full px-1.5 py-0.5 text-[10px] font-bold ${
                tab === id ? 'bg-cyan-500/20 text-cyan-400' : 'bg-slate-800 text-slate-600'
              }`}>
                {count}
              </span>
            </button>
          ))}
        </div>

        {/* ── Blocked IPs table ────────────────────────────────────── */}
        {tab === 'blocked' && (
          <Card>
            <CardContent className="px-0 pb-0">
              {loading ? (
                <div className="py-12 text-center">
                  <RefreshCw className="mx-auto mb-2 h-5 w-5 animate-spin text-cyan-500" />
                  <p className="text-sm text-slate-500">Loading…</p>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>IP Address</TableHead>
                      <TableHead>Reason</TableHead>
                      <TableHead>Threat Level</TableHead>
                      <TableHead>Blocked At</TableHead>
                      <TableHead>Expires At</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {blockedIPs.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={6} className="py-10 text-center text-slate-600">No blocked IPs</TableCell>
                      </TableRow>
                    ) : (
                      blockedIPs.map((b) => {
                        const isUnblocking = unbockingIP === b.ip_address
                        const isDeleting   = deletingIPId === b.id

                        return (
                          <TableRow key={b.id} className={isDeleting ? 'opacity-40' : ''}>
                            <TableCell className="font-mono text-sm text-cyan-300">{b.ip_address}</TableCell>
                            <TableCell className="max-w-xs truncate text-xs text-slate-400">{b.reason}</TableCell>
                            <TableCell><Badge variant={severityVariant(b.threat_level)}>{b.threat_level}</Badge></TableCell>
                            <TableCell className="text-xs text-slate-500">{formatDate(b.blocked_at)}</TableCell>
                            <TableCell className="text-xs text-slate-500">
                              {b.is_permanent ? 'Permanent' : b.unblock_at ? formatDate(b.unblock_at) : '—'}
                            </TableCell>
                            <TableCell>
                              <div className="flex items-center gap-1">
                                {/* Unblock */}
                                <button
                                  onClick={() => unblock(b.ip_address)}
                                  disabled={isUnblocking || isDeleting}
                                  title="Unblock IP"
                                  className="flex h-7 w-7 items-center justify-center rounded-lg border border-slate-700/50 hover:border-emerald-500/50 hover:bg-emerald-500/10 text-slate-400 hover:text-emerald-400 transition-all disabled:opacity-40"
                                >
                                  {isUnblocking
                                    ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                    : <Unlock className="h-3.5 w-3.5" />}
                                </button>

                                {/* Delete */}
                                <button
                                  onClick={() => setConfirmDeleteIPId(b.id)}
                                  disabled={isDeleting || isUnblocking}
                                  title="Delete record"
                                  className="flex h-7 w-7 items-center justify-center rounded-lg border border-slate-700/50 hover:border-red-500/50 hover:bg-red-500/10 text-slate-400 hover:text-red-400 transition-all disabled:opacity-40"
                                >
                                  {isDeleting
                                    ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                    : <Trash2 className="h-3.5 w-3.5" />}
                                </button>
                              </div>
                            </TableCell>
                          </TableRow>
                        )
                      })
                    )}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        )}

        {/* ── Firewall Rules table ──────────────────────────────────── */}
        {tab === 'rules' && (
          <Card>
            <CardContent className="px-0 pb-0">
              {loading ? (
                <div className="py-12 text-center">
                  <RefreshCw className="mx-auto mb-2 h-5 w-5 animate-spin text-cyan-500" />
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Rule Name</TableHead>
                      <TableHead>Source IP</TableHead>
                      <TableHead>Protocol</TableHead>
                      <TableHead>Port</TableHead>
                      <TableHead>Action</TableHead>
                      <TableHead>Priority</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead>Delete</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rules.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={9} className="py-10 text-center text-slate-600">No firewall rules</TableCell>
                      </TableRow>
                    ) : (
                      rules.map((r) => {
                        const isDeleting = deletingRuleId === r.id
                        return (
                          <TableRow key={r.id} className={isDeleting ? 'opacity-40' : ''}>
                            <TableCell className="text-xs font-medium text-slate-200">{r.rule_name}</TableCell>
                            <TableCell className="font-mono text-xs">{r.source_ip || '*'}</TableCell>
                            <TableCell><Badge variant="info">{r.protocol}</Badge></TableCell>
                            <TableCell className="font-mono text-xs">{r.destination_port ?? '*'}</TableCell>
                            <TableCell>
                              <Badge variant={r.action === 'block' ? 'critical' : 'success'}>{r.action}</Badge>
                            </TableCell>
                            <TableCell className="tabular-nums text-xs text-slate-400">{r.priority}</TableCell>
                            <TableCell>
                              {r.is_active
                                ? <Badge variant="success">Active</Badge>
                                : <Badge variant="default">Inactive</Badge>}
                            </TableCell>
                            <TableCell className="text-xs text-slate-500">{formatDate(r.created_at)}</TableCell>
                            <TableCell>
                              <button
                                onClick={() => setConfirmDeleteRuleId(r.id)}
                                disabled={isDeleting}
                                title="Delete rule"
                                className="flex h-7 w-7 items-center justify-center rounded-lg border border-slate-700/50 hover:border-red-500/50 hover:bg-red-500/10 text-slate-400 hover:text-red-400 transition-all disabled:opacity-40"
                              >
                                {isDeleting
                                  ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                  : <Trash2 className="h-3.5 w-3.5" />}
                              </button>
                            </TableCell>
                          </TableRow>
                        )
                      })
                    )}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  )
}
