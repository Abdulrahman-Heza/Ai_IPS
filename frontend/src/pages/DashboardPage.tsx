import { useEffect, useRef, useState } from 'react'
import {
  ShieldAlert, Ban, Flame, Activity, CheckCircle2,
  TrendingUp, Clock, Eye,
} from 'lucide-react'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Badge, attackVariant, severityVariant } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table'
import { apiGet, apiPost } from '@/api/client'
import { useSocket } from '@/hooks/useSocket'
import { formatTime, formatDate } from '@/lib/utils'

interface AuthState { token: string; user: { id: number; email: string; role: string; organization_id: number } }

interface Alert {
  id: string
  alert_type: string
  severity: string
  source_ip: string
  destination_ip: string
  confidence: number
  is_acknowledged: boolean
  created_at: string
}

interface OverviewData {
  total_alerts: number
  blocked_ips: number
  active_rules: number
  unacknowledged: number
  critical_alerts: number
}

interface TimelinePoint {
  hour: string
  threats: number
  benign: number
}

function StatCard({
  icon: Icon, label, value, sub, color,
}: {
  icon: React.ElementType
  label: string
  value: string | number
  sub?: string
  color: 'cyan' | 'red' | 'amber' | 'emerald'
}) {
  const colors = {
    cyan:    { bg: 'bg-cyan-500/10',    border: 'border-cyan-500/20',    icon: 'text-cyan-400',    text: 'text-cyan-100' },
    red:     { bg: 'bg-red-500/10',     border: 'border-red-500/20',     icon: 'text-red-400',     text: 'text-red-100' },
    amber:   { bg: 'bg-amber-500/10',   border: 'border-amber-500/20',   icon: 'text-amber-400',   text: 'text-amber-100' },
    emerald: { bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', icon: 'text-emerald-400', text: 'text-emerald-100' },
  }
  const c = colors[color]
  return (
    <Card className={`card-hover border ${c.border}`}>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle>{label}</CardTitle>
          <div className={`flex h-8 w-8 items-center justify-center rounded-lg ${c.bg}`}>
            <Icon className={`h-4 w-4 ${c.icon}`} />
          </div>
        </div>
        <p className={`text-3xl font-bold tabular-nums ${c.text}`}>{value}</p>
        {sub && <p className="text-xs text-slate-500">{sub}</p>}
      </CardHeader>
    </Card>
  )
}

export function DashboardPage({ auth }: { auth: AuthState }) {
  const [overview, setOverview] = useState<OverviewData | null>(null)
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [timeline, setTimeline] = useState<TimelinePoint[]>([])
  const [loading, setLoading] = useState(true)
  const refreshRef = useRef<() => void>(() => {})

  const { connected, threats, metrics } = useSocket(
    auth.user.organization_id,
    // Refresh stats every time a new threat event arrives
    () => refreshRef.current()
  )

  async function loadData() {
    try {
      const [alertRes, ipsRes, rulesRes, unackRes] = await Promise.allSettled([
        apiGet<{ data: Alert[]; total: number }>('/api/v1/alerts?limit=5', auth.token),
        apiGet<{ data: { total: number } }>('/api/v1/ips/blocked-ips', auth.token),
        apiGet<{ data: unknown[]; total: number }>('/api/v1/ips/firewall-rules', auth.token),
        apiGet<{ data: Alert[]; total: number }>('/api/v1/alerts/unacknowledged/list', auth.token),
      ])

      if (alertRes.status === 'fulfilled') setAlerts(alertRes.value.data ?? [])

      setOverview({
        total_alerts: alertRes.status === 'fulfilled' ? (alertRes.value.total ?? 0) : 0,
        blocked_ips: ipsRes.status === 'fulfilled' ? (ipsRes.value.data?.total ?? 0) : 0,
        active_rules: rulesRes.status === 'fulfilled' ? (rulesRes.value.total ?? 0) : 0,
        unacknowledged: unackRes.status === 'fulfilled' ? (unackRes.value.data?.length ?? 0) : 0,
        critical_alerts: alertRes.status === 'fulfilled'
          ? (alertRes.value.data?.filter((a) => a.severity === 'critical').length ?? 0)
          : 0,
      })
    } finally {
      setLoading(false)
    }
  }

  // Keep refreshRef pointing to current loadData so socket callback stays fresh
  useEffect(() => {
    refreshRef.current = loadData
  })

  useEffect(() => {
    loadData()
    // Mock timeline data for chart - real data from /api/v1/dashboard/timeline
    const now = new Date()
    const pts: TimelinePoint[] = Array.from({ length: 12 }, (_, i) => {
      const h = new Date(now.getTime() - (11 - i) * 3600000)
      return {
        hour: h.toLocaleTimeString('en', { hour: '2-digit', hour12: false }),
        threats: Math.floor(Math.random() * 8),
        benign: Math.floor(Math.random() * 40) + 10,
      }
    })
    setTimeline(pts)
    const id = setInterval(loadData, 20000)
    return () => clearInterval(id)
  }, [])

  async function handleAcknowledge(alertId: string) {
    try {
      await apiPost(`/api/v1/alerts/${alertId}/acknowledge`, {}, auth.token)
      setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, is_acknowledged: true } : a))
    } catch { /* ignore */ }
  }

  return (
    <div className="flex flex-col h-full overflow-auto bg-slate-950 cyber-grid">
      {/* Header */}
      <div className="sticky top-0 z-10 border-b border-slate-800/60 bg-slate-950/80 backdrop-blur-sm px-6 py-3 flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-slate-100">Security Dashboard</h1>
          <p className="text-xs text-slate-500">Real-time monitoring · org #{auth.user.organization_id}</p>
        </div>
        <div className="flex items-center gap-3">
          {connected && metrics && (
            <div className="flex items-center gap-2 rounded-lg border border-emerald-500/20 bg-emerald-500/5 px-3 py-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-xs text-emerald-400 font-medium">
                {metrics.threats_detected} threats · {metrics.total_flows} flows
              </span>
            </div>
          )}
          <div className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs ${
            connected
              ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
              : 'border-slate-700 bg-slate-800 text-slate-500'
          }`}>
            <span className={`h-1.5 w-1.5 rounded-full ${connected ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'}`} />
            {connected ? 'Live' : 'Offline'}
          </div>
        </div>
      </div>

      <div className="flex-1 p-6 space-y-6">
        {/* Stat Cards */}
        {loading ? (
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <Card key={i} className="animate-pulse">
                <CardHeader>
                  <div className="h-3 w-20 rounded bg-slate-800" />
                  <div className="h-8 w-12 rounded bg-slate-800 mt-2" />
                </CardHeader>
              </Card>
            ))}
          </div>
        ) : (
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <StatCard icon={ShieldAlert} label="Total Alerts"       value={overview?.total_alerts ?? 0}     sub="All time"          color="red" />
            <StatCard icon={Ban}         label="Blocked IPs"        value={overview?.blocked_ips ?? 0}      sub="Currently active"  color="amber" />
            <StatCard icon={Flame}       label="Firewall Rules"     value={overview?.active_rules ?? 0}     sub="Active rules"      color="cyan" />
            <StatCard icon={Activity}    label="Unacknowledged"     value={overview?.unacknowledged ?? 0}   sub="Pending review"    color="emerald" />
          </div>
        )}

        <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
          {/* Timeline Chart */}
          <div className="xl:col-span-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <TrendingUp className="h-3.5 w-3.5 text-cyan-500" />
                  Threat Activity (12h)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={180}>
                  <AreaChart data={timeline}>
                    <defs>
                      <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#f87171" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#f87171" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="benignGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.2} />
                        <stop offset="95%" stopColor="#22d3ee" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="hour" tick={{ fontSize: 10, fill: '#475569' }} />
                    <YAxis tick={{ fontSize: 10, fill: '#475569' }} />
                    <Tooltip
                      contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', fontSize: '12px' }}
                      labelStyle={{ color: '#94a3b8' }}
                    />
                    <Area type="monotone" dataKey="benign" stroke="#22d3ee" strokeWidth={1.5} fill="url(#benignGrad)" name="Benign" />
                    <Area type="monotone" dataKey="threats" stroke="#f87171" strokeWidth={1.5} fill="url(#threatGrad)" name="Threats" />
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>

          {/* Live Threat Feed */}
          <div>
            <Card className="h-full">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <span className="h-1.5 w-1.5 rounded-full bg-red-400 animate-pulse" />
                  Live Threat Feed
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-1.5 max-h-52 overflow-auto">
                  {threats.length === 0 ? (
                    <div className="py-8 text-center text-xs text-slate-600">
                      <Activity className="mx-auto mb-2 h-6 w-6 text-slate-700" />
                      Waiting for events…
                    </div>
                  ) : (
                    threats.slice(0, 12).map((t) => (
                      <div
                        key={t.flow_id + t.timestamp}
                        className="flex items-center gap-2 rounded-lg border border-slate-800/50 bg-slate-800/20 px-2.5 py-2 animate-fade-in"
                      >
                        <Badge variant={attackVariant(t.attack_type)} className="shrink-0 text-[10px]">
                          {t.attack_type}
                        </Badge>
                        <span className="flex-1 truncate font-mono text-[10px] text-slate-400">
                          {t.source_ip}
                        </span>
                        <span className="text-[10px] text-slate-600">{formatTime(t.timestamp)}</span>
                      </div>
                    ))
                  )}
                </div>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Recent Alerts Table */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <Clock className="h-3.5 w-3.5 text-cyan-500" />
                Recent Alerts
              </CardTitle>
              <span className="text-xs text-slate-600">{alerts.length} shown</span>
            </div>
          </CardHeader>
          <CardContent className="px-0 pb-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Source IP</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {alerts.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="py-8 text-center text-slate-600">
                      No alerts found
                    </TableCell>
                  </TableRow>
                ) : (
                  alerts.map((a) => (
                    <TableRow key={a.id}>
                      <TableCell className="font-mono text-xs text-slate-500">{formatDate(a.created_at)}</TableCell>
                      <TableCell>
                        <Badge variant={attackVariant(a.alert_type)}>{a.alert_type}</Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{a.source_ip || '—'}</TableCell>
                      <TableCell>
                        <Badge variant={severityVariant(a.severity)}>{a.severity}</Badge>
                      </TableCell>
                      <TableCell>
                        {a.is_acknowledged ? (
                          <span className="flex items-center gap-1 text-xs text-emerald-400">
                            <CheckCircle2 className="h-3 w-3" /> ACK
                          </span>
                        ) : (
                          <span className="text-xs text-amber-400">Pending</span>
                        )}
                      </TableCell>
                      <TableCell>
                        {!a.is_acknowledged && (
                          <Button variant="ghost" size="sm" onClick={() => handleAcknowledge(a.id)}>
                            <Eye className="h-3.5 w-3.5" />
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
