import { type FormEvent, useState } from 'react'
import { Zap, Play, RefreshCw, ShieldAlert, CheckCircle2, AlertTriangle, Info } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Badge, attackVariant } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { apiPost } from '@/api/client'
import { cn } from '@/lib/utils'

interface AuthState { token: string; user: { id: number; email: string; role: string; organization_id: number } }

interface ThreatResult {
  flow_id: string
  source_ip: string
  destination_ip: string
  attack_type: string
  confidence: number
  risk_score: number
  risk_level: string
  protocol: string
  port: number
  timestamp: string
  auto_response: string[]
}

type Preset = 'benign' | 'ddos' | 'brute_force' | 'sql_injection' | 'anomaly' | 'custom'

const PRESETS: Record<Preset, { label: string; color: string; description: string; features: number[] }> = {
  benign: {
    label: 'Normal Traffic',
    color: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10',
    description: 'Simulates normal benign network traffic',
    features: Array.from({ length: 50 }, () => Math.random() * 0.3),
  },
  ddos: {
    label: 'DDoS Attack',
    color: 'text-red-400 border-red-500/30 bg-red-500/10',
    description: 'High volume, high packet rate attack pattern',
    features: Array.from({ length: 50 }, (_, i) => i < 10 ? 0.95 : Math.random() * 0.5 + 0.4),
  },
  brute_force: {
    label: 'Brute Force',
    color: 'text-orange-400 border-orange-500/30 bg-orange-500/10',
    description: 'Many repeated auth attempts from single source',
    features: Array.from({ length: 50 }, (_, i) => i % 5 === 0 ? 0.88 : Math.random() * 0.4 + 0.3),
  },
  sql_injection: {
    label: 'SQL Injection',
    color: 'text-amber-400 border-amber-500/30 bg-amber-500/10',
    description: 'Malicious SQL payload in HTTP requests',
    features: Array.from({ length: 50 }, (_, i) => i < 5 ? 0.1 : i < 20 ? 0.85 : Math.random() * 0.5),
  },
  anomaly: {
    label: 'Anomaly',
    color: 'text-purple-400 border-purple-500/30 bg-purple-500/10',
    description: 'Unknown behavioral pattern detected',
    features: Array.from({ length: 50 }, () => Math.random() > 0.5 ? 0.8 + Math.random() * 0.2 : Math.random() * 0.2),
  },
  custom: {
    label: 'Custom',
    color: 'text-slate-300 border-slate-600/50 bg-slate-800/40',
    description: 'Enter your own values (0.0 – 1.0 each)',
    features: Array.from({ length: 50 }, () => 0.5),
  },
}

function riskColor(score: number) {
  if (score >= 80) return 'text-red-400'
  if (score >= 60) return 'text-orange-400'
  if (score >= 40) return 'text-amber-400'
  return 'text-emerald-400'
}

function riskBg(score: number) {
  if (score >= 80) return 'bg-red-500'
  if (score >= 60) return 'bg-orange-500'
  if (score >= 40) return 'bg-amber-500'
  return 'bg-emerald-500'
}

export function SimulatorPage({ auth }: { auth: AuthState }) {
  const [preset, setPreset] = useState<Preset>('ddos')
  const [sourceIP, setSourceIP] = useState('10.0.0.99')
  const [destIP, setDestIP] = useState('192.168.1.1')
  const [protocol, setProtocol] = useState('TCP')
  const [port, setPort] = useState('80')
  const [customFeaturesStr, setCustomFeaturesStr] = useState('0.5')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<ThreatResult | null>(null)
  const [error, setError] = useState('')
  const [requestCount, setRequestCount] = useState(0)

  function buildFeatures(): number[] {
    if (preset === 'custom') {
      const vals = customFeaturesStr.split(',').map(s => parseFloat(s.trim())).filter(n => !isNaN(n))
      while (vals.length < 50) vals.push(0.5)
      return vals.slice(0, 50)
    }
    return PRESETS[preset].features
  }

  async function handleSimulate(e: FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    setRequestCount(c => c + 1)
    try {
      const features = buildFeatures()
      const res = await apiPost<{ data: ThreatResult }>('/api/v1/threats/process', {
        flow_id: `sim_${Date.now()}`,
        source_ip: sourceIP,
        destination_ip: destIP,
        protocol,
        source_port: Math.floor(Math.random() * 60000) + 1024,
        destination_port: parseInt(port) || 80,
        duration: Math.random() * 10,
        forward_bytes: Math.floor(Math.random() * 1000000),
        backward_bytes: Math.floor(Math.random() * 500000),
        forward_packets: Math.floor(Math.random() * 1000),
        backward_packets: Math.floor(Math.random() * 500),
        features,
      }, auth.token)
      setResult(res.data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Simulation failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex flex-col h-full overflow-auto bg-slate-950 cyber-grid">
      {/* Header */}
      <div className="sticky top-0 z-10 border-b border-slate-800/60 bg-slate-950/80 backdrop-blur-sm px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Zap className="h-5 w-5 text-cyan-400" />
          <div>
            <h1 className="text-lg font-semibold text-slate-100">Threat Simulator</h1>
            <p className="text-xs text-slate-500">Test AI detection pipeline end-to-end · {requestCount} simulations run</p>
          </div>
        </div>
      </div>

      <div className="flex-1 p-6">
        <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
          {/* Left: Config */}
          <form onSubmit={handleSimulate} className="space-y-5">
            {/* Attack Preset Selector */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <ShieldAlert className="h-3.5 w-3.5 text-cyan-500" />
                  Attack Pattern
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                  {(Object.entries(PRESETS) as [Preset, (typeof PRESETS)[Preset]][]).map(([key, p]) => (
                    <button
                      key={key}
                      type="button"
                      onClick={() => setPreset(key)}
                      className={cn(
                        'rounded-lg border px-3 py-3 text-left transition-all duration-150',
                        preset === key
                          ? p.color + ' ring-1 ring-inset ring-current/20'
                          : 'border-slate-800 bg-slate-800/30 text-slate-500 hover:border-slate-700 hover:text-slate-300',
                      )}
                    >
                      <p className="text-xs font-semibold">{p.label}</p>
                      <p className="mt-0.5 text-[10px] opacity-70 leading-tight">{p.description}</p>
                    </button>
                  ))}
                </div>
                {preset === 'custom' && (
                  <div className="mt-4 space-y-1.5">
                    <Label>Features (comma-separated, 50 values, 0.0–1.0)</Label>
                    <textarea
                      className="flex min-h-20 w-full rounded-md border border-slate-700 bg-slate-800/50 px-3 py-2 text-xs font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
                      placeholder="0.5, 0.3, 0.8, ..."
                      value={customFeaturesStr}
                      onChange={(e) => setCustomFeaturesStr(e.target.value)}
                    />
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Network Config */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Info className="h-3.5 w-3.5 text-cyan-500" />
                  Network Flow Details
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <Label htmlFor="src">Source IP</Label>
                    <Input id="src" value={sourceIP} onChange={e => setSourceIP(e.target.value)} className="font-mono text-xs" />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="dst">Destination IP</Label>
                    <Input id="dst" value={destIP} onChange={e => setDestIP(e.target.value)} className="font-mono text-xs" />
                  </div>
                  <div className="space-y-1.5">
                    <Label>Protocol</Label>
                    <select
                      value={protocol}
                      onChange={e => setProtocol(e.target.value)}
                      className="flex h-9 w-full rounded-md border border-slate-700 bg-slate-800/50 px-3 py-1 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
                    >
                      <option>TCP</option>
                      <option>UDP</option>
                      <option>ICMP</option>
                    </select>
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="port">Destination Port</Label>
                    <Input id="port" type="number" value={port} onChange={e => setPort(e.target.value)} className="font-mono text-xs" />
                  </div>
                </div>
              </CardContent>
            </Card>

            {error && (
              <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3">
                <AlertTriangle className="h-4 w-4 shrink-0 text-red-400" />
                <p className="text-xs text-red-400">{error}</p>
              </div>
            )}

            <Button type="submit" className="w-full h-11" disabled={loading}>
              {loading ? (
                <span className="flex items-center gap-2">
                  <span className="h-4 w-4 rounded-full border-2 border-slate-950/30 border-t-slate-950 animate-spin" />
                  Running AI Inference…
                </span>
              ) : (
                <span className="flex items-center gap-2">
                  <Play className="h-4 w-4" />
                  Run Threat Simulation
                </span>
              )}
            </Button>
          </form>

          {/* Right: Results */}
          <div className="space-y-4">
            {!result ? (
              <Card className="flex items-center justify-center" style={{ minHeight: '400px' }}>
                <div className="text-center p-8">
                  <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-cyan-500/5 border border-cyan-500/10">
                    <Zap className="h-8 w-8 text-cyan-500/40" />
                  </div>
                  <p className="text-slate-500 text-sm">Select an attack pattern and click</p>
                  <p className="text-slate-600 text-xs mt-1">Run Threat Simulation to see AI results</p>
                </div>
              </Card>
            ) : (
              <div className="space-y-4 animate-fade-in">
                {/* AI Verdict */}
                <Card className={cn('border', result.attack_type === 'benign' ? 'border-emerald-500/30' : 'border-red-500/30')}>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle className="flex items-center gap-2">
                        {result.attack_type === 'benign'
                          ? <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                          : <ShieldAlert className="h-4 w-4 text-red-400" />}
                        AI Verdict
                      </CardTitle>
                      <Badge variant={attackVariant(result.attack_type)} className="text-sm px-3 py-1">
                        {result.attack_type.replace('_', ' ').toUpperCase()}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 gap-4">
                      {/* Risk Score */}
                      <div>
                        <p className="text-xs text-slate-500 mb-2">Risk Score</p>
                        <p className={`text-4xl font-bold tabular-nums ${riskColor(result.risk_score)}`}>
                          {result.risk_score.toFixed(0)}
                          <span className="text-lg text-slate-600">/100</span>
                        </p>
                        <div className="mt-2 h-2 w-full rounded-full bg-slate-800">
                          <div
                            className={`h-2 rounded-full transition-all duration-500 ${riskBg(result.risk_score)}`}
                            style={{ width: `${result.risk_score}%` }}
                          />
                        </div>
                      </div>
                      {/* Confidence */}
                      <div>
                        <p className="text-xs text-slate-500 mb-2">Confidence</p>
                        <p className="text-4xl font-bold tabular-nums text-cyan-300">
                          {(result.confidence * 100).toFixed(0)}
                          <span className="text-lg text-slate-600">%</span>
                        </p>
                        <div className="mt-2 h-2 w-full rounded-full bg-slate-800">
                          <div
                            className="h-2 rounded-full bg-cyan-500 transition-all duration-500"
                            style={{ width: `${result.confidence * 100}%` }}
                          />
                        </div>
                      </div>
                    </div>

                    <div className="mt-4 grid grid-cols-3 gap-3 border-t border-slate-800 pt-4">
                      <div>
                        <p className="text-[10px] text-slate-600 uppercase tracking-wider">Risk Level</p>
                        <p className={`text-sm font-semibold capitalize ${riskColor(result.risk_score)}`}>{result.risk_level}</p>
                      </div>
                      <div>
                        <p className="text-[10px] text-slate-600 uppercase tracking-wider">Protocol</p>
                        <p className="text-sm font-mono text-slate-300">{result.protocol}</p>
                      </div>
                      <div>
                        <p className="text-[10px] text-slate-600 uppercase tracking-wider">Port</p>
                        <p className="text-sm font-mono text-slate-300">{result.port}</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* Auto Response Actions */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Zap className="h-3.5 w-3.5 text-amber-400" />
                      Self-Healing Actions Taken
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {result.auto_response.length === 0 ? (
                      <div className="py-4 text-center">
                        <CheckCircle2 className="mx-auto mb-2 h-6 w-6 text-emerald-400" />
                        <p className="text-xs text-emerald-400">No action needed — traffic is benign or low risk</p>
                      </div>
                    ) : (
                      <div className="space-y-2">
                        {result.auto_response.map((action, i) => (
                          <div key={i} className="flex items-center gap-2 rounded-lg border border-amber-500/20 bg-amber-500/5 px-3 py-2">
                            <Zap className="h-3 w-3 shrink-0 text-amber-400" />
                            <span className="text-xs font-mono text-amber-300">{action}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>

                {/* Raw Details */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Info className="h-3.5 w-3.5 text-slate-500" />
                      Flow Details
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2 font-mono text-xs">
                      {[
                        ['Flow ID', result.flow_id],
                        ['Source IP', result.source_ip],
                        ['Destination IP', result.destination_ip],
                        ['Timestamp', new Date(result.timestamp).toLocaleString()],
                      ].map(([label, val]) => (
                        <div key={label} className="flex items-center justify-between">
                          <span className="text-slate-600">{label}</span>
                          <span className="text-slate-300 ml-2 truncate">{val}</span>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>

                <Button variant="outline" className="w-full" onClick={() => setResult(null)}>
                  <RefreshCw className="h-4 w-4" /> Clear Results
                </Button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
