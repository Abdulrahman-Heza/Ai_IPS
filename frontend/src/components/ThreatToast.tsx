import { useEffect, useState } from 'react'
import { ShieldAlert, X, ArrowRight, Zap } from 'lucide-react'
import type { ThreatEvent } from '@/hooks/useSocket'

interface ThreatToastProps {
  threat: ThreatEvent
  onDismiss: (flowId: string) => void
  onViewAlerts: () => void
}

const RISK_STYLES: Record<string, { border: string; bg: string; badge: string; icon: string; glow: string }> = {
  critical: {
    border: 'border-red-500/60',
    bg: 'bg-red-950/90',
    badge: 'bg-red-500 text-white',
    icon: 'text-red-400',
    glow: 'shadow-red-500/20',
  },
  high: {
    border: 'border-orange-500/60',
    bg: 'bg-orange-950/90',
    badge: 'bg-orange-500 text-white',
    icon: 'text-orange-400',
    glow: 'shadow-orange-500/20',
  },
  medium: {
    border: 'border-amber-500/60',
    bg: 'bg-amber-950/90',
    badge: 'bg-amber-500 text-white',
    icon: 'text-amber-400',
    glow: 'shadow-amber-500/20',
  },
  low: {
    border: 'border-cyan-500/40',
    bg: 'bg-slate-900/90',
    badge: 'bg-cyan-600 text-white',
    icon: 'text-cyan-400',
    glow: 'shadow-cyan-500/10',
  },
}

const DISMISS_MS = 7000

export function ThreatToast({ threat, onDismiss, onViewAlerts }: ThreatToastProps) {
  const [progress, setProgress] = useState(100)
  const [visible, setVisible] = useState(false)
  const style = RISK_STYLES[threat.risk_level] ?? RISK_STYLES.medium

  // Slide-in on mount
  useEffect(() => {
    const t = setTimeout(() => setVisible(true), 20)
    return () => clearTimeout(t)
  }, [])

  // Progress bar countdown
  useEffect(() => {
    const start = Date.now()
    const frame = () => {
      const elapsed = Date.now() - start
      const remaining = Math.max(0, 100 - (elapsed / DISMISS_MS) * 100)
      setProgress(remaining)
      if (remaining > 0) requestAnimationFrame(frame)
      else onDismiss(threat.flow_id)
    }
    const raf = requestAnimationFrame(frame)
    return () => cancelAnimationFrame(raf)
  }, [threat.flow_id, onDismiss])

  function handleDismiss() {
    setVisible(false)
    setTimeout(() => onDismiss(threat.flow_id), 200)
  }

  function handleView() {
    handleDismiss()
    onViewAlerts()
  }

  return (
    <div
      className={`
        relative overflow-hidden rounded-xl border shadow-2xl
        backdrop-blur-md transition-all duration-300 w-80
        ${style.border} ${style.bg} ${style.glow}
        ${visible ? 'translate-x-0 opacity-100' : 'translate-x-full opacity-0'}
      `}
    >
      {/* Animated left accent bar */}
      <div className={`absolute left-0 top-0 bottom-0 w-1 ${
        threat.risk_level === 'critical' ? 'bg-red-500 animate-pulse' :
        threat.risk_level === 'high'     ? 'bg-orange-500' :
        threat.risk_level === 'medium'   ? 'bg-amber-500' : 'bg-cyan-500'
      }`} />

      <div className="px-4 py-3 pl-5">
        {/* Header */}
        <div className="flex items-start justify-between gap-2 mb-2">
          <div className="flex items-center gap-2">
            <ShieldAlert className={`h-4 w-4 shrink-0 ${style.icon} ${
              threat.risk_level === 'critical' ? 'animate-pulse' : ''
            }`} />
            <span className="text-sm font-semibold text-white leading-tight">
              {threat.risk_level === 'critical' ? '🚨 Critical Threat!' :
               threat.risk_level === 'high'     ? '⚠️ High Risk Alert' :
               threat.risk_level === 'medium'   ? '⚡ Threat Detected' : 'ℹ️ Low Risk Event'}
            </span>
          </div>
          <button
            onClick={handleDismiss}
            className="text-slate-500 hover:text-slate-300 transition-colors shrink-0 mt-0.5"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>

        {/* Threat details */}
        <div className="space-y-1 mb-3">
          <div className="flex items-center gap-2">
            <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-bold uppercase ${style.badge}`}>
              <Zap className="h-2.5 w-2.5" />
              {threat.attack_type.replace(/_/g, ' ')}
            </span>
            <span className="text-[10px] font-mono text-slate-400">
              risk: <span className="text-white font-bold">{threat.risk_score}</span>/100
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Source: <span className="font-mono text-slate-200">{threat.source_ip}</span>
          </p>
          <p className="text-xs text-slate-400">
            Target: <span className="font-mono text-slate-200">{threat.destination_ip}:{threat.port}</span>
          </p>
        </div>

        {/* View alerts button */}
        <button
          onClick={handleView}
          className="flex w-full items-center justify-center gap-1.5 rounded-lg bg-white/10 hover:bg-white/20 
                     transition-colors px-3 py-1.5 text-xs font-medium text-white"
        >
          View Alerts
          <ArrowRight className="h-3 w-3" />
        </button>
      </div>

      {/* Progress bar */}
      <div className="h-0.5 bg-slate-800">
        <div
          className={`h-full transition-none ${
            threat.risk_level === 'critical' ? 'bg-red-500' :
            threat.risk_level === 'high'     ? 'bg-orange-500' :
            threat.risk_level === 'medium'   ? 'bg-amber-500' : 'bg-cyan-500'
          }`}
          style={{ width: `${progress}%` }}
        />
      </div>
    </div>
  )
}

// ── Container that holds all active toasts ─────────────────────────────────
interface ThreatToastContainerProps {
  toasts: ThreatEvent[]
  onDismiss: (flowId: string) => void
  onViewAlerts: () => void
}

export function ThreatToastContainer({ toasts, onDismiss, onViewAlerts }: ThreatToastContainerProps) {
  if (toasts.length === 0) return null

  return (
    <div className="fixed top-4 right-4 z-50 flex flex-col gap-2 pointer-events-none">
      {toasts.map(t => (
        <div key={t.flow_id + t.timestamp} className="pointer-events-auto">
          <ThreatToast
            threat={t}
            onDismiss={onDismiss}
            onViewAlerts={onViewAlerts}
          />
        </div>
      ))}
    </div>
  )
}
