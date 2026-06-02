import { useCallback, useEffect, useRef, useState } from 'react'
import { Sidebar } from '@/components/Sidebar'
import { LoginPage } from '@/pages/LoginPage'
import { DashboardPage } from '@/pages/DashboardPage'
import { AlertsPage } from '@/pages/AlertsPage'
import { IPSPage } from '@/pages/IPSPage'
import { SimulatorPage } from '@/pages/SimulatorPage'
import { ThreatToastContainer } from '@/components/ThreatToast'
import { useSocket, type ThreatEvent } from '@/hooks/useSocket'

type Page = 'dashboard' | 'alerts' | 'ips' | 'simulator'

interface AuthUser {
  id: number
  email: string
  role: string
  organization_id: number
}

interface AuthState {
  token: string
  user: AuthUser
}

const STORAGE_KEY = 'ips_auth_v1'

// ── Web Audio beep generator (no files needed) ─────────────────────────────
function playAlertSound(riskLevel: string) {
  try {
    const ctx = new AudioContext()
    const gain = ctx.createGain()
    gain.connect(ctx.destination)

    const playBeep = (freq: number, start: number, duration: number) => {
      const osc = ctx.createOscillator()
      osc.connect(gain)
      osc.type = 'square'
      osc.frequency.setValueAtTime(freq, ctx.currentTime + start)
      gain.gain.setValueAtTime(0.15, ctx.currentTime + start)
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + start + duration)
      osc.start(ctx.currentTime + start)
      osc.stop(ctx.currentTime + start + duration)
    }

    if (riskLevel === 'critical') {
      // Urgent triple beep
      playBeep(1046, 0.00, 0.12)
      playBeep(1046, 0.15, 0.12)
      playBeep(1318, 0.30, 0.20)
    } else if (riskLevel === 'high') {
      // Double beep
      playBeep(880, 0.00, 0.12)
      playBeep(880, 0.15, 0.12)
    } else {
      // Single soft beep
      playBeep(660, 0.00, 0.15)
    }
  } catch {
    // AudioContext blocked by browser policy (user hasn't interacted yet) — ignore
  }
}

function AppShell({ auth, onLogout }: { auth: AuthState; onLogout: () => void }) {
  const [page, setPage] = useState<Page>('dashboard')
  const [toasts, setToasts] = useState<ThreatEvent[]>([])
  const autoNavTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const handleNewThreat = useCallback((threat: ThreatEvent) => {
    // 1. Play sound based on severity
    playAlertSound(threat.risk_level)

    // 2. Show toast notification (max 4 visible at once)
    setToasts(prev => {
      const already = prev.some(t => t.flow_id === threat.flow_id)
      if (already) return prev
      return [threat, ...prev].slice(0, 4)
    })

    // 3. Auto-navigate to Alerts page for critical / high threats
    if (threat.risk_level === 'critical' || threat.risk_level === 'high') {
      if (autoNavTimerRef.current) clearTimeout(autoNavTimerRef.current)
      autoNavTimerRef.current = setTimeout(() => {
        setPage('alerts')
      }, 2500) // give user 2.5 s to see the toast first
    }
  }, [])

  const dismissToast = useCallback((flowId: string) => {
    setToasts(prev => prev.filter(t => t.flow_id !== flowId))
  }, [])

  const { connected } = useSocket(auth.user.organization_id, handleNewThreat)

  // Cleanup auto-nav timer on unmount
  useEffect(() => () => {
    if (autoNavTimerRef.current) clearTimeout(autoNavTimerRef.current)
  }, [])

  return (
    <div className="flex h-screen overflow-hidden bg-slate-950">
      <Sidebar
        page={page}
        onNavigate={setPage}
        onLogout={onLogout}
        socketConnected={connected}
        userEmail={auth.user.email}
      />

      <main className="flex-1 overflow-hidden">
        {page === 'dashboard'  && <DashboardPage  auth={auth} />}
        {page === 'alerts'     && <AlertsPage     auth={auth} />}
        {page === 'ips'        && <IPSPage        auth={auth} />}
        {page === 'simulator'  && <SimulatorPage  auth={auth} />}
      </main>

      {/* Floating threat notifications — top-right corner */}
      <ThreatToastContainer
        toasts={toasts}
        onDismiss={dismissToast}
        onViewAlerts={() => setPage('alerts')}
      />
    </div>
  )
}

export default function App() {
  const [auth, setAuth] = useState<AuthState | null>(null)
  const [initialised, setInitialised] = useState(false)

  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY)
      if (stored) setAuth(JSON.parse(stored))
    } catch {
      localStorage.removeItem(STORAGE_KEY)
    } finally {
      setInitialised(true)
    }
  }, [])

  function handleLogin(token: string, user: AuthUser) {
    const state: AuthState = { token, user }
    setAuth(state)
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state))
  }

  function handleLogout() {
    setAuth(null)
    localStorage.removeItem(STORAGE_KEY)
  }

  if (!initialised) {
    return (
      <div className="flex h-screen items-center justify-center bg-slate-950">
        <span className="h-8 w-8 rounded-full border-2 border-cyan-500/30 border-t-cyan-500 animate-spin" />
      </div>
    )
  }

  if (!auth) {
    return <LoginPage onLogin={handleLogin} />
  }

  return <AppShell auth={auth} onLogout={handleLogout} />
}
