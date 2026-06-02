import {
  Shield,
  LayoutDashboard,
  Bell,
  Ban,
  Zap,
  LogOut,
  Wifi,
  WifiOff,
  ChevronRight,
} from 'lucide-react'
import { cn } from '@/lib/utils'

type Page = 'dashboard' | 'alerts' | 'ips' | 'simulator'

interface SidebarProps {
  page: Page
  onNavigate: (p: Page) => void
  onLogout: () => void
  socketConnected: boolean
  userEmail: string
}

const navItems: { id: Page; icon: React.ElementType; label: string; description: string }[] = [
  { id: 'dashboard', icon: LayoutDashboard, label: 'Dashboard', description: 'Overview & live feed' },
  { id: 'alerts',    icon: Bell,            label: 'Alerts',    description: 'Manage security alerts' },
  { id: 'ips',       icon: Ban,             label: 'IPS',       description: 'Blocked IPs & rules' },
  { id: 'simulator', icon: Zap,             label: 'Simulator', description: 'Test threat detection' },
]

export function Sidebar({ page, onNavigate, onLogout, socketConnected, userEmail }: SidebarProps) {
  return (
    <aside className="flex w-60 flex-col border-r border-slate-800/60 bg-slate-900/80 backdrop-blur-sm">
      {/* Logo */}
      <div className="flex items-center gap-3 border-b border-slate-800/60 px-5 py-4">
        <div className="relative flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-500/10 border border-cyan-500/30 animate-pulse-glow">
          <Shield className="h-5 w-5 text-cyan-400" />
        </div>
        <div>
          <p className="text-sm font-bold text-slate-100 tracking-wide">IPS System</p>
          <p className="text-xs text-slate-500">Security Center</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1 p-3">
        <p className="mb-2 px-3 text-[10px] font-semibold uppercase tracking-widest text-slate-600">
          Navigation
        </p>
        {navItems.map(({ id, icon: Icon, label, description }) => {
          const active = page === id
          return (
            <button
              key={id}
              onClick={() => onNavigate(id)}
              className={cn(
                'group flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left transition-all duration-150',
                active
                  ? 'bg-cyan-500/10 border border-cyan-500/20 text-cyan-300'
                  : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200 border border-transparent',
              )}
            >
              <Icon
                className={cn(
                  'h-4 w-4 shrink-0 transition-colors',
                  active ? 'text-cyan-400' : 'text-slate-500 group-hover:text-slate-300',
                )}
              />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">{label}</p>
                <p className="text-[10px] text-slate-600 group-hover:text-slate-500 truncate">
                  {description}
                </p>
              </div>
              {active && <ChevronRight className="h-3 w-3 text-cyan-500 shrink-0" />}
            </button>
          )
        })}
      </nav>

      {/* Footer */}
      <div className="border-t border-slate-800/60 p-3 space-y-2">
        {/* WebSocket Status */}
        <div
          className={cn(
            'flex items-center gap-2 rounded-lg px-3 py-2 border',
            socketConnected
              ? 'bg-emerald-500/10 border-emerald-500/20'
              : 'bg-slate-800/40 border-slate-700/40',
          )}
        >
          {socketConnected ? (
            <Wifi className="h-3.5 w-3.5 text-emerald-400" />
          ) : (
            <WifiOff className="h-3.5 w-3.5 text-slate-500" />
          )}
          <div>
            <p className={cn('text-xs font-medium', socketConnected ? 'text-emerald-400' : 'text-slate-500')}>
              {socketConnected ? 'Live Connected' : 'Disconnected'}
            </p>
            <p className="text-[10px] text-slate-600">WebSocket</p>
          </div>
          {socketConnected && (
            <span className="ml-auto h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
          )}
        </div>

        {/* User info */}
        <div className="flex items-center gap-2 rounded-lg px-3 py-2 bg-slate-800/40">
          <div className="flex h-7 w-7 items-center justify-center rounded-full bg-cyan-500/20 border border-cyan-500/20 shrink-0">
            <span className="text-xs font-bold text-cyan-400">
              {userEmail.charAt(0).toUpperCase()}
            </span>
          </div>
          <p className="flex-1 truncate text-xs text-slate-400">{userEmail}</p>
          <button
            onClick={onLogout}
            className="rounded p-1 text-slate-600 hover:text-red-400 hover:bg-red-500/10 transition-colors"
            title="Logout"
          >
            <LogOut className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    </aside>
  )
}
