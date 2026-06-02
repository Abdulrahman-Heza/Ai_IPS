import { type HTMLAttributes } from 'react'
import { cn } from '@/lib/utils'

type Variant = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'success' | 'default'

interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  variant?: Variant
}

const variants: Record<Variant, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high:     'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium:   'bg-amber-500/15 text-amber-400 border-amber-500/30',
  low:      'bg-blue-500/15 text-blue-400 border-blue-500/30',
  info:     'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  success:  'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  default:  'bg-slate-700/50 text-slate-300 border-slate-600/50',
}

export function Badge({ className, variant = 'default', ...props }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium',
        variants[variant],
        className,
      )}
      {...props}
    />
  )
}

export function severityVariant(severity: string): Variant {
  const map: Record<string, Variant> = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    low: 'low',
  }
  return map[severity?.toLowerCase()] ?? 'default'
}

export function attackVariant(type: string): Variant {
  if (type === 'benign') return 'success'
  if (type === 'ddos') return 'critical'
  if (type === 'brute_force') return 'high'
  if (type === 'sql_injection') return 'high'
  if (type === 'anomaly') return 'medium'
  return 'default'
}
