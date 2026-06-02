import { type InputHTMLAttributes, forwardRef } from 'react'
import { cn } from '@/lib/utils'

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        'flex h-9 w-full rounded-md border border-slate-700 bg-slate-800/50 px-3 py-1',
        'text-sm text-slate-100 placeholder:text-slate-500',
        'focus:outline-none focus:ring-2 focus:ring-cyan-500/40 focus:border-cyan-500/60',
        'disabled:opacity-50 disabled:cursor-not-allowed',
        'transition-colors duration-150',
        className,
      )}
      {...props}
    />
  ),
)
Input.displayName = 'Input'
