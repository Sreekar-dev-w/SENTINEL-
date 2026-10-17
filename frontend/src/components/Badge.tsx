import type { ReactNode } from 'react'

interface BadgeProps {
  children: ReactNode
  tone?: string
  dot?: boolean
}

export function Badge({ children, tone = 'neutral', dot = false }: BadgeProps) {
  return <span className={`badge badge-${tone}`}>{dot && <span className="badge-dot" aria-hidden="true" />}{children}</span>
}
