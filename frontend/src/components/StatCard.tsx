import type { LucideIcon } from 'lucide-react'

interface StatCardProps {
  label: string
  value: string | number
  detail: string
  icon: LucideIcon
  tone?: 'cyan' | 'violet' | 'amber' | 'rose'
}

export function StatCard({ label, value, detail, icon: Icon, tone = 'cyan' }: StatCardProps) {
  return <article className={`stat-card stat-${tone}`}>
    <div className="stat-top"><span>{label}</span><span className="stat-icon"><Icon size={17} /></span></div>
    <strong>{value}</strong>
    <small>{detail}</small>
  </article>
}
