import type { CheckResponse, ScanStatusResponse } from '../types'

export const TERMINAL_STATUSES = new Set(['completed', 'failed', 'cancelled'])

export function isTerminal(status: string): boolean {
  return TERMINAL_STATUSES.has(status.toLowerCase())
}

export function statusLabel(status: string): string {
  return status.replace(/[_-]+/g, ' ').replace(/\b\w/g, (character) => character.toUpperCase())
}

export function severityTone(severity: string): 'critical' | 'high' | 'medium' | 'low' | 'info' {
  const normalized = severity.toLowerCase()
  if (normalized === 'critical') return 'critical'
  if (normalized === 'high') return 'high'
  if (normalized === 'medium' || normalized === 'moderate') return 'medium'
  if (normalized === 'low') return 'low'
  return 'info'
}

export function progressForScan(scan: ScanStatusResponse): number {
  if (scan.summary.checks_total <= 0) return scan.status === 'completed' ? 100 : 0
  return Math.min(100, Math.round((scan.summary.checks_completed / scan.summary.checks_total) * 100))
}

export function checkTone(check: CheckResponse): 'done' | 'running' | 'failed' | 'waiting' {
  const status = check.status.toLowerCase()
  if (['completed', 'complete', 'passed', 'done'].includes(status)) return 'done'
  if (['failed', 'error'].includes(status)) return 'failed'
  if (['running', 'in_progress'].includes(status)) return 'running'
  return 'waiting'
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date)
}

export function formatRelative(value: string | null | undefined): string {
  if (!value) return '—'
  const time = new Date(value).getTime()
  if (Number.isNaN(time)) return value
  const minutes = Math.max(0, Math.round((Date.now() - time) / 60000))
  if (minutes < 1) return 'just now'
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.round(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.round(hours / 24)}d ago`
}
