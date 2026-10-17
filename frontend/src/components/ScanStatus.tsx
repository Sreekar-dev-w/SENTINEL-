import { CircleCheck, CircleDot, CircleX, LoaderCircle, Timer } from 'lucide-react'
import { Badge } from './Badge'
import { statusLabel } from '../lib/scan-utils'

interface ScanStatusProps { status: string; compact?: boolean }

export function ScanStatus({ status, compact = false }: ScanStatusProps) {
  const normalized = status.toLowerCase()
  const terminal = normalized === 'completed' || normalized === 'cancelled' || normalized === 'failed'
  const tone = normalized === 'completed' ? 'success' : normalized === 'failed' ? 'danger' : normalized === 'cancelled' ? 'neutral' : 'running'
  const Icon = normalized === 'completed' ? CircleCheck : normalized === 'failed' ? CircleX : normalized === 'cancelled' ? Timer : normalized === 'running' ? LoaderCircle : CircleDot
  return <Badge tone={tone} dot={!compact}>{!compact && <Icon size={13} className={terminal ? '' : 'spin'} />}{statusLabel(status)}</Badge>
}
