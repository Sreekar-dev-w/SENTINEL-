import { AlertTriangle, CheckCircle2, CircleHelp, RefreshCw, Server } from 'lucide-react'
import { useEffect, useState } from 'react'
import { getExternalTools } from '../api'
import { Badge } from './Badge'
import type { ApiError, ExternalToolAvailability } from '../types'

function message(error: unknown): string {
  if (typeof error === 'object' && error !== null && 'message' in error) return String((error as ApiError).message)
  return 'The external-tool status service could not be reached.'
}

function statusTone(status: string): 'success' | 'warning' | 'danger' | 'neutral' {
  if (status === 'available') return 'success'
  if (status === 'unavailable') return 'warning'
  if (status === 'error') return 'danger'
  return 'neutral'
}

export function ExternalToolStatus() {
  const [tools, setTools] = useState<ExternalToolAvailability[] | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    const controller = new AbortController()
    void getExternalTools(controller.signal).then(setTools).catch((requestError: unknown) => {
      if (!(requestError instanceof DOMException && requestError.name === 'AbortError')) setError(message(requestError))
    })
    return () => controller.abort()
  }, [])

  return <section className="panel external-tool-status"><div className="panel-heading"><div><p className="eyebrow">Tool status</p><h2>External tools</h2></div><Server size={17} className="muted" /></div><p className="setting-description">Read-only availability from <code>GET /external-tools</code>. Tools are never started by this view; ordinary scans remain passive by default.</p>{tools === null && !error && <div className="external-tool-state" role="status"><RefreshCw size={15} className="spin" /> Checking configured tools…</div>}{error && <div className="external-tool-state error" role="alert"><AlertTriangle size={15} /> {error}</div>}{tools && !tools.length && <div className="external-tool-state" role="status"><CircleHelp size={15} /> No external tools are configured.</div>}{tools && tools.length > 0 && <div className="external-tool-list">{tools.map((tool) => { const status = tool.status.toLowerCase(); return <article className="external-tool-row" key={tool.identity.name}><div><strong>{tool.identity.name}</strong><span>{tool.identity.vendor} · adapter {tool.identity.adapter_version}</span>{tool.diagnostics?.[0] && <small>{tool.diagnostics[0].message}</small>}</div><Badge tone={statusTone(status)} dot>{status}</Badge></article> })}</div>}{tools && tools.length > 0 && tools.some((tool) => tool.status.toLowerCase() === 'unavailable') && <div className="external-tool-note"><CheckCircle2 size={14} /> Unavailable tools are reported only; no tool execution is attempted.</div>}</section>
}
