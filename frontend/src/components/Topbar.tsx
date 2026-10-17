import { Bell, HelpCircle, Search } from 'lucide-react'
import type { View } from './Sidebar'

export function Topbar({ view, onNavigate }: { view: View; onNavigate: (view: View) => void }) {
  const titles: Record<View, [string, string]> = {
    overview: ['Overview', 'Monitor your authorized assessments'],
    'new-scan': ['New scan', 'Run a focused, non-destructive assessment'],
    history: ['Scan history', 'Review scans retained in this session'],
    findings: ['Findings explorer', 'Review and prioritize observed signals'],
    settings: ['Settings', 'Understand this local SENTINEL workspace'],
    about: ['About SENTINEL', 'Built for transparent, authorized testing'],
    detail: ['Scan detail', 'Live status and safe evidence'],
  }
  const [title, subtitle] = titles[view]
  return <header className="topbar"><div className="crumb"><span>SENTINEL</span><span className="crumb-sep">/</span><strong>{title}</strong><p>{subtitle}</p></div><div className="top-actions"><button className="icon-button" aria-label="Search (not available)"><Search size={17} /></button><button className="icon-button" aria-label="Help" onClick={() => onNavigate('about')}><HelpCircle size={17} /></button><button className="icon-button" aria-label="Notifications"><Bell size={17} /></button><div className="avatar">SO</div></div></header>
}
