import { Activity, BookOpen, FileSearch, History, LayoutDashboard, Menu, Plus, ScanLine, Settings, Shield, Sparkles, X } from 'lucide-react'

export type View = 'overview' | 'new-scan' | 'history' | 'findings' | 'intelligence' | 'settings' | 'about' | 'detail'

interface SidebarProps {
  view: View
  onNavigate: (view: View) => void
  open: boolean
  onClose: () => void
}

const primary = [
  { id: 'overview' as const, label: 'Overview', icon: LayoutDashboard },
  { id: 'new-scan' as const, label: 'New scan', icon: ScanLine },
  { id: 'history' as const, label: 'Scan history', icon: History },
  { id: 'findings' as const, label: 'Findings', icon: FileSearch },
  { id: 'intelligence' as const, label: 'Intelligence', icon: Sparkles },
]

export function Sidebar({ view, onNavigate, open, onClose }: SidebarProps) {
  return <>
    <button className={`mobile-menu ${open ? 'is-open' : ''}`} onClick={onClose} aria-label="Close navigation">{open ? <X size={19} /> : <Menu size={19} />}</button>
    <aside className={`sidebar ${open ? 'sidebar-open' : ''}`}>
      <div className="brand"><div className="brand-mark"><Shield size={18} /></div><div><strong>SENTINEL</strong><span>SECURITY OPERATIONS</span></div></div>
      <div className="workspace-pill"><span className="live-dot" /> <span>Local workspace</span><Activity size={14} /></div>
      <nav aria-label="Primary navigation">
        <p className="nav-label">Workspace</p>
        {primary.map(({ id, label, icon: Icon }) => <button key={id} className={`nav-item ${view === id ? 'active' : ''}`} onClick={() => { onNavigate(id); onClose() }}><Icon size={17} /><span>{label}</span>{id === 'findings' && <span className="nav-count">API</span>}</button>)}
      </nav>
      <div className="sidebar-bottom">
        <p className="nav-label">Resources</p>
        <button className={`nav-item ${view === 'settings' ? 'active' : ''}`} onClick={() => { onNavigate('settings'); onClose() }}><Settings size={17} /><span>Settings</span></button>
        <button className={`nav-item ${view === 'about' ? 'active' : ''}`} onClick={() => { onNavigate('about'); onClose() }}><BookOpen size={17} /><span>About SENTINEL</span></button>
        <button className="new-scan-button" onClick={() => { onNavigate('new-scan'); onClose() }}><Plus size={17} /><span>Start a scan</span><kbd>⌘ N</kbd></button>
        <div className="sidebar-footer"><span className="footer-mark">S</span><div><strong>Authorized testing only</strong><small>Use against targets you own.</small></div></div>
      </div>
    </aside>
  </>
}
