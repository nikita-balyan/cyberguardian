import React from 'react'
import { Shield, ScanSearch, History, FileText, PanelLeftClose, PanelLeftOpen, X } from 'lucide-react'

export const NAV_ITEMS = [
  { id: 'scan', label: 'New scan', icon: ScanSearch },
  { id: 'history', label: 'Scan history', icon: History },
  { id: 'reports', label: 'Reports & settings', icon: FileText },
]

function NavList({ active, onNavigate, collapsed }) {
  return (
    <nav className="flex-1 px-2 py-3 space-y-0.5" aria-label="Main">
      {NAV_ITEMS.map(({ id, label, icon: Icon }) => {
        const isActive = active === id
        return (
          <button
            key={id}
            onClick={() => onNavigate(id)}
            title={collapsed ? label : undefined}
            aria-current={isActive ? 'page' : undefined}
            className={`w-full flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors ${
              isActive
                ? 'bg-accent-soft text-accent'
                : 'text-muted hover:bg-surface-2 hover:text-fg'
            } ${collapsed ? 'justify-center px-0' : ''}`}
          >
            <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
            {!collapsed && <span className="truncate">{label}</span>}
          </button>
        )
      })}
    </nav>
  )
}

function Brand({ collapsed }) {
  return (
    <div className={`flex h-14 items-center gap-2 border-b border-line px-4 ${collapsed ? 'justify-center px-0' : ''}`}>
      <Shield className="h-5 w-5 text-accent shrink-0" aria-hidden="true" />
      {!collapsed && <span className="text-sm font-semibold tracking-tight">CyberGuardian</span>}
    </div>
  )
}

export default function Sidebar({ active, onNavigate, collapsed, onToggleCollapse, mobileOpen, onCloseMobile }) {
  return (
    <>
      {/* Desktop */}
      <aside
        className={`hidden md:flex flex-col shrink-0 border-r border-line bg-surface transition-[width] duration-200 ${
          collapsed ? 'w-16' : 'w-60'
        }`}
      >
        <Brand collapsed={collapsed} />
        <NavList active={active} onNavigate={onNavigate} collapsed={collapsed} />
        <div className="border-t border-line p-2">
          <button
            onClick={onToggleCollapse}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            className={`flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm text-muted hover:bg-surface-2 hover:text-fg ${
              collapsed ? 'justify-center px-0' : ''
            }`}
          >
            {collapsed ? <PanelLeftOpen className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}
            {!collapsed && <span>Collapse</span>}
          </button>
        </div>
      </aside>

      {/* Mobile drawer */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 md:hidden" role="dialog" aria-modal="true" aria-label="Navigation">
          <div className="absolute inset-0 bg-slate-900/50" onClick={onCloseMobile} />
          <aside className="relative flex h-full w-64 flex-col border-r border-line bg-surface">
            <div className="flex items-center justify-between">
              <Brand collapsed={false} />
              <button onClick={onCloseMobile} aria-label="Close menu" className="mr-3 rounded-md p-2 text-muted hover:bg-surface-2">
                <X className="h-4 w-4" />
              </button>
            </div>
            <NavList
              active={active}
              onNavigate={(id) => { onNavigate(id); onCloseMobile() }}
              collapsed={false}
            />
          </aside>
        </div>
      )}
    </>
  )
}