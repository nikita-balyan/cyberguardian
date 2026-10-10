import React, { useState, useEffect } from 'react'
import { Menu, Sun, Moon } from 'lucide-react'
import { checkHealth } from '../services/api'

const STATUS = {
  online: { label: 'API connected', dot: 'bg-sev-low', text: 'text-sev-low', bg: 'bg-sev-low-bg' },
  offline: { label: 'API offline', dot: 'bg-sev-critical', text: 'text-sev-critical', bg: 'bg-sev-critical-bg' },
  checking: { label: 'Checking API', dot: 'bg-sev-medium', text: 'text-sev-medium', bg: 'bg-sev-medium-bg' },
}

function ApiStatus() {
  const [status, setStatus] = useState('checking')

  useEffect(() => {
    let mounted = true
    const verify = async () => {
      try {
        await checkHealth()
        if (mounted) setStatus('online')
      } catch {
        if (mounted) setStatus('offline')
      }
    }
    verify()
    const interval = setInterval(verify, 10000)
    return () => {
      mounted = false
      clearInterval(interval)
    }
  }, [])

  const s = STATUS[status]
  return (
    <span className={`inline-flex items-center gap-2 rounded px-2 py-1 text-xs font-medium ${s.bg} ${s.text}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} aria-hidden="true" />
      {s.label}
    </span>
  )
}

export default function TopBar({ title, theme, onToggleTheme, onOpenMobile }) {
  return (
    <header className="flex h-14 shrink-0 items-center gap-3 border-b border-line bg-surface px-4 md:px-8">
      <button
        onClick={onOpenMobile}
        aria-label="Open menu"
        className="rounded-md p-2 text-muted hover:bg-surface-2 hover:text-fg md:hidden"
      >
        <Menu className="h-5 w-5" />
      </button>
      <h1 className="text-sm font-semibold">{title}</h1>
      <div className="ml-auto flex items-center gap-3">
        <ApiStatus />
        <button
          onClick={onToggleTheme}
          aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          className="rounded-md p-2 text-muted hover:bg-surface-2 hover:text-fg"
        >
          {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </button>
      </div>
    </header>
  )
}