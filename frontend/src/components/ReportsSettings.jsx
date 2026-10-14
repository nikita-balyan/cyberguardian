import React, { useState } from 'react'
import { Download, Sun, Moon, Loader2, AlertCircle, Check } from 'lucide-react'
import { getScanHistory, checkHealth, clearHistory } from '../services/api'

const stamp = () => new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)

function download(blob, filename) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

// Stops spreadsheet apps from running a cell that starts with = + - @ as a formula
const csvCell = (v) => {
  let s = String(v ?? '')
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s
  return '"' + s.replace(/"/g, '""') + '"'
}

const btn =
  'inline-flex items-center justify-center gap-2 rounded-md px-3 py-1.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-60'
const btnOutline = `${btn} border border-line bg-surface hover:bg-surface-2`

function Section({ title, description, children }) {
  return (
    <section className="rounded-lg border border-line bg-surface p-5">
      <h3 className="text-sm font-semibold">{title}</h3>
      <p className="mb-4 mt-0.5 text-xs text-muted">{description}</p>
      {children}
    </section>
  )
}

export default function ReportsSettings({ theme, onToggleTheme }) {
  const [busy, setBusy] = useState(null) // 'csv' | 'json' | null
  const [error, setError] = useState(null)
  const [done, setDone] = useState(null)
  const [health, setHealth] = useState({ state: 'idle', message: '' })

  const [clearing, setClearing] = useState(false)
  const [clearedCount, setClearedCount] = useState(null)
  const [clearError, setClearError] = useState(null)

  const handleClear = async () => {
    if (!window.confirm("Delete every scan saved for this browser? This can't be undone.")) return
    setClearing(true)
    setClearError(null)
    setClearedCount(null)
    try {
      const res = await clearHistory()
      setClearedCount(res?.deleted ?? 0)
    } catch (err) {
      setClearError(err.message || 'Could not delete your scan history.')
    } finally {
      setClearing(false)
    }
  }

  const exportHistory = async (kind) => {
    setBusy(kind)
    setError(null)
    setDone(null)
    try {
      const data = await getScanHistory()
      const scans = data?.scans || []
      if (scans.length === 0) {
        setError('There are no saved scans to export yet.')
        return
      }

      if (kind === 'json') {
        download(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }), `cyberguardian_history_${stamp()}.json`)
      } else {
        const headers = ['ID', 'Timestamp', 'Type', 'Target', 'Risk Level', 'Risk Score', 'Summary']
        const rows = scans.map((s) => [
          s.id,
          s.created_at,
          s.scan_type || s.modality,
          s.target,
          s.risk_level || s.severity_level,
          s.risk_score ?? s.composite_risk_score,
          s.summary || s.ai_explanation,
        ])
        const csv = [headers.map(csvCell).join(','), ...rows.map((r) => r.map(csvCell).join(','))].join('\n')
        download(new Blob([csv], { type: 'text/csv;charset=utf-8;' }), `cyberguardian_history_${stamp()}.csv`)
      }
      setDone(kind)
      setTimeout(() => setDone(null), 3000)
    } catch (err) {
      setError(err.message || 'Could not export scan history.')
    } finally {
      setBusy(null)
    }
  }

  const testConnection = async () => {
    setHealth({ state: 'checking', message: '' })
    try {
      await checkHealth()
      setHealth({ state: 'ok', message: 'The backend responded.' })
    } catch (err) {
      setHealth({ state: 'fail', message: err.message || 'The backend did not respond.' })
    }
  }

  return (
    <div className="max-w-3xl space-y-4">
      <Section
        title="Export scan history"
        description="Download your saved scans. Exports include the most recent scans the server returns."
      >
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={() => exportHistory('csv')} disabled={busy !== null} className={btnOutline}>
            {busy === 'csv' ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : done === 'csv' ? <Check className="h-4 w-4" aria-hidden="true" /> : <Download className="h-4 w-4" aria-hidden="true" />}
            {done === 'csv' ? 'CSV exported' : 'Export CSV'}
          </button>
          <button type="button" onClick={() => exportHistory('json')} disabled={busy !== null} className={btnOutline}>
            {busy === 'json' ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : done === 'json' ? <Check className="h-4 w-4" aria-hidden="true" /> : <Download className="h-4 w-4" aria-hidden="true" />}
            {done === 'json' ? 'JSON exported' : 'Export JSON'}
          </button>
        </div>
        {error && (
          <div role="alert" className="mt-3 flex items-start gap-2 rounded-md bg-sev-critical-bg p-3 text-sm text-sev-critical">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
            <span>{error}</span>
          </div>
        )}
        <p className="mt-3 text-xs text-muted">
          To export a single scan as a PDF, use the buttons on that scan's result.
        </p>
      </Section>
      
      <Section title="Your data" description="Scans are saved only for this browser and expire automatically.">
        <button type="button" onClick={handleClear} disabled={clearing} className={btnOutline}>
          {clearing && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
          {clearing ? 'Deleting…' : 'Delete my scan history'}
        </button>
        {clearedCount !== null && (
          <p role="status" className="mt-3 text-xs text-muted">
            Deleted {clearedCount} saved {clearedCount === 1 ? 'scan' : 'scans'}.
          </p>
        )}
        {clearError && (
          <div role="alert" className="mt-3 flex items-start gap-2 rounded-md bg-sev-critical-bg p-3 text-sm text-sev-critical">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
            <span>{clearError}</span>
          </div>
        )}
      </Section>

      <Section title="Appearance" description="Choose how CyberGuardian looks. Your choice is saved in this browser.">
        <div role="group" aria-label="Theme" className="inline-flex rounded-md border border-line bg-surface-2 p-0.5 text-sm">
          {[
            { value: 'light', label: 'Light', Icon: Sun },
            { value: 'dark', label: 'Dark', Icon: Moon },
          ].map(({ value, label, Icon }) => (
            <button
              key={value}
              type="button"
              aria-pressed={theme === value}
              onClick={() => theme !== value && onToggleTheme()}
              className={`inline-flex items-center gap-2 rounded px-3 py-1 font-medium transition-colors ${
                theme === value ? 'bg-surface text-fg shadow-sm' : 'text-muted hover:text-fg'
              }`}
            >
              <Icon className="h-3.5 w-3.5" aria-hidden="true" />
              {label}
            </button>
          ))}
        </div>
      </Section>

      <Section title="Backend connection" description="Check that the CyberGuardian API is reachable.">
        <div className="flex flex-wrap items-center gap-3">
          <button type="button" onClick={testConnection} disabled={health.state === 'checking'} className={btnOutline}>
            {health.state === 'checking' && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
            {health.state === 'checking' ? 'Testing…' : 'Test connection'}
          </button>
          {health.state === 'ok' && (
            <span role="status" className="rounded bg-sev-low-bg px-2 py-1 text-xs font-medium text-sev-low">
              {health.message}
            </span>
          )}
          {health.state === 'fail' && (
            <span role="alert" className="rounded bg-sev-critical-bg px-2 py-1 text-xs font-medium text-sev-critical">
              {health.message}
            </span>
          )}
        </div>
      </Section>
    </div>
  )
}