import React, { useState, useEffect, useMemo } from 'react'
import {
  RefreshCw, Globe, QrCode, MessageSquare, Shield, AlertCircle,
  ChevronDown, ChevronUp, ChevronRight, ArrowUpDown,
} from 'lucide-react'
import SeverityBadge from './SeverityBadge'
import { getScanHistory } from '../services/api'

const TYPE_META = {
  url: { label: 'URL', Icon: Globe },
  qr: { label: 'QR code', Icon: QrCode },
  message: { label: 'Message', Icon: MessageSquare },
}

const LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

// Maps any persisted schema (legacy or current) into a single shape.
const normalizeScan = (scan) => ({
  id: scan.id,
  scanType: String(scan.scan_type || scan.modality || 'unknown').toLowerCase(),
  target: scan.target,
  riskLevel: (scan.risk_level || scan.severity_level || 'LOW').toUpperCase(),
  riskScore: scan.risk_score ?? scan.composite_risk_score ?? 0,
  heuristicScore: scan.heuristic_score,
  mlProbability: scan.ml_probability,
  summary: scan.summary || scan.ai_explanation || '',
  evidence: scan.evidence || scan.evidence_json || null,
  createdAt: scan.created_at,
})

const formatDate = (dateStr) => {
  if (!dateStr) return '-'
  const d = new Date(dateStr)
  if (Number.isNaN(d.getTime())) return String(dateStr)
  return d.toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

const timeOf = (s) => {
  const t = new Date(s.createdAt).getTime()
  return Number.isNaN(t) ? 0 : t
}

const COMPARATORS = {
  createdAt: (a, b) => timeOf(a) - timeOf(b),
  scanType: (a, b) => a.scanType.localeCompare(b.scanType),
  target: (a, b) => String(a.target || '').localeCompare(String(b.target || '')),
  riskScore: (a, b) => (Number(a.riskScore) || 0) - (Number(b.riskScore) || 0),
}

function TypeTag({ type }) {
  const meta = TYPE_META[type] || { label: type, Icon: Shield }
  const { Icon } = meta
  return (
    <span className="inline-flex items-center gap-1.5 text-sm">
      <Icon className="h-3.5 w-3.5 text-muted" aria-hidden="true" />
      {meta.label}
    </span>
  )
}

function SortHeader({ label, k, sort, onSort, className = '' }) {
  const active = sort.key === k
  const Icon = !active ? ArrowUpDown : sort.dir === 'asc' ? ChevronUp : ChevronDown
  return (
    <th
      scope="col"
      aria-sort={active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}
      className={`px-4 py-2 text-left font-medium ${className}`}
    >
      <button type="button" onClick={() => onSort(k)} className="inline-flex items-center gap-1 hover:text-fg">
        {label}
        <Icon className={`h-3 w-3 ${active ? 'text-fg' : 'opacity-50'}`} aria-hidden="true" />
      </button>
    </th>
  )
}

const selectCls = 'rounded-md border border-line bg-bg px-2.5 py-1.5 text-sm focus:border-accent'

export default function HistoryTab() {
  const [historyData, setHistoryData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [expandedRow, setExpandedRow] = useState(null)
  const [query, setQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')
  const [levelFilter, setLevelFilter] = useState('all')
  const [sort, setSort] = useState({ key: 'createdAt', dir: 'desc' })

  const fetchHistory = async () => {
    setLoading(true)
    setError(null)
    try {
      setHistoryData(await getScanHistory())
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchHistory()
  }, [])

  const onSort = (key) =>
    setSort((s) =>
      s.key === key
        ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' }
        : { key, dir: key === 'createdAt' || key === 'riskScore' ? 'desc' : 'asc' }
    )

  const allScans = useMemo(() => (historyData?.scans || []).map(normalizeScan), [historyData])
  const typeOptions = useMemo(() => [...new Set(allScans.map((s) => s.scanType))], [allScans])

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    const filtered = allScans.filter(
      (s) =>
        (typeFilter === 'all' || s.scanType === typeFilter) &&
        (levelFilter === 'all' || s.riskLevel === levelFilter) &&
        (!q || String(s.target || '').toLowerCase().includes(q))
    )
    const cmp = COMPARATORS[sort.key]
    return [...filtered].sort((a, b) => (sort.dir === 'asc' ? cmp(a, b) : cmp(b, a)))
  }, [allScans, query, typeFilter, levelFilter, sort])

  const rb = historyData?.risk_breakdown || {}
  const pick = (k) => Number(rb[k] ?? rb[k.toUpperCase()] ?? 0)
  const totalScans = historyData?.total_scans || 0
  const stats = [
    { id: 'total', label: 'Total scans', value: totalScans },
    { id: 'high', level: 'HIGH', label: 'High / critical', value: pick('high') + pick('critical') },
    { id: 'medium', level: 'MEDIUM', label: 'Medium', value: pick('medium') },
    { id: 'low', level: 'LOW', label: 'Low', value: pick('low') },
  ]

  const filtersActive = query || typeFilter !== 'all' || levelFilter !== 'all'
  const clearFilters = () => {
    setQuery('')
    setTypeFilter('all')
    setLevelFilter('all')
  }

  return (
    <div className="space-y-4">
      {/* Summary */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {stats.map((s) => (
          <div key={s.id} className="rounded-lg border border-line bg-surface p-4">
            {s.level ? (
              <SeverityBadge level={s.level} label={s.label} />
            ) : (
              <span className="text-xs font-medium text-muted">{s.label}</span>
            )}
            <p className="mt-2 text-2xl font-semibold tabular-nums">{s.value}</p>
            <p className="text-xs text-muted">
              {s.id === 'total'
                ? 'Saved in the audit log'
                : totalScans > 0
                ? `${Math.round((s.value / totalScans) * 100)}% of total`
                : '0% of total'}
            </p>
          </div>
        ))}
      </div>

      {error && (
        <div role="alert" className="flex items-start gap-2 rounded-md bg-sev-critical-bg p-3 text-sm text-sev-critical">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          <span>{error}</span>
        </div>
      )}

      {/* Audit log */}
      <section className="rounded-lg border border-line bg-surface" aria-label="Audit log">
        <div className="flex flex-col gap-3 border-b border-line p-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h3 className="text-sm font-semibold">Audit log</h3>
            <p className="text-xs text-muted">
              Showing {rows.length} of {allScans.length} recent scans
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <label htmlFor="history-search" className="sr-only">Search targets</label>
            <input
              id="history-search"
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search targets"
              className="w-44 rounded-md border border-line bg-bg px-2.5 py-1.5 font-mono text-sm placeholder:font-sans placeholder:text-muted focus:border-accent"
            />
            <label htmlFor="history-type" className="sr-only">Filter by type</label>
            <select id="history-type" value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} className={selectCls}>
              <option value="all">All types</option>
              {typeOptions.map((t) => (
                <option key={t} value={t}>{TYPE_META[t]?.label || t}</option>
              ))}
            </select>
            <label htmlFor="history-level" className="sr-only">Filter by risk level</label>
            <select id="history-level" value={levelFilter} onChange={(e) => setLevelFilter(e.target.value)} className={selectCls}>
              <option value="all">All risk levels</option>
              {LEVELS.map((l) => (
                <option key={l} value={l}>{l.charAt(0) + l.slice(1).toLowerCase()}</option>
              ))}
            </select>
            <button
              type="button"
              onClick={fetchHistory}
              disabled={loading}
              className="inline-flex items-center gap-2 rounded-md border border-line bg-surface px-3 py-1.5 text-sm font-medium transition-colors hover:bg-surface-2 disabled:opacity-60"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
              Refresh
            </button>
          </div>
        </div>

        {loading && !historyData ? (
          <p className="p-10 text-center text-sm text-muted">Loading scan history…</p>
        ) : allScans.length === 0 ? (
          <div className="p-10 text-center">
            <p className="text-sm font-medium">No scans yet</p>
            <p className="mt-1 text-xs text-muted">Run a URL, message, or QR scan and it will show up here.</p>
          </div>
        ) : rows.length === 0 ? (
          <div className="p-10 text-center">
            <p className="text-sm font-medium">No scans match these filters</p>
            {filtersActive && (
              <button type="button" onClick={clearFilters} className="mt-2 text-sm text-accent underline underline-offset-2">
                Clear filters
              </button>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-sm">
              <thead>
                <tr className="border-b border-line bg-surface-2 text-xs text-muted">
                  <SortHeader label="Timestamp" k="createdAt" sort={sort} onSort={onSort} />
                  <SortHeader label="Type" k="scanType" sort={sort} onSort={onSort} />
                  <SortHeader label="Target" k="target" sort={sort} onSort={onSort} />
                  <SortHeader label="Risk" k="riskScore" sort={sort} onSort={onSort} />
                  <th scope="col" className="w-10 px-4 py-2"><span className="sr-only">Details</span></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((scan) => {
                  const isOpen = expandedRow === scan.id
                  const detailId = `scan-detail-${scan.id}`
                  return (
                    <React.Fragment key={scan.id}>
                      <tr
                        onClick={() => setExpandedRow(isOpen ? null : scan.id)}
                        className="cursor-pointer border-b border-line transition-colors hover:bg-surface-2"
                      >
                        <td className="whitespace-nowrap px-4 py-2.5 text-muted">{formatDate(scan.createdAt)}</td>
                        <td className="px-4 py-2.5"><TypeTag type={scan.scanType} /></td>
                        <td className="max-w-xs truncate px-4 py-2.5 font-mono text-xs" title={scan.target}>
                          {scan.target || '(empty)'}
                        </td>
                        <td className="px-4 py-2.5">
                          <span className="inline-flex items-center gap-2">
                            <SeverityBadge level={scan.riskLevel} />
                            <span className="tabular-nums text-muted">{scan.riskScore}</span>
                          </span>
                        </td>
                        <td className="px-4 py-2.5 text-muted">
                          {/* No onClick here: the click bubbles up to the row, so mouse and keyboard both work */}
                          <button
                            type="button"
                            aria-expanded={isOpen}
                            aria-controls={detailId}
                            aria-label={isOpen ? 'Hide scan details' : 'Show scan details'}
                            className="rounded p-1 hover:text-fg"
                          >
                            {isOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                          </button>
                        </td>
                      </tr>

                      {isOpen && (
                        <tr id={detailId} className="border-b border-line bg-surface-2">
                          <td colSpan={5} className="space-y-4 px-4 py-4">
                            <div>
                              <h4 className="mb-1 text-xs font-semibold text-muted">AI summary</h4>
                              <p className="whitespace-pre-wrap text-sm">{scan.summary || 'No summary was saved for this scan.'}</p>
                            </div>

                            <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                              <div>
                                <dt className="text-xs text-muted">Severity</dt>
                                <dd className="mt-0.5"><SeverityBadge level={scan.riskLevel} /></dd>
                              </div>
                              <div>
                                <dt className="text-xs text-muted">Composite score</dt>
                                <dd className="text-sm font-medium tabular-nums">{scan.riskScore}/100</dd>
                              </div>
                              <div>
                                <dt className="text-xs text-muted">Heuristic score</dt>
                                <dd className="text-sm font-medium tabular-nums">
                                  {scan.heuristicScore ?? 'N/A'}
                                </dd>
                              </div>
                              <div>
                                <dt className="text-xs text-muted">ML probability</dt>
                                <dd className="text-sm font-medium tabular-nums">
                                  {scan.mlProbability != null ? `${(scan.mlProbability * 100).toFixed(1)}%` : 'N/A'}
                                </dd>
                              </div>
                            </dl>

                            {scan.evidence && (
                              <div>
                                <h4 className="mb-1 text-xs font-semibold text-muted">Evidence (JSON)</h4>
                                <pre className="max-h-60 overflow-auto rounded-md border border-line bg-surface p-3 font-mono text-xs">
                                  {JSON.stringify(scan.evidence, null, 2)}
                                </pre>
                              </div>
                            )}
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}