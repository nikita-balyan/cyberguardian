import React, { useState } from 'react'
import { Upload, Download, AlertCircle, Loader2 } from 'lucide-react'
import SeverityBadge from './SeverityBadge'
import { scanBatch } from '../services/api'

const MAX_ITEMS = 50
const FILTERS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

function Segmented({ label, options, value, onChange }) {
  return (
    <div role="group" aria-label={label} className="inline-flex rounded-md border border-line bg-surface-2 p-0.5 text-sm">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          aria-pressed={value === o.value}
          onClick={() => onChange(o.value)}
          className={`rounded px-3 py-1 font-medium transition-colors ${
            value === o.value ? 'bg-surface text-fg shadow-sm' : 'text-muted hover:text-fg'
          }`}
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}

// Stops spreadsheet apps from running a cell that starts with = + - @ as a formula
const csvCell = (v) => {
  let s = String(v ?? '')
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s
  return '"' + s.replace(/"/g, '""') + '"'
}

export default function BatchScanner() {
  const [scanType, setScanType] = useState('url')
  const [inputType, setInputType] = useState('textarea')
  const [rawText, setRawText] = useState('')
  const [fileName, setFileName] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [batchResult, setBatchResult] = useState(null)
  const [riskFilter, setRiskFilter] = useState('ALL')
  const [searchQuery, setSearchQuery] = useState('')

  const handleFileUpload = (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    setFileName(file.name)
    const reader = new FileReader()
    reader.onload = (event) => {
      const content = event.target?.result
      if (typeof content === 'string') setRawText(content)
    }
    reader.readAsText(file)
  }

  const itemsList = rawText
    .split('\n')
    .map((i) => i.trim())
    .filter((i) => i && !i.startsWith('#'))
  const isOverLimit = itemsList.length > MAX_ITEMS

  const handleRunBatchScan = async (e) => {
    e.preventDefault()
    setError(null)
    if (itemsList.length === 0) {
      setError('Enter at least one target, or upload a file.')
      return
    }
    if (isOverLimit) {
      setError(`Too many targets. The limit is ${MAX_ITEMS} per batch.`)
      return
    }
    setLoading(true)
    try {
      setBatchResult(await scanBatch(itemsList, scanType))
      setRiskFilter('ALL')
      setSearchQuery('')
    } catch (err) {
      setError(err.message || 'The batch scan failed.')
    } finally {
      setLoading(false)
    }
  }

  const handleExportCSV = () => {
    if (!batchResult?.results) return
    const headers = ['Target', 'Risk Level', 'Risk Score', 'Threat Intel Flagged', 'Flags Count', 'Summary']
    const rows = batchResult.results.map((r) => [
      csvCell(r.target),
      csvCell(r.risk_level),
      csvCell(r.risk_score),
      csvCell(r.threat_intel_flagged ? 'YES' : 'NO'),
      csvCell(r.flags_count),
      csvCell(r.summary),
    ])
    const csv = [headers.map(csvCell).join(','), ...rows.map((r) => r.join(','))].join('\n')
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8;' }))
    const link = document.createElement('a')
    link.href = url
    link.download = `cyberguardian_batch_${scanType}_${Date.now()}.csv`
    document.body.appendChild(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(url)
  }

  const results = batchResult?.results || []
  const q = searchQuery.trim().toLowerCase()
  const filteredResults = results.filter((r) => {
    const level = String(r.risk_level || '').toUpperCase()
    const matchesRisk = riskFilter === 'ALL' || level === riskFilter
    const matchesSearch =
      !q || String(r.target || '').toLowerCase().includes(q) || String(r.summary || '').toLowerCase().includes(q)
    return matchesRisk && matchesSearch
  })

  const count = (...levels) => results.filter((r) => levels.includes(String(r.risk_level || '').toUpperCase())).length
  const stats = [
    { id: 'total', label: 'Total targets', value: batchResult?.total_items ?? results.length },
    { id: 'high', level: 'HIGH', label: 'High / critical', value: count('HIGH', 'CRITICAL') },
    { id: 'medium', level: 'MEDIUM', label: 'Medium', value: count('MEDIUM') },
    { id: 'low', level: 'LOW', label: 'Low', value: count('LOW') },
  ]

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-line bg-surface p-5">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <Segmented
            label="Scan type"
            value={scanType}
            onChange={setScanType}
            options={[
              { value: 'url', label: 'URLs' },
              { value: 'message', label: 'Messages' },
            ]}
          />
          <Segmented
            label="Input method"
            value={inputType}
            onChange={setInputType}
            options={[
              { value: 'textarea', label: 'Paste text' },
              { value: 'file', label: 'Upload file' },
            ]}
          />
        </div>

        <form onSubmit={handleRunBatchScan} noValidate>
          {inputType === 'textarea' ? (
            <>
              <label htmlFor="batch-input" className="mb-1.5 block text-sm font-medium">
                {scanType === 'url' ? 'URLs, one per line' : 'Messages, one per line'}
              </label>
              <textarea
                id="batch-input"
                rows={7}
                value={rawText}
                onChange={(e) => setRawText(e.target.value)}
                spellCheck={false}
                placeholder={
                  scanType === 'url'
                    ? 'https://example.com\nhttp://paypal-security-update.xyz/login'
                    : 'URGENT: Verify your account at http://phish.example\nYour order #123 has shipped.'
                }
                className="w-full resize-y rounded-md border border-line bg-bg px-3 py-2 font-mono text-xs placeholder:text-muted focus:border-accent"
              />
            </>
          ) : (
            <>
              <input
                type="file"
                accept=".txt,.csv"
                onChange={handleFileUpload}
                className="sr-only"
                id="batch-file-input"
              />
              <label
                htmlFor="batch-file-input"
                className="flex cursor-pointer flex-col items-center gap-2 rounded-md border border-dashed border-line px-6 py-10 text-center transition-colors hover:bg-surface-2 focus-within:ring-2 focus-within:ring-accent"
              >
                <Upload className="h-5 w-5 text-muted" aria-hidden="true" />
                <span className="text-sm font-medium">
                  {fileName ? `Loaded: ${fileName}` : 'Choose a .txt or .csv file'}
                </span>
                <span className="text-xs text-muted">One target per line. Lines starting with # are ignored.</span>
              </label>
            </>
          )}

          <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
            <p className={`text-xs ${isOverLimit ? 'font-medium text-sev-critical' : 'text-muted'}`}>
              {itemsList.length} of {MAX_ITEMS} targets
              {isOverLimit && ' · Remove extra lines to continue'}
            </p>
            <button
              type="submit"
              disabled={loading || isOverLimit || itemsList.length === 0}
              className="inline-flex items-center justify-center gap-2 rounded-md bg-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
              {loading ? `Scanning ${itemsList.length} targets…` : 'Run batch scan'}
            </button>
          </div>

          {error && (
            <div role="alert" className="mt-4 flex items-start gap-2 rounded-md bg-sev-critical-bg p-3 text-sm text-sev-critical">
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
              <span>{error}</span>
            </div>
          )}
        </form>
      </div>

      {batchResult && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            {stats.map((s) => (
              <div key={s.id} className="rounded-lg border border-line bg-surface p-4">
                {s.level ? (
                  <SeverityBadge level={s.level} label={s.label} />
                ) : (
                  <span className="text-xs font-medium text-muted">{s.label}</span>
                )}
                <p className="mt-2 text-2xl font-semibold tabular-nums">{s.value}</p>
              </div>
            ))}
          </div>

          <section className="rounded-lg border border-line bg-surface" aria-label="Batch results">
            <div className="flex flex-col gap-3 border-b border-line p-4 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <h3 className="text-sm font-semibold">Results</h3>
                <p className="text-xs text-muted">
                  Showing {filteredResults.length} of {results.length}
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <label htmlFor="batch-search" className="sr-only">Search results</label>
                <input
                  id="batch-search"
                  type="search"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search targets or summaries"
                  className="w-52 rounded-md border border-line bg-bg px-2.5 py-1.5 text-sm placeholder:text-muted focus:border-accent"
                />
                <label htmlFor="batch-risk" className="sr-only">Filter by risk level</label>
                <select
                  id="batch-risk"
                  value={riskFilter}
                  onChange={(e) => setRiskFilter(e.target.value)}
                  className="rounded-md border border-line bg-bg px-2.5 py-1.5 text-sm focus:border-accent"
                >
                  {FILTERS.map((f) => (
                    <option key={f} value={f}>
                      {f === 'ALL' ? 'All risk levels' : f.charAt(0) + f.slice(1).toLowerCase()}
                    </option>
                  ))}
                </select>
                <button
                  type="button"
                  onClick={handleExportCSV}
                  disabled={results.length === 0}
                  className="inline-flex items-center gap-2 rounded-md border border-line bg-surface px-3 py-1.5 text-sm font-medium transition-colors hover:bg-surface-2 disabled:opacity-50"
                >
                  <Download className="h-3.5 w-3.5" aria-hidden="true" />
                  Export CSV
                </button>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full min-w-[720px] text-sm">
                <thead>
                  <tr className="border-b border-line bg-surface-2 text-left text-xs text-muted">
                    <th scope="col" className="px-4 py-2 font-medium">Risk</th>
                    <th scope="col" className="px-4 py-2 font-medium">Target</th>
                    <th scope="col" className="px-4 py-2 font-medium">Threat feeds</th>
                    <th scope="col" className="px-4 py-2 font-medium">Flags</th>
                    <th scope="col" className="px-4 py-2 font-medium">Summary</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredResults.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-4 py-8 text-center text-sm text-muted">
                        No results match these filters.
                      </td>
                    </tr>
                  ) : (
                    filteredResults.map((res, idx) => (
                      <tr key={idx} className="border-b border-line last:border-b-0 align-top">
                        <td className="whitespace-nowrap px-4 py-2.5">
                          <span className="inline-flex items-center gap-2">
                            <SeverityBadge level={res.risk_level} />
                            <span className="tabular-nums text-muted">{res.risk_score}</span>
                          </span>
                        </td>
                        <td className="max-w-xs truncate px-4 py-2.5 font-mono text-xs" title={res.target}>
                          {res.target}
                        </td>
                        <td className="whitespace-nowrap px-4 py-2.5">
                          {res.threat_intel_flagged ? (
                            <SeverityBadge level="CRITICAL" label="Flagged" />
                          ) : (
                            <SeverityBadge level="LOW" label="Clean" />
                          )}
                        </td>
                        <td className="whitespace-nowrap px-4 py-2.5 tabular-nums">{res.flags_count}</td>
                        <td className="max-w-md px-4 py-2.5 text-muted">{res.summary}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      )}
    </div>
  )
}