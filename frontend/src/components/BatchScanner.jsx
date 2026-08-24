import React, { useState } from 'react'
import { scanBatch } from '../services/api'
import {
  Layers,
  Upload,
  FileText,
  Download,
  AlertTriangle,
  CheckCircle,
  Shield,
  Search,
  Loader2
} from 'lucide-react'

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
  const isOverLimit = itemsList.length > 50

  const handleRunBatchScan = async (e) => {
    e.preventDefault()
    setError(null)
    if (itemsList.length === 0) {
      setError('Please enter at least one target item or upload a file.')
      return
    }
    if (itemsList.length > 50) {
      setError('Batch limit exceeded. Maximum 50 items allowed.')
      return
    }
    setLoading(true)
    try {
      const data = await scanBatch(itemsList, scanType)
      setBatchResult(data)
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Batch scan failed.')
    } finally {
      setLoading(false)
    }
  }

  const handleExportCSV = () => {
    if (!batchResult || !batchResult.results) return
    const headers = ['Target', 'Risk Level', 'Risk Score', 'Threat Intel Flagged', 'Flags Count', 'Summary']
    const rows = batchResult.results.map((r) => [
      '"' + (r.target || '').replace(/"/g, '""') + '"',
      r.risk_level,
      r.risk_score,
      r.threat_intel_flagged ? 'YES' : 'NO',
      r.flags_count,
      '"' + (r.summary || '').replace(/"/g, '""') + '"'
    ])
    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n')
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `cyberguardian_batch_${scanType}_${Date.now()}.csv`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  }

  const filteredResults =
    batchResult?.results?.filter((r) => {
      const matchesRisk =
        riskFilter === 'ALL' ||
        (riskFilter === 'HIGH' && (r.risk_level === 'HIGH' || r.risk_level === 'CRITICAL')) ||
        r.risk_level === riskFilter
      const matchesSearch =
        r.target.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (r.summary && r.summary.toLowerCase().includes(searchQuery.toLowerCase()))
      return matchesRisk && matchesSearch
    }) || []

  const totalItems = batchResult ? batchResult.total_items : itemsList.length
  const highRiskCount =
    batchResult?.results?.filter((r) => r.risk_level === 'HIGH' || r.risk_level === 'CRITICAL').length || 0
  const mediumRiskCount = batchResult?.results?.filter((r) => r.risk_level === 'MEDIUM').length || 0
  const lowRiskCount = batchResult?.results?.filter((r) => r.risk_level === 'LOW').length || 0

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header Controls Card */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl backdrop-blur-md">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-xl font-bold text-white flex items-center space-x-2">
              <Layers className="w-5 h-5 text-indigo-400" />
              <span>Multi-Target Batch Threat Scanner</span>
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Bulk triage up to 50 URLs or messages concurrently with live threat intelligence and automated risk scoring.
            </p>
          </div>

          <div className="flex bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs">
            <button
              type="button"
              onClick={() => setScanType('url')}
              className={`px-3.5 py-1.5 rounded-lg font-semibold transition-all ${
                scanType === 'url' ? 'bg-indigo-600 text-white shadow-md' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Scan URLs
            </button>
            <button
              type="button"
              onClick={() => setScanType('message')}
              className={`px-3.5 py-1.5 rounded-lg font-semibold transition-all ${
                scanType === 'message' ? 'bg-indigo-600 text-white shadow-md' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Scan Messages
            </button>
          </div>
        </div>
      </div>

      {/* Input Selection & Form Card */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl backdrop-blur-md">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-2 text-sm font-semibold text-slate-200">
            <FileText className="w-4 h-4 text-indigo-400" />
            <span>Target Inputs</span>
          </div>

          <div className="flex bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs">
            <button
              type="button"
              onClick={() => setInputType('textarea')}
              className={`px-3 py-1.5 rounded-lg font-medium transition-all ${
                inputType === 'textarea' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Multiline Text
            </button>
            <button
              type="button"
              onClick={() => setInputType('file')}
              className={`px-3 py-1.5 rounded-lg font-medium transition-all ${
                inputType === 'file' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              File Upload (.txt / .csv)
            </button>
          </div>
        </div>

        <form onSubmit={handleRunBatchScan} className="space-y-4">
          {inputType === 'textarea' ? (
            <textarea
              rows={6}
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              placeholder={
                scanType === 'url'
                  ? 'Enter one URL per line (e.g. https://google.com\nhttp://paypal-security-update.xyz/login\nhttps://github.com)'
                  : 'Enter one message per line\nURGENT: Verify your account immediately at http://phish.com\nYour order #123 has shipped.'
              }
              className="w-full bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          ) : (
            <div className="border-2 border-dashed border-slate-800 hover:border-indigo-500/50 rounded-2xl p-8 text-center transition-all bg-slate-950/50">
              <input
                type="file"
                accept=".txt,.csv"
                onChange={handleFileUpload}
                className="hidden"
                id="batch-file-input"
              />
              <label htmlFor="batch-file-input" className="cursor-pointer flex flex-col items-center space-y-3">
                <div className="p-3 rounded-full bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                  <Upload className="w-6 h-6" />
                </div>
                <div>
                  <p className="text-sm font-semibold text-white">
                    {fileName ? `Loaded: ${fileName}` : 'Click to select or drag & drop a .txt or .csv file'}
                  </p>
                  <p className="text-xs text-slate-400 mt-1">One target per line (up to 50 items max)</p>
                </div>
              </label>
            </div>
          )}

          <div className="flex items-center justify-between text-xs">
            <span className={`font-semibold ${isOverLimit ? 'text-rose-400' : 'text-slate-400'}`}>
              Detected targets: {itemsList.length} / 50 max
            </span>
            {isOverLimit && (
              <span className="text-rose-400 font-medium flex items-center space-x-1">
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>Limit exceeded (max 50). Please remove extra lines.</span>
              </span>
            )}
          </div>

          {error && (
            <div className="p-3.5 rounded-xl bg-rose-950/50 border border-rose-800/60 text-rose-300 text-xs flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div className="flex justify-end pt-2">
            <button
              type="submit"
              disabled={loading || isOverLimit || itemsList.length === 0}
              className="inline-flex items-center space-x-2 px-6 py-3 rounded-xl bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-500 hover:to-blue-500 text-white font-semibold text-sm shadow-lg shadow-indigo-600/25 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Analyzing {itemsList.length} Targets Concurrently...</span>
                </>
              ) : (
                <>
                  <Shield className="w-4 h-4" />
                  <span>Run Batch Threat Scan</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Batch Results Section */}
      {batchResult && (
        <div className="space-y-6 animate-fadeIn">
          {/* Summary Metric Counters */}
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl backdrop-blur-md">
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Targets</p>
              <p className="text-3xl font-black text-white mt-1">{totalItems}</p>
            </div>
            <div className="bg-slate-900/80 border border-rose-900/40 rounded-2xl p-5 shadow-xl backdrop-blur-md">
              <p className="text-xs font-semibold text-rose-400 uppercase tracking-wider">Critical / High Risk</p>
              <p className="text-3xl font-black text-rose-400 mt-1">{highRiskCount}</p>
            </div>
            <div className="bg-slate-900/80 border border-amber-900/40 rounded-2xl p-5 shadow-xl backdrop-blur-md">
              <p className="text-xs font-semibold text-amber-400 uppercase tracking-wider">Medium Risk</p>
              <p className="text-3xl font-black text-amber-400 mt-1">{mediumRiskCount}</p>
            </div>
            <div className="bg-slate-900/80 border border-emerald-900/40 rounded-2xl p-5 shadow-xl backdrop-blur-md">
              <p className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">Low Risk</p>
              <p className="text-3xl font-black text-emerald-400 mt-1">{lowRiskCount}</p>
            </div>
          </div>

          {/* Filter, Search & Export Actions */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-4 shadow-xl backdrop-blur-md flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
              <div className="relative flex-1 md:w-64">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search targets or summaries..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-4 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                />
              </div>

              <div className="flex items-center space-x-1 bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs">
                {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((lvl) => (
                  <button
                    key={lvl}
                    type="button"
                    onClick={() => setRiskFilter(lvl)}
                    className={`px-3 py-1.5 rounded-lg font-semibold transition-all ${
                      riskFilter === lvl ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {lvl}
                  </button>
                ))}
              </div>
            </div>

            <button
              type="button"
              onClick={handleExportCSV}
              disabled={!batchResult || !batchResult.results}
              className="inline-flex items-center space-x-2 px-4 py-2 rounded-xl bg-emerald-600/20 hover:bg-emerald-600/30 border border-emerald-500/30 text-emerald-300 font-semibold text-xs transition-all w-full md:w-auto justify-center disabled:opacity-50"
            >
              <Download className="w-4 h-4" />
              <span>Export Batch Results to CSV</span>
            </button>
          </div>

          {/* Forensic Results Table */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl shadow-xl backdrop-blur-md overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-950/60 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    <th className="py-3.5 px-6">Risk Severity</th>
                    <th className="py-3.5 px-6">Target</th>
                    <th className="py-3.5 px-6">Threat Intel Hit</th>
                    <th className="py-3.5 px-6">Flags</th>
                    <th className="py-3.5 px-6">Key Finding Summary</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-sm">
                  {filteredResults.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="py-8 text-center text-slate-500 text-xs">
                        No batch targets matching current filter/search.
                      </td>
                    </tr>
                  ) : (
                    filteredResults.map((res, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-4 px-6 whitespace-nowrap">
                          <div className="flex items-center space-x-2">
                            <span
                              className={`px-2.5 py-1 rounded-full text-xs font-bold ${
                                res.risk_level === 'CRITICAL'
                                  ? 'bg-rose-950 text-rose-400 border border-rose-800'
                                  : res.risk_level === 'HIGH'
                                  ? 'bg-red-950 text-red-400 border border-red-800'
                                  : res.risk_level === 'MEDIUM'
                                  ? 'bg-amber-950 text-amber-400 border border-amber-800'
                                  : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                              }`}
                            >
                              {res.risk_level}
                            </span>
                            <span className="text-xs font-mono font-bold text-slate-300">
                              {res.risk_score}/100
                            </span>
                          </div>
                        </td>
                        <td className="py-4 px-6 font-mono text-xs text-slate-200 max-w-xs truncate" title={res.target}>
                          {res.target}
                        </td>
                        <td className="py-4 px-6 whitespace-nowrap">
                          {res.threat_intel_flagged ? (
                            <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-950/60 text-rose-400 border border-rose-800/50">
                              <AlertTriangle className="w-3 h-3" />
                              <span>Flagged</span>
                            </span>
                          ) : (
                            <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950/60 text-emerald-400 border border-emerald-800/50">
                              <CheckCircle className="w-3 h-3" />
                              <span>Clean</span>
                            </span>
                          )}
                        </td>
                        <td className="py-4 px-6 whitespace-nowrap font-mono text-xs text-slate-400">
                          {res.flags_count} flags
                        </td>
                        <td className="py-4 px-6 text-xs text-slate-400 max-w-md">
                          {res.summary}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}