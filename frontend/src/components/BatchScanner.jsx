import React, { useState } from 'react'
import { scanBatch } from '../services/api'
import {
  Layers, Upload, FileText, Download, AlertTriangle,
  CheckCircle, Shield, Search, Filter, Loader2, Globe, MessageSquare
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

  const itemsList = rawText.split('\n').map(i => i.trim()).filter(i => i && !i.startsWith('#'))
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
      setError(err.message || 'Batch scan failed.')
    } finally {
      setLoading(false)
    }
  }

  const handleExportCSV = () => {
    if (!batchResult || !batchResult.results) return
    const headers = ['Target', 'Risk Level', 'Risk Score', 'Threat Intel Flagged', 'Flags Count', 'Summary']
    const rows = batchResult.results.map(r => [
      '"' + r.target.replace(/"/g, '""') + '"',
      r.risk_level, r.risk_score,
      r.threat_intel_flagged ? 'YES' : 'NO',
      r.flags_count,
      '"' + r.summary.replace(/"/g, '""') + '"'
    ])
    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n')
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'cyberguardian_batch_results_' + Date.now() + '.csv'
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  }

  const filteredResults = batchResult?.results?.filter(r => {
    const matchesRisk = riskFilter === 'ALL' || (riskFilter === 'HIGH' && (r.risk_level === 'HIGH' || r.risk_level === 'CRITICAL')) || r.risk_level === riskFilter
    const matchesSearch = r.target.toLowerCase().includes(searchQuery.toLowerCase()) || r.summary.toLowerCase().includes(searchQuery.toLowerCase())
    return matchesRisk && matchesSearch
  }) || []

   // Calculate summary counts
   const totalItems = itemsList.length
   const highRiskCount = batchResult?.results?.filter(r => r.risk_level === 'HIGH' || r.risk_level === 'CRITICAL').length || 0
   const mediumRiskCount = batchResult?.results?.filter(r => r.risk_level === 'MEDIUM').length || 0
   const lowRiskCount = batchResult?.results?.filter(r => r.risk_level === 'LOW').length || 0

   return (
    <div className="batch-scanner-container">
      <header className="batch-scanner-header">
        <h2>Batch Threat Scanner</h2>
        <div className="scan-type-toggle">
          <label htmlFor="scanType">Scan Type:</label>
          <select id="scanType" value={scanType} onChange={(e) => setScanType(e.target.value)}>
            <option value="url">URLs</option>
            <option value="message">Messages</option>
          </select>
        </div>
      </header>

      {/* Triage Summary Cards */}
      <div className="triage-summary-cards">
        <div className="card">
          <h3>Total Targets</h3>
          <p className="count">{totalItems}</p>
        </div>
        <div className="card">
          <h3>Critical/High Risk</h3>
          <p className="count">{highRiskCount}</p>
        </div>
        <div className="card">
          <h3>Medium Risk</h3>
          <p className="count">{mediumRiskCount}</p>
        </div>
        <div className="card">
          <h3>Low Risk</h3>
          <p className="count">{lowRiskCount}</p>
        </div>
      </div>

      {/* Interactive Data Table */}
      <div className="data-table-container">
        <table className="risk-score-table">
          <thead>
            <tr>
              <th>Target</th>
              <th>Risk Severity</th>
              <th>Score (0-100)</th>
              <th>Threat Intel Flagged</th>
              <th>Key Finding Summary</th>
            </tr>
          </thead>
          <tbody>
            {filteredResults.map((row) => (
              <tr key={row.target}>
                <td>{row.target}</td>
                <td>
                  <span className={`risk-badge ${row.risk_level}`}>
                    {row.risk_level.charAt(0).toUpperCase() + row.risk_level.slice(1)}
                  </span>
                </td>
                <td>{row.risk_score}</td>
                <td>
                  <span className={row.threat_intel_flagged ? 'threat-intel-flag' : ''}>
                    {row.threat_intel_flagged ? '✅ YES' : '❌ NO'}
                  </span>
                </td>
                <td>{row.summary.slice(0, 100) + '...'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Filters */}
      <div className="filters">
        <div className="filter-group">
          <label>Risk Level Filter:</label>
          <select value={riskFilter} onChange={(e) => setRiskFilter(e.target.value)}>
            <option value="ALL">All Risk Levels</option>
            <option value="LOW">Low</option>
            <option value="MEDIUM">Medium</option>
            <option value="HIGH">High</option>
            <option value="CRITICAL">Critical</option>
          </select>
        </div>
        <div className="search-input">
          <input
            type="text"
            placeholder="Search targets or summaries..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
      </div>

      {/* Action Buttons */}
      <div className="action-buttons">
        <button onClick={handleExportCSV} disabled={!batchResult || !batchResult.results}>
          Export Batch Results to CSV
        </button>
      </div>
    </div>
  )
}
