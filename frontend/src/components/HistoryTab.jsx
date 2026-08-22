import React, { useState, useEffect } from 'react'
import {
  Activity,
  AlertTriangle,
  AlertOctagon,
  CheckCircle2,
  RefreshCw,
  Globe,
  QrCode,
  MessageSquare,
  Clock,
  ChevronDown,
  ChevronUp,
  Shield,
  Layers,
  FileText,
  AlertCircle
} from 'lucide-react'
import { getScanHistory } from '../services/api'

export default function HistoryTab() {
  const [historyData, setHistoryData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [expandedRow, setExpandedRow] = useState(null)

  const fetchHistory = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await getScanHistory()
      setHistoryData(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchHistory()
  }, [])

  const getRiskBadge = (level, score) => {
    const lvl = level?.toUpperCase()
    if (lvl === 'CRITICAL' || lvl === 'HIGH') {
      return (
        <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-bold bg-rose-500/15 border border-rose-500/30 text-rose-400">
          <AlertOctagon className="w-3 h-3" />
          <span>{level} ({score})</span>
        </span>
      )
    }
    if (lvl === 'MEDIUM') {
      return (
        <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-bold bg-amber-500/15 border border-amber-500/30 text-amber-400">
          <AlertTriangle className="w-3 h-3" />
          <span>{level} ({score})</span>
        </span>
      )
    }
    return (
      <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-bold bg-emerald-500/15 border border-emerald-500/30 text-emerald-400">
        <CheckCircle2 className="w-3 h-3" />
        <span>{level || 'LOW'} ({score})</span>
      </span>
    )
  }

  const getTypeIcon = (type) => {
    switch (type?.toLowerCase()) {
      case 'url':
        return (
          <span className="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded-md text-xs font-semibold bg-blue-500/10 border border-blue-500/20 text-blue-400">
            <Globe className="w-3 h-3" />
            <span>URL</span>
          </span>
        )
      case 'qr':
        return (
          <span className="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded-md text-xs font-semibold bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
            <QrCode className="w-3 h-3" />
            <span>QR</span>
          </span>
        )
      case 'message':
        return (
          <span className="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded-md text-xs font-semibold bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <MessageSquare className="w-3 h-3" />
            <span>Message</span>
          </span>
        )
      default:
        return (
          <span className="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded-md text-xs font-semibold bg-slate-500/10 border border-slate-500/20 text-slate-400">
            <Shield className="w-3 h-3" />
            <span>{type}</span>
          </span>
        )
    }
  }

  const formatDate = (dateStr) => {
    if (!dateStr) return '-'
    try {
      const d = new Date(dateStr)
      return d.toLocaleString(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })
    } catch {
      return dateStr
    }
  }

  const totalScans = historyData?.total_scans || 0
  const highScans = historyData?.risk_breakdown?.high || historyData?.risk_breakdown?.HIGH || 0
  const mediumScans = historyData?.risk_breakdown?.medium || historyData?.risk_breakdown?.MEDIUM || 0
  const lowScans = historyData?.risk_breakdown?.low || historyData?.risk_breakdown?.LOW || 0

  return (
    <div className="space-y-6">
      {/* Header & Refresh Controls */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-slate-900/80 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm shadow-xl">
        <div className="flex items-center space-x-3">
          <div className="bg-purple-600/20 p-2.5 rounded-xl border border-purple-500/30 text-purple-400">
            <Activity className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">Scan History & Threat Analytics</h3>
            <p className="text-xs text-slate-400">Real-time audit telemetry and deterministic risk metrics stored in SQLite</p>
          </div>
        </div>

        <button
          onClick={fetchHistory}
          disabled={loading}
          className="inline-flex items-center space-x-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 text-xs font-semibold border border-slate-700 transition-all shadow-sm"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Data</span>
        </button>
      </div>

      {/* Analytics Counter Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Scans */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 backdrop-blur-sm shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Scans</span>
            <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
              <Layers className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <span className="text-3xl font-black text-white">{totalScans}</span>
            <span className="text-xs text-slate-400 block mt-0.5">Persisted audit entries</span>
          </div>
        </div>

        {/* High / Critical Risk */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 backdrop-blur-sm shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-rose-400 uppercase tracking-wider">High / Critical</span>
            <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400">
              <AlertOctagon className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <span className="text-3xl font-black text-rose-400">{highScans}</span>
            <span className="text-xs text-slate-400 block mt-0.5">
              {totalScans > 0 ? `${Math.round((highScans / totalScans) * 100)}% of total` : '0%'}
            </span>
          </div>
        </div>

        {/* Medium Risk */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 backdrop-blur-sm shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-amber-400 uppercase tracking-wider">Medium Risk</span>
            <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <span className="text-3xl font-black text-amber-400">{mediumScans}</span>
            <span className="text-xs text-slate-400 block mt-0.5">
              {totalScans > 0 ? `${Math.round((mediumScans / totalScans) * 100)}% of total` : '0%'}
            </span>
          </div>
        </div>

        {/* Low Risk */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 backdrop-blur-sm shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">Low Risk</span>
            <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
              <CheckCircle2 className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <span className="text-3xl font-black text-emerald-400">{lowScans}</span>
            <span className="text-xs text-slate-400 block mt-0.5">
              {totalScans > 0 ? `${Math.round((lowScans / totalScans) * 100)}% of total` : '0%'}
            </span>
          </div>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div className="p-4 bg-rose-950/30 border border-rose-900/50 rounded-xl flex items-center space-x-3 text-rose-300 text-sm">
          <AlertCircle className="w-5 h-5 flex-shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}


      {/* Audit Log Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden backdrop-blur-sm shadow-xl">
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Clock className="w-4 h-4 text-slate-400" />
            <h4 className="text-sm font-bold text-white uppercase tracking-wider">Latest 20 Audit Log Records</h4>
          </div>
          <span className="text-xs text-slate-500 font-mono">SQLite: cyberguardian.db</span>
        </div>

        {loading && !historyData ? (
          <div className="p-12 text-center text-slate-400 space-y-3">
            <RefreshCw className="w-8 h-8 animate-spin mx-auto text-slate-500" />
            <p className="text-sm">Loading audit logs...</p>
          </div>
        ) : historyData?.scans?.length === 0 ? (
          <div className="p-12 text-center text-slate-500 space-y-2">
            <FileText className="w-8 h-8 mx-auto text-slate-600 opacity-50" />
            <p className="text-sm font-medium">No scan audit logs recorded yet.</p>
            <p className="text-xs text-slate-600">Run a URL, QR, or Phishing message scan to generate audit telemetry.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider">
                  <th className="py-3.5 px-4"># ID</th>
                  <th className="py-3.5 px-4">Timestamp</th>
                  <th className="py-3.5 px-4">Type</th>
                  <th className="py-3.5 px-4">Target Payload</th>
                  <th className="py-3.5 px-4">Risk Assessment</th>
                  <th className="py-3.5 px-4 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {historyData?.scans?.map((scan) => {
                  const isExpanded = expandedRow === scan.id
                  return (
                    <React.Fragment key={scan.id}>
                      <tr
                        onClick={() => setExpandedRow(isExpanded ? null : scan.id)}
                        className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                      >
                        <td className="py-3.5 px-4 font-mono text-slate-500">#{scan.id}</td>
                        <td className="py-3.5 px-4 text-slate-400 whitespace-nowrap">
                          {formatDate(scan.created_at)}
                        </td>
                        <td className="py-3.5 px-4">{getTypeIcon(scan.scan_type)}</td>
                        <td className="py-3.5 px-4 font-mono text-slate-200 max-w-xs truncate" title={scan.target}>
                          {scan.target || '<empty>'}
                        </td>
                        <td className="py-3.5 px-4">
                          {getRiskBadge(scan.risk_level, scan.risk_score)}
                        </td>
                        <td className="py-3.5 px-4 text-right text-slate-500">
                          <button
                            type="button"
                            className="p-1 hover:text-slate-300 rounded"
                            aria-label="Toggle details"
                          >
                            {isExpanded ? (
                              <ChevronUp className="w-4 h-4" />
                            ) : (
                              <ChevronDown className="w-4 h-4" />
                            )}
                          </button>
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr className="bg-slate-950/60 border-b border-slate-800/80">
                          <td colSpan={6} className="py-4 px-6 space-y-3">
                            <div>
                              <span className="text-slate-400 font-semibold uppercase tracking-wider text-[10px] block mb-1">
                                AI Explainer Summary:
                              </span>
                              <p className="text-slate-200 text-xs bg-slate-900/90 p-3 rounded-xl border border-slate-800">
                                {scan.summary || 'No summary available.'}
                              </p>
                            </div>
                            {scan.evidence && (
                              <div>
                                <span className="text-slate-400 font-semibold uppercase tracking-wider text-[10px] block mb-1">
                                  Evidence Snapshot (JSON):
                                </span>
                                <pre className="text-[11px] font-mono text-cyan-300 bg-slate-950 p-3 rounded-xl border border-slate-800 overflow-x-auto max-h-40">
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
      </div>
    </div>
  )
}

