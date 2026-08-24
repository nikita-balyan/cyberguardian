import React, { useState } from 'react'
import { FileText, FileCode, Download, Loader2, AlertCircle, Share2, Check } from 'lucide-react'
import { exportPdf } from '../services/api'

export default function ReportExport({ scanData }) {
  const [pdfLoading, setPdfLoading] = useState(false)
  const [pdfSuccess, setPdfSuccess] = useState(false)
  const [jsonSuccess, setJsonSuccess] = useState(false)
  const [error, setError] = useState(null)

  if (!scanData) return null

  const handleDownloadPdf = async () => {
    try {
      setPdfLoading(true)
      setError(null)
      setPdfSuccess(false)

      const blob = await exportPdf(scanData)
      const blobUrl = window.URL.createObjectURL(new Blob([blob], { type: 'application/pdf' }))
      
      const link = document.createElement('a')
      link.href = blobUrl
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
      link.download = `cyberguardian_threat_report_${timestamp}.pdf`
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(blobUrl)

      setPdfSuccess(true)
      setTimeout(() => setPdfSuccess(false), 3000)
    } catch (err) {
      setError(err.message || 'Failed to generate PDF report.')
    } finally {
      setPdfLoading(false)
    }
  }

  const handleExportJson = () => {
    try {
      setError(null)
      setJsonSuccess(false)

      const jsonString = JSON.stringify(scanData, null, 2)
      const blob = new Blob([jsonString], { type: 'application/json' })
      const blobUrl = window.URL.createObjectURL(blob)

      const link = document.createElement('a')
      link.href = blobUrl
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
      link.download = `cyberguardian_threat_report_${timestamp}.json`
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(blobUrl)

      setJsonSuccess(true)
      setTimeout(() => setJsonSuccess(false), 3000)
    } catch (err) {
      setError('Failed to export JSON file.')
    }
  }

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm shadow-xl space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div className="flex items-center space-x-3">
          <div className="bg-blue-600/20 p-2.5 rounded-xl border border-blue-500/30 text-blue-400">
            <Share2 className="w-5 h-5" />
          </div>
          <div>
            <h4 className="text-base font-bold text-white">Forensic Threat Report Generation</h4>
            <p className="text-xs text-slate-400">
              Export executive-grade PDF reports or structured JSON scan telemetry
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={handleDownloadPdf}
            disabled={pdfLoading}
            className="flex-1 sm:flex-none bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 text-white text-xs font-semibold px-4 py-2.5 rounded-xl transition-all shadow-lg shadow-blue-600/20 flex items-center justify-center space-x-2 border border-blue-500/30 cursor-pointer disabled:cursor-not-allowed"
          >
            {pdfLoading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-blue-200" />
                <span>Generating PDF...</span>
              </>
            ) : pdfSuccess ? (
              <>
                <Check className="w-4 h-4 text-emerald-400" />
                <span>Downloaded PDF</span>
              </>
            ) : (
              <>
                <FileText className="w-4 h-4" />
                <span>Download PDF Report</span>
              </>
            )}
          </button>

          <button
            type="button"
            onClick={handleExportJson}
            className="flex-1 sm:flex-none bg-slate-950 hover:bg-slate-800 text-slate-200 text-xs font-semibold px-4 py-2.5 rounded-xl transition-all border border-slate-800 flex items-center justify-center space-x-2 cursor-pointer"
          >
            {jsonSuccess ? (
              <>
                <Check className="w-4 h-4 text-emerald-400" />
                <span>Exported JSON</span>
              </>
            ) : (
              <>
                <FileCode className="w-4 h-4 text-slate-400" />
                <span>Export JSON</span>
              </>
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 bg-rose-950/30 border border-rose-900/50 rounded-xl flex items-center space-x-2.5 text-rose-300 text-xs">
          <AlertCircle className="w-4 h-4 flex-shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}
    </div>
  )
}
