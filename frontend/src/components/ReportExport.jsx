import React, { useState } from 'react'
import { FileText, FileCode, Loader2, AlertCircle, Check } from 'lucide-react'
import { exportPdf } from '../services/api'

const stamp = () => new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)

function download(blob, filename) {
  const url = window.URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.URL.revokeObjectURL(url)
}

const btn =
  'inline-flex items-center justify-center gap-2 rounded-md px-3 py-1.5 text-xs font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-60'

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
      download(new Blob([blob], { type: 'application/pdf' }), `cyberguardian_threat_report_${stamp()}.pdf`)
      setPdfSuccess(true)
      setTimeout(() => setPdfSuccess(false), 3000)
    } catch (err) {
      setError(err.message || 'Could not generate the PDF report.')
    } finally {
      setPdfLoading(false)
    }
  }

  const handleExportJson = () => {
    try {
      setError(null)
      setJsonSuccess(false)
      const blob = new Blob([JSON.stringify(scanData, null, 2)], { type: 'application/json' })
      download(blob, `cyberguardian_threat_report_${stamp()}.json`)
      setJsonSuccess(true)
      setTimeout(() => setJsonSuccess(false), 3000)
    } catch {
      setError('Could not export the JSON file.')
    }
  }

  return (
    <section aria-label="Export report" className="rounded-lg border border-line bg-surface p-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h3 className="text-sm font-semibold">Export report</h3>
          <p className="text-xs text-muted">Download this scan as a PDF report or raw JSON.</p>
        </div>

        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={handleDownloadPdf}
            disabled={pdfLoading}
            className={`${btn} bg-accent text-white hover:bg-accent-hover`}
          >
            {pdfLoading ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
            ) : pdfSuccess ? (
              <Check className="h-3.5 w-3.5" aria-hidden="true" />
            ) : (
              <FileText className="h-3.5 w-3.5" aria-hidden="true" />
            )}
            {pdfLoading ? 'Preparing PDF…' : pdfSuccess ? 'PDF downloaded' : 'Download PDF'}
          </button>

          <button
            type="button"
            onClick={handleExportJson}
            className={`${btn} border border-line bg-surface hover:bg-surface-2`}
          >
            {jsonSuccess ? (
              <Check className="h-3.5 w-3.5" aria-hidden="true" />
            ) : (
              <FileCode className="h-3.5 w-3.5" aria-hidden="true" />
            )}
            {jsonSuccess ? 'JSON exported' : 'Export JSON'}
          </button>
        </div>
      </div>

      {error && (
        <div role="alert" className="mt-3 flex items-start gap-2 rounded-md bg-sev-critical-bg p-3 text-xs text-sev-critical">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          <span>{error}</span>
        </div>
      )}
    </section>
  )
}