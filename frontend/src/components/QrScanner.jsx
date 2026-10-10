import React, { useState, useRef, useEffect } from 'react'
import { Upload, Loader2, AlertCircle, X } from 'lucide-react'
import RiskMeter from './RiskMeter'
import AiExplanationCard from './AiExplanationCard'
import EvidenceInspector from './EvidenceInspector'
import ReportExport from './ReportExport'
import TelemetryBreakdown from './TelemetryBreakdown'
import { scanQrCode } from '../services/api'

const ACCEPTED = ['image/png', 'image/jpeg', 'image/webp']

export default function QrScanner() {
  const [file, setFile] = useState(null)
  const [preview, setPreview] = useState(null)
  const [dragging, setDragging] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)
  const fileInputRef = useRef(null)

  // Free the preview's object URL when it changes or the component unmounts
  useEffect(() => () => { if (preview) URL.revokeObjectURL(preview) }, [preview])

  const processSelectedFile = (selected) => {
    if (!ACCEPTED.includes(selected.type)) {
      setError('That file type isn\'t supported. Upload a PNG, JPG, or WebP image.')
      return
    }
    setFile(selected)
    setPreview(URL.createObjectURL(selected))
    setError(null)
    setResult(null)
  }

  const handleScan = async () => {
    if (!file) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      setResult(await scanQrCode(file))
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const clearFile = () => {
    setFile(null)
    setPreview(null)
    setResult(null)
    setError(null)
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  const onDrop = (e) => {
    e.preventDefault()
    setDragging(false)
    const dropped = e.dataTransfer.files?.[0]
    if (dropped) processSelectedFile(dropped)
  }

  const urlEvidence = result?.evidence?.url_evidence
  const decoded = result?.evidence?.extracted_text

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-line bg-surface p-5">
        <input
          ref={fileInputRef}
          type="file"
          accept="image/png,image/jpeg,image/webp"
          onChange={(e) => e.target.files?.[0] && processSelectedFile(e.target.files[0])}
          className="hidden"
          aria-label="QR code image"
        />

        {!preview ? (
          <div
            role="button"
            tabIndex={0}
            onClick={() => fileInputRef.current?.click()}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault()
                fileInputRef.current?.click()
              }
            }}
            onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
            className={`flex cursor-pointer flex-col items-center gap-2 rounded-md border border-dashed px-6 py-10 text-center transition-colors ${
              dragging ? 'border-accent bg-accent-soft' : 'border-line hover:bg-surface-2'
            }`}
          >
            <Upload className="h-5 w-5 text-muted" aria-hidden="true" />
            <p className="text-sm font-medium">Drop a QR code image here, or click to browse</p>
            <p className="text-xs text-muted">PNG, JPG, or WebP</p>
          </div>
        ) : (
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex min-w-0 items-center gap-4">
              <img
                src={preview}
                alt="Uploaded QR code preview"
                className="h-20 w-20 shrink-0 rounded-md border border-line object-cover"
              />
              <div className="min-w-0">
                <p className="truncate text-sm font-medium">{file?.name}</p>
                <p className="text-xs text-muted">{file ? `${Math.max(1, Math.round(file.size / 1024))} KB` : ''}</p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={clearFile}
                className="inline-flex items-center gap-1.5 rounded-md border border-line px-3 py-2 text-sm font-medium transition-colors hover:bg-surface-2"
              >
                <X className="h-4 w-4" aria-hidden="true" />
                Remove
              </button>
              <button
                type="button"
                onClick={handleScan}
                disabled={loading}
                className="inline-flex items-center justify-center gap-2 rounded-md bg-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
              >
                {loading && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
                {loading ? 'Scanning…' : 'Scan QR code'}
              </button>
            </div>
          </div>
        )}

        {error && (
          <div role="alert" className="mt-4 flex items-start gap-2 rounded-md bg-sev-critical-bg p-3 text-sm text-sev-critical">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {result && (
        <div className="space-y-4">
          <RiskMeter
            score={result.risk_assessment.score}
            level={result.risk_assessment.level}
            triggers={result.risk_assessment.triggers}
            mlProbability={urlEvidence?.ml_probability ?? null}
          />

          {decoded && (
            <section className="rounded-lg border border-line bg-surface p-5" aria-label="Decoded QR content">
              <h3 className="mb-2 text-sm font-semibold">Decoded QR content</h3>
              <p className="break-all rounded-md border border-line bg-surface-2 p-3 font-mono text-xs">{decoded}</p>
            </section>
          )}

          {urlEvidence?.lexical_features && <TelemetryBreakdown evidence={urlEvidence} />}

          <AiExplanationCard explanation={result.explanation} scanData={result} />
          <EvidenceInspector evidence={result.evidence} />
          {!result.explanation && <ReportExport scanData={result} />}
        </div>
      )}
    </div>
  )
}
