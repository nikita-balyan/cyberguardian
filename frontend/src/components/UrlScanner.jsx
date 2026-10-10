import React, { useState } from 'react'
import { Loader2, AlertCircle } from 'lucide-react'
import RiskMeter from './RiskMeter'
import AiExplanationCard from './AiExplanationCard'
import EvidenceInspector from './EvidenceInspector'
import ReportExport from './ReportExport'
import TelemetryBreakdown from './TelemetryBreakdown'
import { scanUrl } from '../services/api'

const EXAMPLES = [
  { label: 'Safe example', url: 'https://www.google.com' },
  { label: 'Phishing-style example', url: 'http://paypal-security-update.suspicious-domain.com/login' },
]

export default function UrlScanner() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)

  const handleScan = async (e) => {
    e?.preventDefault()
    if (!url.trim()) return

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const data = await scanUrl(url.trim())
      setResult(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-line bg-surface p-5">
        <form onSubmit={handleScan} noValidate>
          <label htmlFor="url-input" className="mb-1.5 block text-sm font-medium">
            URL to scan
          </label>
          <div className="flex flex-col gap-2 sm:flex-row">
            <input
              id="url-input"
              type="text"
              inputMode="url"
              autoComplete="off"
              spellCheck={false}
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/login"
              className="min-w-0 flex-1 rounded-md border border-line bg-bg px-3 py-2 font-mono text-sm placeholder:text-muted focus:border-accent"
            />
            <button
              type="submit"
              disabled={loading || !url.trim()}
              className="inline-flex items-center justify-center gap-2 rounded-md bg-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
              {loading ? 'Scanning…' : 'Scan URL'}
            </button>
          </div>

          <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
            <span className="text-muted">Try an example:</span>
            {EXAMPLES.map((ex) => (
              <button
                key={ex.label}
                type="button"
                onClick={() => setUrl(ex.url)}
                className="rounded border border-line px-2 py-1 font-medium transition-colors hover:bg-surface-2"
              >
                {ex.label}
              </button>
            ))}
          </div>
        </form>

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
            mlProbability={result.evidence.ml_probability}
          />
          <TelemetryBreakdown evidence={result.evidence} />
          <AiExplanationCard explanation={result.explanation} scanData={result} />
          <EvidenceInspector evidence={result.evidence} />
          {/* The AI card already has export buttons. This is only a fallback when there's no AI explanation. */}
          {!result.explanation && <ReportExport scanData={result} />}
        </div>
      )}
    </div>
  )
}