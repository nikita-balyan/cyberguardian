import React, { useState } from 'react'
import { Loader2, AlertCircle } from 'lucide-react'
import RiskMeter from './RiskMeter'
import MessageEvidence from './MessageEvidence'
import AiExplanationCard from './AiExplanationCard'
import EvidenceInspector from './EvidenceInspector'
import ReportExport from './ReportExport'
import { scanMessage } from '../services/api'

const EXAMPLES = [
  {
    label: 'Phishing-style SMS',
    text: 'URGENT: Your Netflix subscription payment failed. Update billing details immediately at https://netflix-billing-update.suspicious-domain.com to avoid service termination.',
  },
  {
    label: 'Safe email',
    text: 'Hi team, reminder for our weekly sync scheduled tomorrow at 10 AM EST. Please review the agenda attached in Google Docs.',
  },
]

export default function MessageScanner() {
  const [message, setMessage] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)

  const handleScan = async (e) => {
    e?.preventDefault()
    if (!message.trim()) return

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      setResult(await scanMessage(message.trim()))
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  // Highest ML probability across links in the message, or null if there are none
  const mlValues = (result?.evidence?.url_evidences || [])
    .map((u) => u.ml_probability)
    .filter((v) => v != null)
  const mlMax = mlValues.length ? Math.max(...mlValues) : null

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-line bg-surface p-5">
        <form onSubmit={handleScan} noValidate>
          <label htmlFor="message-input" className="mb-1.5 block text-sm font-medium">
            Message text
          </label>
          <textarea
            id="message-input"
            rows={6}
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="Paste the SMS or email text here, including any links."
            className="w-full resize-y rounded-md border border-line bg-bg px-3 py-2 text-sm placeholder:text-muted focus:border-accent"
          />

          <div className="mt-3 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <span className="text-muted">Try an example:</span>
              {EXAMPLES.map((ex) => (
                <button
                  key={ex.label}
                  type="button"
                  onClick={() => setMessage(ex.text)}
                  className="rounded border border-line px-2 py-1 font-medium transition-colors hover:bg-surface-2"
                >
                  {ex.label}
                </button>
              ))}
            </div>

            <button
              type="submit"
              disabled={loading || !message.trim()}
              className="inline-flex items-center justify-center gap-2 rounded-md bg-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
              {loading ? 'Scanning…' : 'Scan message'}
            </button>
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
            mlProbability={mlMax}
          />
          <MessageEvidence evidence={result.evidence} />
          <AiExplanationCard explanation={result.explanation} scanData={result} />
          <EvidenceInspector evidence={result.evidence} />
          {!result.explanation && <ReportExport scanData={result} />}
        </div>
      )}
    </div>
  )
}
