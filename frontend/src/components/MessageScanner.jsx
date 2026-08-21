import React, { useState } from 'react'
import { MessageSquare, Loader2, Sparkles, AlertCircle } from 'lucide-react'
import RiskMeter from './RiskMeter'
import AiExplanationCard from './AiExplanationCard'
import EvidenceInspector from './EvidenceInspector'
import { scanMessage } from '../services/api'

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
      const data = await scanMessage(message.trim())
      setResult(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const fillSample = (sampleText) => {
    setMessage(sampleText)
  }

  return (
    <div className="space-y-6">
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm shadow-xl">
        <div className="flex items-center space-x-3 mb-4">
          <div className="bg-cyan-600/20 p-2.5 rounded-xl border border-cyan-500/30 text-cyan-400">
            <MessageSquare className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">Phishing Message & SMS Analyzer</h3>
            <p className="text-xs text-slate-400">Scan email content or SMS text for urgency tactics, financial lures, and malicious URLs</p>
          </div>
        </div>

        <form onSubmit={handleScan} className="space-y-4">
          <div>
            <textarea
              rows={5}
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Paste suspicious SMS or email text here (e.g., 'URGENT: Your bank account will be suspended. Click http://suspicious-bank-login.com immediately')..."
              className="w-full p-4 bg-slate-950/80 border border-slate-800 rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 text-sm transition-all resize-none"
            />
          </div>

          <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
              <span className="text-xs text-slate-400 font-medium">Quick Fill:</span>
              <button
                type="button"
                onClick={() => fillSample('URGENT: Your Netflix subscription payment failed. Update billing details immediately at https://netflix-billing-update.suspicious-domain.com to avoid service termination.')}
                className="text-xs bg-slate-950 hover:bg-slate-800 text-rose-300 px-3 py-1.5 rounded-lg border border-slate-800 transition-colors"
              >
                Phishing SMS
              </button>
              <button
                type="button"
                onClick={() => fillSample('Hi team, reminder for our weekly sync scheduled tomorrow at 10 AM EST. Please review the agenda attached in Google Docs.')}
                className="text-xs bg-slate-950 hover:bg-slate-800 text-slate-300 px-3 py-1.5 rounded-lg border border-slate-800 transition-colors"
              >
                Safe Email
              </button>
            </div>

            <button
              type="submit"
              disabled={loading || !message.trim()}
              className="w-full sm:w-auto bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-600 text-white font-medium px-6 py-3 rounded-xl transition-all shadow-lg shadow-cyan-600/20 flex items-center justify-center space-x-2 text-sm"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Analyzing Message...</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4" />
                  <span>Scan Message Now</span>
                </>
              )}
            </button>
          </div>
        </form>

        {error && (
          <div className="mt-4 p-4 bg-rose-950/30 border border-rose-900/50 rounded-xl flex items-center space-x-3 text-rose-300 text-sm">
            <AlertCircle className="w-5 h-5 flex-shrink-0 text-rose-400" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {result && (
        <div className="space-y-6 animate-fadeIn">
          <RiskMeter
            score={result.risk_assessment.score}
            level={result.risk_assessment.level}
            triggers={result.risk_assessment.triggers}
          />
          <AiExplanationCard explanation={result.explanation} />
          <EvidenceInspector evidence={result.evidence} />
        </div>
      )}
    </div>
  )
}
