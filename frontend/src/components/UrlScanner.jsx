import React, { useState } from 'react'
import { Globe, Search, Loader2, Sparkles, AlertCircle } from 'lucide-react'
import RiskMeter from './RiskMeter'
import AiExplanationCard from './AiExplanationCard'
import EvidenceInspector from './EvidenceInspector'
import ReportExport from './ReportExport'
import TelemetryBreakdown from './TelemetryBreakdown'
import { scanUrl } from '../services/api'

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

  const fillSample = (sampleUrl) => {
    setUrl(sampleUrl)
  }

  return (
    <div className="space-y-6">
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm shadow-xl">
        <div className="flex items-center space-x-3 mb-4">
          <div className="bg-blue-600/20 p-2.5 rounded-xl border border-blue-500/30 text-blue-400">
            <Globe className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">URL Threat Scanner</h3>
            <p className="text-xs text-slate-400">Analyze website links for SSL validity, domain age, and threat intel</p>
          </div>
        </div>

        <form onSubmit={handleScan} className="space-y-4">
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-slate-500">
              <Search className="w-5 h-5" />
            </div>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter URL to analyze (e.g., https://example.com)"
              className="w-full pl-12 pr-4 py-3.5 bg-slate-950/80 border border-slate-800 rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 text-sm font-mono transition-all"
            />
          </div>

          <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
              <span className="text-xs text-slate-400 font-medium">Quick Fill:</span>
              <button
                type="button"
                onClick={() => fillSample('https://www.google.com')}
                className="text-xs bg-slate-950 hover:bg-slate-800 text-slate-300 px-3 py-1.5 rounded-lg border border-slate-800 transition-colors"
              >
                Safe Google
              </button>
              <button
                type="button"
                onClick={() => fillSample('http://paypal-security-update.suspicious-domain.com/login')}
                className="text-xs bg-slate-950 hover:bg-slate-800 text-rose-300 px-3 py-1.5 rounded-lg border border-slate-800 transition-colors"
              >
                Phishing PayPal
              </button>
            </div>

            <button
              type="submit"
              disabled={loading || !url.trim()}
              className="w-full sm:w-auto bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 disabled:text-slate-600 text-white font-medium px-6 py-3 rounded-xl transition-all shadow-lg shadow-blue-600/20 flex items-center justify-center space-x-2 text-sm"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Analyzing URL...</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4" />
                  <span>Scan URL Now</span>
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
            mlProbability={result.evidence.ml_probability}
          />
          <TelemetryBreakdown evidence={result.evidence} />
          <AiExplanationCard explanation={result.explanation} scanData={result} />
          <EvidenceInspector evidence={result.evidence} />
          <ReportExport scanData={result} />
        </div>
      )}
    </div>
  )
}
