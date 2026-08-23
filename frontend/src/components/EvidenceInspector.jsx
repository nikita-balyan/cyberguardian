import React, { useState } from 'react'
import { ChevronDown, ChevronUp, Database, ShieldCheck, ShieldAlert } from 'lucide-react'

export default function EvidenceInspector({ evidence }) {
  const [isOpen, setIsOpen] = useState(false)

  if (!evidence) return null

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden backdrop-blur-sm shadow-xl">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full px-6 py-4 flex items-center justify-between text-left hover:bg-slate-800/40 transition-colors"
      >
        <div className="flex items-center space-x-3">
          <div className="bg-slate-800 p-2 rounded-xl text-slate-300">
            <Database className="w-4 h-4" />
          </div>
          <div>
            <h4 className="text-sm font-bold text-white">Raw Evidence Inspector</h4>
            <p className="text-xs text-slate-400">View underlying technical scan telemetry & attributes</p>
          </div>
        </div>
        <div className="flex items-center space-x-2 text-slate-400 text-xs font-medium">
          <span>{isOpen ? 'Hide Details' : 'View Details'}</span>
          {isOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </div>
      </button>

      {isOpen && (
        <div className="px-6 pb-6 pt-2 border-t border-slate-800 space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
            {evidence.domain_age_days !== undefined && (
              <div className="bg-slate-950/60 p-3.5 rounded-xl border border-slate-800">
                <span className="text-xs text-slate-400 block font-medium">Domain Age</span>
                <span className="text-sm font-bold text-slate-200 mt-1 block">
                  {evidence.domain_age_days !== null ? `${evidence.domain_age_days} days` : 'Unknown'}
                </span>
              </div>
            )}

            {evidence.ssl_valid !== undefined && (
              <div className="bg-slate-950/60 p-3.5 rounded-xl border border-slate-800">
                <span className="text-xs text-slate-400 block font-medium">SSL Status</span>
                <span className="text-sm font-bold mt-1 flex items-center space-x-1.5">
                  {evidence.ssl_valid ? (
                    <>
                      <ShieldCheck className="w-4 h-4 text-emerald-400" />
                      <span className="text-emerald-400">Valid</span>
                    </>
                  ) : (
                    <>
                      <ShieldAlert className="w-4 h-4 text-rose-400" />
                      <span className="text-rose-400">Invalid / None</span>
                    </>
                  )}
                </span>
              </div>
            )}

            {evidence.redirect_count !== undefined && (
              <div className="bg-slate-950/60 p-3.5 rounded-xl border border-slate-800">
                <span className="text-xs text-slate-400 block font-medium">Redirects</span>
                <span className="text-sm font-bold text-slate-200 mt-1 block">
                  {evidence.redirect_count} hops
                </span>
              </div>
            )}

            {evidence.threat_intel !== undefined && evidence.threat_intel !== null ? (
              <div className="bg-slate-950/60 p-3.5 rounded-xl border border-slate-800 sm:col-span-2 md:col-span-3 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-400 block font-medium">External Threat Intelligence (URLhaus & Safe Browsing)</span>
                  <span className={`text-xs px-2.5 py-1 rounded-full font-bold flex items-center space-x-1 ${evidence.threat_intel.flagged ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40 animate-pulse' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'}`}>
                    {evidence.threat_intel.flagged ? (
                      <>
                        <ShieldAlert className="w-3.5 h-3.5" />
                        <span>FLAGGED BY THREAT FEEDS</span>
                      </>
                    ) : (
                      <>
                        <ShieldCheck className="w-3.5 h-3.5" />
                        <span>BENIGN / CLEAN</span>
                      </>
                    )}
                  </span>
                </div>

                {evidence.threat_intel.flagged && evidence.threat_intel.threat_summary && evidence.threat_intel.threat_summary.length > 0 && (
                  <div className="p-3 bg-rose-950/50 border border-rose-900/70 rounded-xl text-xs text-rose-300 space-y-1">
                    <span className="font-bold uppercase tracking-wider block text-rose-400">Threat Feed Alert Summary:</span>
                    <ul className="list-disc list-inside space-y-0.5">
                      {evidence.threat_intel.threat_summary.map((summary, idx) => (
                        <li key={idx}>{summary}</li>
                      ))}
                    </ul>
                  </div>
                )}

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 pt-1">
                  {evidence.threat_intel.sources?.urlhaus && (
                    <div className="bg-slate-900/90 p-3 rounded-xl border border-slate-800 flex items-center justify-between">
                      <div>
                        <span className="text-xs font-bold text-slate-200 block">URLhaus Feed</span>
                        <span className="text-[11px] text-slate-400">Status: {evidence.threat_intel.sources.urlhaus.status}</span>
                      </div>
                      <span className={`text-[11px] font-bold px-2 py-0.5 rounded-md ${evidence.threat_intel.sources.urlhaus.flagged ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-emerald-500/15 text-emerald-400'}`}>
                        {evidence.threat_intel.sources.urlhaus.flagged ? 'Flagged' : 'Clean'}
                      </span>
                    </div>
                  )}

                  {evidence.threat_intel.sources?.google_safebrowsing && (
                    <div className="bg-slate-900/90 p-3 rounded-xl border border-slate-800 flex items-center justify-between">
                      <div>
                        <span className="text-xs font-bold text-slate-200 block">Google Safe Browsing</span>
                        <span className="text-[11px] text-slate-400">Status: {evidence.threat_intel.sources.google_safebrowsing.status}</span>
                      </div>
                      <span className={`text-[11px] font-bold px-2 py-0.5 rounded-md ${evidence.threat_intel.sources.google_safebrowsing.flagged ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-emerald-500/15 text-emerald-400'}`}>
                        {evidence.threat_intel.sources.google_safebrowsing.flagged ? 'Flagged' : 'Clean / Unconfigured'}
                      </span>
                    </div>
                  )}
                </div>
              </div>
            ) : evidence.safe_browsing_hit !== undefined && (
              <div className="bg-slate-950/60 p-3.5 rounded-xl border border-slate-800">
                <span className="text-xs text-slate-400 block font-medium">Threat Intel</span>
                <span className={`text-sm font-bold mt-1 block ${evidence.safe_browsing_hit ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {evidence.safe_browsing_hit ? 'Threat Match' : 'Clean'}
                </span>
              </div>
            )}
          </div>

          <div className="mt-4">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-2">
              Raw JSON Telemetry
            </span>
            <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-xs font-mono text-slate-400 overflow-x-auto max-h-60">
              {JSON.stringify(evidence, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  )
}
