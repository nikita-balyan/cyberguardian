import React from 'react'
import { Sparkles, ShieldAlert, CheckCircle, Lightbulb, ArrowRight } from 'lucide-react'

export default function AiExplanationCard({ explanation }) {
  if (!explanation) return null

  const { summary, why_flagged = [], recommended_actions = [], educational_tip } = explanation

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm shadow-xl space-y-6">
      {/* Header Banner */}
      <div className="flex items-center space-x-3 pb-4 border-b border-slate-800">
        <div className="bg-indigo-600/20 p-2.5 rounded-xl border border-indigo-500/30 text-indigo-400">
          <Sparkles className="w-5 h-5 animate-pulse" />
        </div>
        <div>
          <span className="text-xs uppercase font-bold tracking-widest text-indigo-400">
            Grounded AI Threat Analysis
          </span>
          <h3 className="text-lg font-bold text-white">AI Evidence Interpretation</h3>
        </div>
      </div>

      {/* Summary Banner */}
      <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-4 text-slate-200 text-sm leading-relaxed">
        <span className="font-semibold text-blue-400 block mb-1">Executive Summary</span>
        {summary}
      </div>

      {/* Why is this flagged */}
      {why_flagged.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center space-x-2 text-rose-400 font-semibold text-sm">
            <ShieldAlert className="w-4 h-4" />
            <span>Why is this flagged? (Key Evidence Breakdown)</span>
          </div>
          <ul className="space-y-2">
            {why_flagged.map((item, idx) => (
              <li key={idx} className="flex items-start space-x-3 text-sm bg-slate-950/40 p-3 rounded-xl border border-slate-900">
                <span className="text-rose-400 font-bold mt-0.5">•</span>
                <span className="text-slate-300">{item}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Recommended Actions */}
      {recommended_actions.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center space-x-2 text-emerald-400 font-semibold text-sm">
            <CheckCircle className="w-4 h-4" />
            <span>Recommended Actions</span>
          </div>
          <div className="grid grid-cols-1 gap-2">
            {recommended_actions.map((action, idx) => (
              <div key={idx} className="flex items-start space-x-3 text-sm bg-emerald-950/20 border border-emerald-900/30 p-3 rounded-xl text-slate-200">
                <ArrowRight className="w-4 h-4 text-emerald-400 mt-0.5 flex-shrink-0" />
                <span>{action}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Educational Tip */}
      {educational_tip && (
        <div className="bg-gradient-to-r from-blue-950/40 to-cyan-950/40 border border-blue-800/40 rounded-xl p-4 flex items-start space-x-3">
          <div className="bg-blue-600/20 p-2 rounded-lg text-blue-400 mt-0.5">
            <Lightbulb className="w-4 h-4" />
          </div>
          <div>
            <span className="text-xs uppercase font-bold tracking-wider text-blue-400 block mb-1">
              Educational Tip
            </span>
            <p className="text-sm text-slate-300 leading-relaxed">{educational_tip}</p>
          </div>
        </div>
      )}
    </div>
  )
}
