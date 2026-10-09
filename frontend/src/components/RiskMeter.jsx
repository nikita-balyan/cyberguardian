import React from 'react'
import { AlertTriangle, CheckCircle2, AlertOctagon, HelpCircle, Brain } from 'lucide-react'

export default function RiskMeter({ score, level, triggers = [], mlProbability = 0 }) {
  const getLevelStyles = (lvl) => {
    switch (lvl?.toUpperCase()) {
      case 'LOW':
        return {
          bg: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
          badgeBg: 'bg-emerald-500',
          icon: <CheckCircle2 className="w-6 h-6 text-emerald-400" />,
          barColor: 'bg-emerald-500',
          textTitle: 'Low Risk',
        }
      case 'MEDIUM':
        return {
          bg: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
          badgeBg: 'bg-amber-500',
          icon: <AlertTriangle className="w-6 h-6 text-amber-400" />,
          barColor: 'bg-amber-500',
          textTitle: 'Medium Risk',
        }
      case 'HIGH':
      case 'CRITICAL':
        return {
          bg: 'bg-rose-500/10 border-rose-500/30 text-rose-400',
          badgeBg: 'bg-rose-500',
          icon: <AlertOctagon className="w-6 h-6 text-rose-400" />,
          barColor: 'bg-rose-500',
          textTitle: 'High Risk',
        }
      default:
        return {
          bg: 'bg-slate-500/10 border-slate-500/30 text-slate-400',
          badgeBg: 'bg-slate-500',
          icon: <HelpCircle className="w-6 h-6 text-slate-400" />,
          barColor: 'bg-slate-500',
          textTitle: 'Unknown Risk',
        }
    }
  }

  const style = getLevelStyles(level)

  return (
    <div className={`p-6 rounded-2xl border ${style.bg} backdrop-blur-sm shadow-xl transition-all duration-300`}>
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center space-x-4">
          <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 shadow-inner">
            {style.icon}
          </div>
          <div>
            <span className="text-xs uppercase tracking-wider font-semibold opacity-75">
              Risk Assessment
            </span>
            <h2 className="text-2xl font-black tracking-tight mt-0.5 flex items-center space-x-2">
              <span>{style.textTitle}</span>
              <span className="text-xs px-2.5 py-0.5 rounded-full font-bold uppercase tracking-wide bg-slate-900/60 border border-slate-700/50">
                {level || 'UNKNOWN'}
              </span>
            </h2>
          </div>
        </div>

        <div className="flex items-center space-x-3 bg-slate-900/80 px-5 py-3 rounded-xl border border-slate-800/80 w-full sm:w-auto justify-between sm:justify-start">
          <div className="text-right">
            <span className="text-xs text-slate-400 block font-medium">Deterministic Score</span>
            <span className="text-3xl font-extrabold tracking-tight text-white">
              {score}<span className="text-slate-500 text-lg">/100</span>
            </span>
          </div>
          <div className="w-16 h-16 relative flex items-center justify-center">
            <svg className="w-full h-full transform -rotate-90">
              <circle
                cx="32"
                cy="32"
                r="26"
                stroke="currentColor"
                strokeWidth="6"
                className="text-slate-800 fill-none"
              />
              <circle
                cx="32"
                cy="32"
                r="26"
                stroke="currentColor"
                strokeWidth="6"
                strokeDasharray={2 * Math.PI * 26}
                strokeDashoffset={2 * Math.PI * 26 * (1 - (score || 0) / 100)}
                strokeLinecap="round"
                className={`fill-none transition-all duration-1000 ${
                  level === 'LOW'
                    ? 'text-emerald-400'
                    : level === 'MEDIUM'
                    ? 'text-amber-400'
                    : 'text-rose-400'
                }`}
              />
            </svg>
            <span className="absolute text-xs font-bold text-white">{score}%</span>
          </div>
        </div>
      </div>

      {triggers && triggers.length > 0 && (
        <div className="mt-4 pt-4 border-t border-slate-800/60">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-2">
            Deterministic Triggers:
          </span>
          <div className="flex flex-wrap gap-2">
            {triggers.map((trigger, idx) => (
              <span
                key={idx}
                className="text-xs bg-slate-900/90 text-slate-300 px-2.5 py-1 rounded-lg border border-slate-800 font-mono"
              >
                • {trigger}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* ML Probability & Heuristic Score Breakdown */}
      <div className="mt-4 pt-4 border-t border-slate-800/60 grid grid-cols-2 gap-4">
        <div className="bg-slate-900/60 rounded-xl p-4 border border-slate-800/50">
          <div className="flex items-center space-x-2 text-cyan-400 font-semibold text-sm mb-3">
            <Brain className="w-4 h-4" />
            <span>ML Phishing Probability</span>
          </div>
          <div className="flex items-center space-x-4">
            <div className="w-20 h-20 relative flex items-center justify-center flex-shrink-0">
              <svg className="w-full h-full transform -rotate-90">
                <circle
                  cx="32"
                  cy="32"
                  r="26"
                  stroke="currentColor"
                  strokeWidth="6"
                  className="text-slate-800 fill-none"
                />
                <circle
                  cx="32"
                  cy="32"
                  r="26"
                  stroke="currentColor"
                  strokeWidth="6"
                  strokeDasharray={2 * Math.PI * 26}
                  strokeDashoffset={2 * Math.PI * 26 * (1 - (mlProbability || 0))}
                  strokeLinecap="round"
                  className={`fill-none transition-all duration-1000 ${
                    mlProbability < 0.3 ? 'text-emerald-400' : mlProbability < 0.6 ? 'text-amber-400' : 'text-rose-400'
                  }`}
                />
              </svg>
              <span className="absolute text-xs font-bold text-white">{Math.round((mlProbability || 0) * 100)}%</span>
            </div>
            <div className="flex-1">
              <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all duration-1000 ${
                    mlProbability < 0.3 ? 'bg-emerald-400' : mlProbability < 0.6 ? 'bg-amber-400' : 'bg-rose-400'
                  }`}
                  style={{ width: `${(mlProbability || 0) * 100}%` }}
                />
              </div>
              <div className="flex justify-between text-xs text-slate-400 mt-1">
                <span>Benign (0%)</span>
                <span>Phishing (100%)</span>
              </div>
            </div>
          </div>
        </div>
        <div className="bg-slate-900/60 rounded-xl p-4 border border-slate-800/50">
          <div className="text-slate-400 font-semibold text-sm mb-3">Score Breakdown</div>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between text-slate-300">
              <span>Composite Risk Score</span>
              <span className="font-bold text-white">{score}/100</span>
            </div>
            <div className="flex justify-between text-slate-300">
              <span>Heuristic Score</span>
              <span className="font-bold text-white">{score}/100</span>
            </div>
            <div className="flex justify-between text-slate-300">
              <span>ML Probability Score</span>
              <span className="font-bold text-white">{Math.round((mlProbability || 0) * 100)}/100</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
