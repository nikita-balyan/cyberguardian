import React from 'react'
import SeverityBadge from './SeverityBadge'
import { getSeverity, levelFromProbability } from '../lib/severity'

const clamp = (n) => Math.max(0, Math.min(100, Number(n) || 0))

export default function RiskMeter({ score, level, triggers = [], mlProbability = null }) {
  // Message and QR scans with no link have no ML score, so hide the meter instead of showing a fake 0%
  const hasMl = mlProbability !== null && mlProbability !== undefined

  const sev = getSeverity(level)
  const scorePct = clamp(score)
  const mlPct = Math.round(clamp((mlProbability || 0) * 100))
  const mlSev = getSeverity(levelFromProbability(mlProbability))

  return (
    <section className="rounded-lg border border-line bg-surface p-5" aria-label="Risk assessment">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <SeverityBadge level={level} />
          <span className="text-sm text-muted">Risk assessment</span>
        </div>
        <span className="text-2xl font-semibold tabular-nums">
          {score ?? '–'}
          <span className="text-base font-normal text-muted">/100</span>
        </span>
      </div>

      <div
        className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-surface-2"
        role="progressbar"
        aria-label="Risk score"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={scorePct}
      >
        <div className={`h-full rounded-full ${sev.bar}`} style={{ width: `${scorePct}%` }} />
      </div>

      <div className={`mt-5 grid gap-6 border-t border-line pt-5 ${hasMl ? 'md:grid-cols-2' : ''}`}>
        <div>
          <h3 className="mb-2 text-sm font-semibold">Rule triggers</h3>
          {triggers && triggers.length > 0 ? (
            <ul className="flex flex-wrap gap-1.5">
              {triggers.map((trigger, idx) => (
                <li key={idx} className="rounded border border-line bg-surface-2 px-2 py-1 text-xs">
                  {trigger}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-muted">No rules triggered.</p>
          )}
        </div>

        {hasMl && (
          <div>
            <div className="mb-2 flex items-baseline justify-between">
              <h3 className="text-sm font-semibold">ML phishing probability</h3>
              <span className="text-sm font-semibold tabular-nums">{mlPct}%</span>
            </div>
            <div
              className="h-1.5 w-full overflow-hidden rounded-full bg-surface-2"
              role="progressbar"
              aria-label="ML phishing probability"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={mlPct}
            >
              <div className={`h-full rounded-full ${mlSev.bar}`} style={{ width: `${mlPct}%` }} />
            </div>
            <div className="mt-1 flex justify-between text-xs text-muted">
              <span>Benign</span>
              <span>Phishing</span>
            </div>
          </div>
        )}
      </div>
    </section>
  )
}