import React from 'react'
import SeverityBadge from './SeverityBadge'
import TelemetryBreakdown from './TelemetryBreakdown'

// Impact levels are display hints only. The API doesn't send per-signal weights.
export default function MessageEvidence({ evidence }) {
  if (!evidence) return null

  const urls = evidence.url_evidences || []
  const extracted = evidence.extracted_urls || []
  const rows = [
    { signal: 'Urgency language', hit: evidence.urgency_detected },
    { signal: 'Financial lure', hit: evidence.financial_lures_detected },
    { signal: 'Suspicious phone or sender', hit: evidence.suspicious_phone_or_sender },
  ]

  return (
    <div className="space-y-4">
      <section className="rounded-lg border border-line bg-surface" aria-label="Message signals">
        <div className="flex items-baseline justify-between px-5 py-4">
          <h3 className="text-sm font-semibold">Message signals</h3>
          <span className="text-xs text-muted">{rows.length} signals</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[480px] text-sm">
            <thead>
              <tr className="border-y border-line bg-surface-2 text-left text-xs text-muted">
                <th scope="col" className="px-5 py-2 font-medium">Signal</th>
                <th scope="col" className="px-3 py-2 font-medium">Finding</th>
                <th scope="col" className="px-3 py-2 font-medium">Impact</th>
                <th scope="col" className="px-5 py-2 font-medium">Source</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.signal} className="border-b border-line last:border-b-0">
                  <td className="px-5 py-2 font-medium">{r.signal}</td>
                  <td className="px-3 py-2">{r.hit ? 'Detected' : 'Not detected'}</td>
                  <td className="px-3 py-2">
                    {r.hit ? <SeverityBadge level="MEDIUM" /> : <span className="text-muted">–</span>}
                  </td>
                  <td className="px-5 py-2 text-muted">Rule</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="rounded-lg border border-line bg-surface p-5" aria-label="Links found in message">
        <h3 className="mb-2 text-sm font-semibold">Links found in message</h3>
        {extracted.length > 0 ? (
          <ul className="space-y-1">
            {extracted.map((u, i) => (
              <li key={i} className="break-all font-mono text-xs">{u}</li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted">This message contains no links.</p>
        )}
      </section>

      {urls.map((u, i) => (
        <div key={i} className="space-y-2">
          <p className="break-all font-mono text-xs text-muted">
            Link {i + 1}: {u.final_url || extracted[i] || 'unknown'}
          </p>
          {u.lexical_features ? (
            <TelemetryBreakdown evidence={u} />
          ) : (
            <p className="rounded-lg border border-line bg-surface p-4 text-sm text-muted">
              No signal data is available for this link.
            </p>
          )}
        </div>
      ))}
    </div>
  )
}