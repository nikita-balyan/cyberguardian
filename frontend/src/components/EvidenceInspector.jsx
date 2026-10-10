import React, { useState, useEffect, useRef } from 'react'
import { Database, X, Copy, Check, ChevronRight } from 'lucide-react'
import SeverityBadge from './SeverityBadge'

function Row({ label, children }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-t border-line py-2.5 text-sm first:border-t-0">
      <dt className="text-muted">{label}</dt>
      <dd className="text-right font-medium">{children}</dd>
    </div>
  )
}

export default function EvidenceInspector({ evidence }) {
  const [open, setOpen] = useState(false)
  const [copied, setCopied] = useState(false)
  const closeRef = useRef(null)

  useEffect(() => {
    if (!open) return
    const onKey = (e) => e.key === 'Escape' && setOpen(false)
    const prevOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    document.addEventListener('keydown', onKey)
    closeRef.current?.focus()
    return () => {
      document.body.style.overflow = prevOverflow
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  if (!evidence) return null

  const json = JSON.stringify(evidence, null, 2)
  const ti = evidence.threat_intel
  const feeds = ti?.sources
    ? [
        ['URLhaus', ti.sources.urlhaus],
        ['Google Safe Browsing', ti.sources.google_safebrowsing],
      ].filter(([, src]) => src)
    : []

  // URL scans have these fields. Message and QR scans usually don't, so we hide the section.
  const hasDetails =
    evidence.domain_age_days !== undefined ||
    evidence.ssl_valid !== undefined ||
    evidence.redirect_count !== undefined

  const copyJson = async () => {
    try {
      await navigator.clipboard.writeText(json)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      /* clipboard blocked: user can still select the text */
    }
  }

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="flex w-full items-center justify-between gap-3 rounded-lg border border-line bg-surface px-5 py-3 text-left transition-colors hover:bg-surface-2"
      >
        <span className="flex items-center gap-3">
          <Database className="h-4 w-4 text-muted" aria-hidden="true" />
          <span>
            <span className="block text-sm font-semibold">Raw evidence</span>
            <span className="block text-xs text-muted">Scan details, threat feed results, and the full JSON</span>
          </span>
        </span>
        <ChevronRight className="h-4 w-4 text-muted" aria-hidden="true" />
      </button>

      {open && (
        <div className="fixed inset-0 z-50" role="dialog" aria-modal="true" aria-label="Raw evidence">
          <div className="absolute inset-0 bg-slate-900/50" onClick={() => setOpen(false)} />

          <aside className="absolute right-0 top-0 flex h-full w-full max-w-xl flex-col border-l border-line bg-surface shadow-xl">
            <div className="flex h-14 shrink-0 items-center justify-between border-b border-line px-5">
              <h3 className="text-sm font-semibold">Raw evidence</h3>
              <button
                ref={closeRef}
                type="button"
                onClick={() => setOpen(false)}
                aria-label="Close evidence panel"
                className="rounded-md p-2 text-muted hover:bg-surface-2 hover:text-fg"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="flex-1 space-y-6 overflow-y-auto p-5">
              {/* Scan details */}
              {hasDetails && (
                <div>
                  <h4 className="mb-1 text-sm font-semibold">Scan details</h4>
                  <dl>
                    {evidence.domain_age_days !== undefined && (
                      <Row label="Domain age">
                        {evidence.domain_age_days !== null ? `${evidence.domain_age_days} days` : 'Unknown'}
                      </Row>
                    )}
                    {evidence.ssl_valid !== undefined && (
                      <Row label="SSL certificate">
                        {evidence.ssl_valid ? (
                          <SeverityBadge level="LOW" label="Valid" />
                        ) : (
                          <SeverityBadge level="HIGH" label="Invalid or none" />
                        )}
                      </Row>
                    )}
                    {evidence.redirect_count !== undefined && (
                      <Row label="Redirects">{evidence.redirect_count} hops</Row>
                    )}
                  </dl>
                </div>
              )}

              {/* Threat intelligence */}
              {ti != null ? (
                <div>
                  <div className="mb-2 flex items-center justify-between gap-3">
                    <h4 className="text-sm font-semibold">Threat intelligence</h4>
                    {ti.flagged ? (
                      <SeverityBadge level="CRITICAL" label="Flagged by threat feeds" />
                    ) : (
                      <SeverityBadge level="LOW" label="Clean" />
                    )}
                  </div>

                  {ti.flagged && ti.threat_summary && ti.threat_summary.length > 0 && (
                    <div className="mb-3 rounded-md bg-sev-critical-bg p-3 text-xs text-sev-critical">
                      <p className="mb-1 font-semibold">Feed alerts</p>
                      <ul className="list-disc space-y-0.5 pl-4">
                        {ti.threat_summary.map((s, idx) => (
                          <li key={idx}>{s}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {feeds.length > 0 && (
                    <div className="overflow-x-auto rounded-md border border-line">
                      <table className="w-full text-sm">
                        <thead>
                          <tr className="bg-surface-2 text-left text-xs text-muted">
                            <th scope="col" className="px-3 py-2 font-medium">Feed</th>
                            <th scope="col" className="px-3 py-2 font-medium">Status</th>
                            <th scope="col" className="px-3 py-2 font-medium">Result</th>
                          </tr>
                        </thead>
                        <tbody>
                          {feeds.map(([name, src]) => (
                            <tr key={name} className="border-t border-line">
                              <td className="px-3 py-2 font-medium">{name}</td>
                              <td className="px-3 py-2 text-muted">{src.status}</td>
                              <td className="px-3 py-2">
                                {src.flagged ? (
                                  <SeverityBadge level="CRITICAL" label="Flagged" />
                                ) : (
                                  <SeverityBadge level="LOW" label="Clean" />
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              ) : (
                evidence.safe_browsing_hit !== undefined && (
                  <div>
                    <h4 className="mb-1 text-sm font-semibold">Threat intelligence</h4>
                    <dl>
                      <Row label="Safe Browsing">
                        {evidence.safe_browsing_hit ? (
                          <SeverityBadge level="CRITICAL" label="Match" />
                        ) : (
                          <SeverityBadge level="LOW" label="Clean" />
                        )}
                      </Row>
                    </dl>
                  </div>
                )
              )}

              {/* Raw JSON */}
              <div>
                <div className="mb-2 flex items-center justify-between">
                  <h4 className="text-sm font-semibold">Full JSON</h4>
                  <button
                    type="button"
                    onClick={copyJson}
                    className="inline-flex items-center gap-1.5 rounded-md border border-line bg-surface px-2.5 py-1 text-xs font-medium hover:bg-surface-2"
                  >
                    {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                    {copied ? 'Copied' : 'Copy JSON'}
                  </button>
                </div>
                <pre className="max-h-96 overflow-auto rounded-md border border-line bg-surface-2 p-4 font-mono text-xs">
                  {json}
                </pre>
              </div>
            </div>
          </aside>
        </div>
      )}
    </>
  )
}
