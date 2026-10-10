import React from 'react'
import SeverityBadge from './SeverityBadge'
import { levelFromProbability } from '../lib/severity'

const val = (v, digits) => {
  if (v == null) return 'N/A'
  return digits != null ? Number(v).toFixed(digits) : String(v)
}

const on = (v) => v === 1 || v === true

// NOTE: the "impact" thresholds below are display-only hints chosen on the
// frontend. They are NOT the backend's real scoring weights. Once the API
// returns per-signal weights, replace `impact` with those.
function buildGroups(evidence) {
  const lf = evidence.lexical_features
  const {
    domain_age_days, ssl_valid, ssl_issuer, redirect_count, final_url,
    is_ip_address, brand_impersonation, safe_browsing_hit, ml_probability,
  } = evidence

  const mlImpact = ml_probability == null ? null : levelFromProbability(ml_probability)

  return [
    {
      title: 'URL structure',
      rows: [
        { signal: 'URL length', finding: val(lf.url_length), impact: lf.url_length > 75 ? 'MEDIUM' : null, source: 'Rule' },
        { signal: 'Hostname length', finding: val(lf.hostname_length), impact: lf.hostname_length > 30 ? 'MEDIUM' : null, source: 'Rule' },
        { signal: 'Path length', finding: val(lf.path_length), impact: null, source: 'Rule' },
        { signal: 'Path depth', finding: val(lf.path_depth), impact: lf.path_depth > 5 ? 'MEDIUM' : null, source: 'Rule' },
        { signal: 'Subdomain count', finding: val(lf.subdomain_count), impact: lf.subdomain_count > 3 ? 'MEDIUM' : null, source: 'Rule' },
        { signal: 'Dot count', finding: val(lf.dot_count), impact: lf.dot_count > 4 ? 'MEDIUM' : null, source: 'Rule' },
        { signal: 'Hyphen count', finding: val(lf.hyphen_count), impact: lf.hyphen_count > 3 ? 'MEDIUM' : null, source: 'Rule' },
        { signal: 'Digit ratio', finding: val(lf.digit_ratio, 2), impact: lf.digit_ratio > 0.3 ? 'MEDIUM' : null, source: 'Rule' },
        { signal: 'Shannon entropy', finding: val(lf.shannon_entropy, 3), impact: lf.shannon_entropy > 4 ? 'MEDIUM' : null, source: 'Rule' },
        { signal: 'Uses IP address', finding: on(lf.has_ip) ? 'Yes' : 'No', impact: on(lf.has_ip) ? 'HIGH' : null, source: 'Rule' },
        { signal: 'Suspicious TLD', finding: (on(lf.suspicious_tld) || on(evidence.suspicious_tld)) ? 'Yes' : 'No', impact: (on(lf.suspicious_tld) || on(evidence.suspicious_tld)) ? 'HIGH' : null, source: 'Rule' },
        { signal: 'Protocol', finding: on(lf.https_status) ? 'HTTPS' : 'HTTP', impact: on(lf.https_status) ? null : 'MEDIUM', source: 'Rule' },
      ],
    },
    {
      title: 'Domain and reputation',
      rows: [
        {
          signal: 'Domain age',
          finding: domain_age_days == null ? 'Unknown' : `${domain_age_days} days`,
          impact: domain_age_days == null ? null : domain_age_days < 30 ? 'HIGH' : domain_age_days < 180 ? 'MEDIUM' : null,
          source: 'Rule',
        },
        { signal: 'SSL certificate', finding: ssl_valid ? 'Valid' : 'Invalid or none', impact: ssl_valid ? null : 'HIGH', source: 'Rule' },
        { signal: 'SSL issuer', finding: ssl_issuer ?? 'N/A', impact: null, source: 'Rule' },
        { signal: 'Redirects', finding: val(redirect_count), impact: redirect_count > 2 ? 'MEDIUM' : null, source: 'Rule' },
        { signal: 'Final URL', finding: final_url ?? 'N/A', mono: true, impact: null, source: 'Rule' },
        { signal: 'IP-based host', finding: is_ip_address ? 'Yes' : 'No', impact: is_ip_address ? 'HIGH' : null, source: 'Rule' },
        { signal: 'Brand impersonation', finding: brand_impersonation ? 'Detected' : 'None', impact: brand_impersonation ? 'HIGH' : null, source: 'Rule' },
        { signal: 'Safe Browsing match', finding: safe_browsing_hit ? 'Match' : 'No match', impact: safe_browsing_hit ? 'CRITICAL' : null, source: 'Safe Browsing' },
        {
          signal: 'ML phishing probability',
          finding: ml_probability == null ? 'N/A' : `${(ml_probability * 100).toFixed(1)}%`,
          impact: mlImpact === 'LOW' ? null : mlImpact,
          source: 'ML',
        },
      ],
    },
  ]
}

export default function TelemetryBreakdown({ evidence }) {
  if (!evidence || !evidence.lexical_features) {
    return (
      <div className="rounded-lg border border-line bg-surface p-5 text-sm text-muted">
        No signal data is available for this scan.
      </div>
    )
  }

  const groups = buildGroups(evidence)
  const total = groups.reduce((n, g) => n + g.rows.length, 0)

  return (
    <section className="rounded-lg border border-line bg-surface" aria-label="Threat signals">
      <div className="flex items-baseline justify-between px-5 py-4">
        <h3 className="text-sm font-semibold">Threat signals</h3>
        <span className="text-xs text-muted">{total} signals</span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full min-w-[560px] text-sm">
          <thead>
            <tr className="border-y border-line bg-surface-2 text-left text-xs font-medium text-muted">
              <th scope="col" className="px-5 py-2 font-medium">Signal</th>
              <th scope="col" className="px-3 py-2 font-medium">Finding</th>
              <th scope="col" className="px-3 py-2 font-medium">Impact</th>
              <th scope="col" className="px-5 py-2 font-medium">Source</th>
            </tr>
          </thead>
          {groups.map((group) => (
            <tbody key={group.title}>
              <tr className="border-b border-line bg-surface-2">
                <th colSpan={4} scope="colgroup" className="px-5 py-1.5 text-left text-xs font-semibold">
                  {group.title}
                </th>
              </tr>
              {group.rows.map((row) => (
                <tr key={row.signal} className="border-b border-line last:border-b-0">
                  <td className="px-5 py-2 font-medium">{row.signal}</td>
                  <td className={`px-3 py-2 ${row.mono ? 'break-all font-mono text-xs' : ''}`}>{row.finding}</td>
                  <td className="px-3 py-2">
                    {row.impact ? <SeverityBadge level={row.impact} /> : <span className="text-muted">–</span>}
                  </td>
                  <td className="px-5 py-2 text-muted">{row.source}</td>
                </tr>
              ))}
            </tbody>
          ))}
        </table>
      </div>
    </section>
  )
}
