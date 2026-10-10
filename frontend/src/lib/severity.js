// One source of truth for severity styling. Severity colors are used ONLY for
// badges, score bars, and the AI card's left border.
const SEVERITY = {
  LOW:      { label: 'LOW',      text: 'text-sev-low',      bg: 'bg-sev-low-bg',      bar: 'bg-sev-low',      borderL: 'border-l-sev-low' },
  MEDIUM:   { label: 'MEDIUM',   text: 'text-sev-medium',   bg: 'bg-sev-medium-bg',   bar: 'bg-sev-medium',   borderL: 'border-l-sev-medium' },
  HIGH:     { label: 'HIGH',     text: 'text-sev-high',     bg: 'bg-sev-high-bg',     bar: 'bg-sev-high',     borderL: 'border-l-sev-high' },
  CRITICAL: { label: 'CRITICAL', text: 'text-sev-critical', bg: 'bg-sev-critical-bg', bar: 'bg-sev-critical', borderL: 'border-l-sev-critical' },
  UNKNOWN:  { label: 'UNKNOWN',  text: 'text-muted',        bg: 'bg-surface-2',       bar: 'bg-muted',        borderL: 'border-l-line' },
}

export function getSeverity(level) {
  return SEVERITY[String(level || '').toUpperCase()] || SEVERITY.UNKNOWN
}

// Same 30% / 60% cutoffs the old ML meter used
export function levelFromProbability(p) {
  const v = Number(p) || 0
  return v < 0.3 ? 'LOW' : v < 0.6 ? 'MEDIUM' : 'HIGH'
}