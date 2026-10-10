import React from 'react'
import { getSeverity } from '../lib/severity'

export default function SeverityBadge({ level, label, className = '' }) {
  const s = getSeverity(level)
  return (
    <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold ${s.bg} ${s.text} ${className}`}>
      {label || s.label}
    </span>
  )
}