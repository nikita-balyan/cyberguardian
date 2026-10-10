import React, { useState } from 'react'
import { Globe, MessageSquare, QrCode, Layers } from 'lucide-react'
import UrlScanner from './UrlScanner'
import MessageScanner from './MessageScanner'
import QrScanner from './QrScanner'
import BatchScanner from './BatchScanner'

const TABS = [
  { id: 'url', label: 'URL', icon: Globe, Component: UrlScanner },
  { id: 'message', label: 'Message', icon: MessageSquare, Component: MessageScanner },
  { id: 'qr', label: 'QR code', icon: QrCode, Component: QrScanner },
  { id: 'batch', label: 'Batch', icon: Layers, Component: BatchScanner },
]

export default function NewScan() {
  const [tab, setTab] = useState('url')
  const Active = TABS.find((t) => t.id === tab).Component

  return (
    <section>
      <p className="mb-4 text-sm text-muted">
        Check a link, a message, a QR code, or a list of links for scam and phishing signals.
      </p>

      <div role="tablist" aria-label="Scan type" className="mb-6 flex gap-1 border-b border-line overflow-x-auto">
        {TABS.map(({ id, label, icon: Icon }) => {
          const isActive = tab === id
          return (
            <button
              key={id}
              role="tab"
              aria-selected={isActive}
              onClick={() => setTab(id)}
              className={`-mb-px flex items-center gap-2 whitespace-nowrap border-b-2 px-3 py-2 text-sm font-medium transition-colors ${
                isActive
                  ? 'border-accent text-fg'
                  : 'border-transparent text-muted hover:text-fg'
              }`}
            >
              <Icon className="h-4 w-4" aria-hidden="true" />
              {label}
            </button>
          )
        })}
      </div>

      <div role="tabpanel">
        <Active />
      </div>
    </section>
  )
}