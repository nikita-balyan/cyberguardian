import React from 'react'

// Matches inline markdown tokens: **bold**, __bold__, *italic*, _italic_, `code`, [text](url)
const INLINE_PATTERN =
  /(\*\*(?:[^*]|\*(?!\*))+\*\*|__(?:[^_]|_(?!_))+__|\*(?:[^*])+\*|_(?:[^_])+_|`[^`]+`|\[[^\]]+\]\([^)]+\))/g

// Only allow safe link protocols (blocks javascript: and similar)
const isSafeUrl = (href) => /^(https?:|mailto:)/i.test(href.trim())

// Renders a single line of inline markdown into React nodes.
export function renderInline(text, keyPrefix = 'md') {
  if (text === null || text === undefined) return null
  const parts = String(text).split(INLINE_PATTERN)
  return parts.map((part, idx) => {
    if (!part) return null
    const key = `${keyPrefix}-${idx}`

    if (
      (part.startsWith('**') && part.endsWith('**')) ||
      (part.startsWith('__') && part.endsWith('__'))
    ) {
      return (
        <strong key={key} className="font-semibold">
          {part.slice(2, -2)}
        </strong>
      )
    }

    if (part.startsWith('`') && part.endsWith('`')) {
      return (
        <code
          key={key}
          className="mx-0.5 rounded border border-line bg-surface-2 px-1.5 py-0.5 font-mono text-[0.85em]"
        >
          {part.slice(1, -1)}
        </code>
      )
    }

    if (
      (part.startsWith('*') && part.endsWith('*')) ||
      (part.startsWith('_') && part.endsWith('_'))
    ) {
      return (
        <em key={key} className="italic">
          {part.slice(1, -1)}
        </em>
      )
    }

    const linkMatch = part.match(/^\[([^\]]+)\]\(([^)]+)\)$/)
    if (linkMatch) {
      if (!isSafeUrl(linkMatch[2])) {
        return <React.Fragment key={key}>{linkMatch[1]}</React.Fragment>
      }
      return (
        <a
          key={key}
          href={linkMatch[2]}
          target="_blank"
          rel="noopener noreferrer"
          className="break-all text-accent underline underline-offset-2 hover:text-accent-hover"
        >
          {linkMatch[1]}
        </a>
      )
    }

    return <React.Fragment key={key}>{part}</React.Fragment>
  })
}

const HEADING_CLASSES = {
  1: 'text-base font-semibold mt-1 mb-2',
  2: 'text-sm font-semibold mt-1 mb-1.5',
  3: 'text-sm font-semibold mt-1 mb-1',
  4: 'text-sm font-medium mt-1 mb-1',
  5: 'text-xs font-medium text-muted mt-1 mb-1',
  6: 'text-xs font-medium text-muted mt-1 mb-1',
}

// Renders a full block-level markdown document (headings, lists, quotes, rules, paragraphs).
export default function MarkdownRenderer({ content, className = '' }) {
  if (!content) return null

  const lines = String(content).split(/\r?\n/)
  const blocks = []
  let listBuffer = null // { ordered: boolean, items: string[] }

  const flushList = () => {
    if (!listBuffer) return
    const { ordered, items } = listBuffer
    const ListTag = ordered ? 'ol' : 'ul'
    blocks.push(
      <ListTag
        key={`list-${blocks.length}`}
        className={ordered ? 'ml-5 list-outside list-decimal space-y-1.5' : 'ml-5 list-outside list-disc space-y-1.5'}
      >
        {items.map((item, i) => (
          <li key={i} className="pl-1 leading-relaxed">
            {renderInline(item, `li-${blocks.length}-${i}`)}
          </li>
        ))}
      </ListTag>
    )
    listBuffer = null
  }

  lines.forEach((rawLine, idx) => {
    const line = rawLine.trimEnd()

    if (!line.trim()) {
      flushList()
      return
    }

    const headingMatch = line.match(/^(#{1,6})\s+(.*)$/)
    if (headingMatch) {
      flushList()
      const level = headingMatch[1].length
      const Tag = `h${level}`
      blocks.push(
        <Tag key={`h-${idx}`} className={HEADING_CLASSES[level]}>
          {renderInline(headingMatch[2], `h-${idx}`)}
        </Tag>
      )
      return
    }

    if (/^(---|\*\*\*|___)\s*$/.test(line.trim())) {
      flushList()
      blocks.push(<hr key={`hr-${idx}`} className="my-2 border-line" />)
      return
    }

    const quoteMatch = line.match(/^>\s?(.*)$/)
    if (quoteMatch) {
      flushList()
      blocks.push(
        <blockquote key={`q-${idx}`} className="border-l-2 border-line py-0.5 pl-3 text-muted">
          {renderInline(quoteMatch[1], `q-${idx}`)}
        </blockquote>
      )
      return
    }

    const ulMatch = line.match(/^\s*[-*+]\s+(.*)$/)
    if (ulMatch) {
      if (!listBuffer || listBuffer.ordered) {
        flushList()
        listBuffer = { ordered: false, items: [] }
      }
      listBuffer.items.push(ulMatch[1])
      return
    }

    const olMatch = line.match(/^\s*\d+\.\s+(.*)$/)
    if (olMatch) {
      if (!listBuffer || !listBuffer.ordered) {
        flushList()
        listBuffer = { ordered: true, items: [] }
      }
      listBuffer.items.push(olMatch[1])
      return
    }

    flushList()
    blocks.push(
      <p key={`p-${idx}`} className="leading-relaxed">
        {renderInline(line, `p-${idx}`)}
      </p>
    )
  })

  flushList()

  return <div className={`space-y-2 ${className}`}>{blocks}</div>
}