import React, { useState } from 'react'
import Sidebar from './components/Sidebar'
import TopBar from './components/TopBar'
import NewScan from './components/NewScan'
import HistoryTab from './components/HistoryTab'
import ReportsSettings from './components/ReportsSettings'
import useTheme from './hooks/useTheme'

const TITLES = {
  scan: 'New scan',
  history: 'Scan history',
  reports: 'Reports & settings',
}

export default function App() {
  const [page, setPage] = useState('scan')
  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
  const { theme, toggle } = useTheme()

  return (
    <div className="flex h-screen bg-bg text-fg">
      <Sidebar
        active={page}
        onNavigate={setPage}
        collapsed={collapsed}
        onToggleCollapse={() => setCollapsed((c) => !c)}
        mobileOpen={mobileOpen}
        onCloseMobile={() => setMobileOpen(false)}
      />

      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar
          title={TITLES[page]}
          theme={theme}
          onToggleTheme={toggle}
          onOpenMobile={() => setMobileOpen(true)}
        />

        <main className="flex-1 overflow-y-auto px-4 py-6 md:px-8">
          <div className="mx-auto max-w-6xl">
            {page === 'scan' && <NewScan />}
            {page === 'history' && <HistoryTab />}
            {page === 'reports' && <ReportsSettings theme={theme} onToggleTheme={toggle} />}
          </div>
        </main>
      </div>
    </div>
  )
}