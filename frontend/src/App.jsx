import React, { useState } from 'react'
import Header from './components/Header'
import UrlScanner from './components/UrlScanner'
import QrScanner from './components/QrScanner'
import MessageScanner from './components/MessageScanner'
import HistoryTab from './components/HistoryTab'
import { Globe, QrCode, MessageSquare, Shield, Clock } from 'lucide-react'

export default function App() {
  const [activeTab, setActiveTab] = useState('url')

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      <Header />

      <main className="flex-1 max-w-5xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Hero Section */}
        <div className="text-center space-y-3">
          <div className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-full bg-blue-950/60 border border-blue-800/50 text-blue-400 text-xs font-semibold mb-2 shadow-inner">
            <Shield className="w-3.5 h-3.5" />
            <span>Autonomous Threat Intelligence & Phishing Analyzer</span>
          </div>
          <h1 className="text-3xl sm:text-4xl font-black tracking-tight bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
            Unified Threat Scanner Dashboard
          </h1>
          <p className="text-sm sm:text-base text-slate-400 max-w-2xl mx-auto">
            Instantly evaluate URLs, QR codes, and suspicious messages using deterministic scoring engines and grounded AI threat explanations.
          </p>
        </div>

        {/* Navigation Tabs */}
        <div className="flex justify-center">
          <div className="bg-slate-900/90 border border-slate-800/80 p-1.5 rounded-2xl flex items-center space-x-1 shadow-xl backdrop-blur-md flex-wrap justify-center">
            <button
              onClick={() => setActiveTab('url')}
              className={`flex items-center space-x-2 px-5 py-2.5 rounded-xl text-sm font-semibold transition-all ${
                activeTab === 'url'
                  ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/25'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Globe className="w-4 h-4" />
              <span>URL Scanner</span>
            </button>

            <button
              onClick={() => setActiveTab('qr')}
              className={`flex items-center space-x-2 px-5 py-2.5 rounded-xl text-sm font-semibold transition-all ${
                activeTab === 'qr'
                  ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/25'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <QrCode className="w-4 h-4" />
              <span>QR Scanner</span>
            </button>

            <button
              onClick={() => setActiveTab('message')}
              className={`flex items-center space-x-2 px-5 py-2.5 rounded-xl text-sm font-semibold transition-all ${
                activeTab === 'message'
                  ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-600/25'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <MessageSquare className="w-4 h-4" />
              <span>Phishing Message</span>
            </button>

            <button
              onClick={() => setActiveTab('history')}
              className={`flex items-center space-x-2 px-5 py-2.5 rounded-xl text-sm font-semibold transition-all ${
                activeTab === 'history'
                  ? 'bg-purple-600 text-white shadow-lg shadow-purple-600/25'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Clock className="w-4 h-4" />
              <span>Scan History & Analytics</span>
            </button>
          </div>
        </div>

        {/* Active Tab Content */}
        <div className="transition-all duration-300">
          {activeTab === 'url' && <UrlScanner />}
          {activeTab === 'qr' && <QrScanner />}
          {activeTab === 'message' && <MessageScanner />}
          {activeTab === 'history' && <HistoryTab />}
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-6 mt-16 text-center text-xs text-slate-500">
        <p>CyberGuardian Threat Intelligence Analyzer &copy; 2026 • Built with FastAPI, Pydantic, & React</p>
      </footer>
    </div>
  )
}
