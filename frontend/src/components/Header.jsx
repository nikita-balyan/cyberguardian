import React, { useState, useEffect } from 'react'
import { Shield, Activity, Wifi, WifiOff } from 'lucide-react'
import { checkHealth } from '../services/api'

export default function Header() {
  const [backendStatus, setBackendStatus] = useState('checking')

  useEffect(() => {
    let isMounted = true
    const verifyHealth = async () => {
      try {
        await checkHealth()
        if (isMounted) setBackendStatus('online')
      } catch (err) {
        if (isMounted) setBackendStatus('offline')
      }
    }
    verifyHealth()
    const interval = setInterval(verifyHealth, 10000)
    return () => {
      isMounted = false
      clearInterval(interval)
    }
  }, [])

  return (
    <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="bg-blue-600 p-2 rounded-xl text-white shadow-lg shadow-blue-500/20 flex items-center justify-center">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <span className="text-xl font-bold bg-gradient-to-r from-blue-400 via-indigo-300 to-cyan-400 bg-clip-text text-transparent">
              CyberGuardian
            </span>
            <span className="hidden sm:inline-block ml-2 text-xs px-2 py-0.5 rounded-full bg-blue-950 text-blue-400 border border-blue-800/60">
              Threat Intelligence Analyzer
            </span>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 text-xs bg-slate-900 px-3 py-1.5 rounded-full border border-slate-800">
            {backendStatus === 'online' ? (
              <>
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                <span className="text-emerald-400 font-medium">API Connected</span>
                <Wifi className="w-3.5 h-3.5 text-emerald-400 ml-1" />
              </>
            ) : backendStatus === 'offline' ? (
              <>
                <span className="w-2 h-2 rounded-full bg-rose-500"></span>
                <span className="text-rose-400 font-medium">API Offline</span>
                <WifiOff className="w-3.5 h-3.5 text-rose-400 ml-1" />
              </>
            ) : (
              <>
                <span className="w-2 h-2 rounded-full bg-amber-500 animate-ping"></span>
                <span className="text-amber-400 font-medium">Checking API...</span>
              </>
            )}
          </div>
        </div>
      </div>
    </header>
  )
}
