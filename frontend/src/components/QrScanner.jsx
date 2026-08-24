import React, { useState, useRef } from 'react'
import { QrCode, Upload, Loader2, Sparkles, AlertCircle, X } from 'lucide-react'
import RiskMeter from './RiskMeter'
import AiExplanationCard from './AiExplanationCard'
import EvidenceInspector from './EvidenceInspector'
import ReportExport from './ReportExport'
import { scanQrCode } from '../services/api'

export default function QrScanner() {
  const [file, setFile] = useState(null)
  const [preview, setPreview] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)
  const fileInputRef = useRef(null)

  const processSelectedFile = (selectedFile) => {
    if (!['image/png', 'image/jpeg', 'image/webp'].includes(selectedFile.type)) {
      setError('Please upload a valid PNG, JPG, or WebP image.')
      return
    }
    setFile(selectedFile)
    setPreview(URL.createObjectURL(selectedFile))
    setError(null)
    setResult(null)
  }

  const handleScan = async () => {
    if (!file) return

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const data = await scanQrCode(file)
      setResult(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const clearFile = () => {
    setFile(null)
    setPreview(null)
    setResult(null)
    setError(null)
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  return (
    <div className="space-y-6">
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm shadow-xl">
        <div className="flex items-center space-x-3 mb-4">
          <div className="bg-indigo-600/20 p-2.5 rounded-xl border border-indigo-500/30 text-indigo-400">
            <QrCode className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">QR Code Threat Scanner</h3>
            <p className="text-xs text-slate-400">Upload QR code image (PNG, JPG, WebP) to decode and inspect</p>
          </div>
        </div>

        {!preview ? (
          <div
            onClick={() => fileInputRef.current?.click()}
            className="border-2 border-dashed border-slate-800 hover:border-indigo-500/50 bg-slate-950/60 rounded-2xl p-8 text-center cursor-pointer transition-all flex flex-col items-center justify-center space-y-3"
          >
            <div className="bg-slate-900 p-4 rounded-full text-slate-400">
              <Upload className="w-6 h-6 text-indigo-400" />
            </div>
            <div>
              <p className="text-sm font-semibold text-slate-200">Click to upload QR image</p>
              <p className="text-xs text-slate-500 mt-1">PNG, JPG, WebP supported</p>
            </div>
            <input
              ref={fileInputRef}
              type="file"
              accept="image/png, image/jpeg, image/webp"
              onChange={(e) => e.target.files?.[0] && processSelectedFile(e.target.files[0])}
              className="hidden"
            />
          </div>
        ) : (
          <div className="bg-slate-950/80 border border-slate-800 rounded-2xl p-6 flex flex-col sm:flex-row items-center justify-between gap-6">
            <div className="flex items-center space-x-4">
              <div className="w-20 h-20 bg-slate-900 rounded-xl overflow-hidden border border-slate-800 flex items-center justify-center">
                <img src={preview} alt="QR Preview" className="w-full h-full object-cover" />
              </div>
              <div>
                <span className="text-xs uppercase font-bold tracking-wider text-slate-500 block">File</span>
                <h4 className="text-sm font-bold text-slate-200 truncate max-w-xs">{file?.name}</h4>
              </div>
            </div>

            <div className="flex items-center space-x-3 w-full sm:w-auto">
              <button
                type="button"
                onClick={clearFile}
                className="p-3 bg-slate-900 hover:bg-slate-800 text-slate-400 rounded-xl border border-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
              <button
                type="button"
                onClick={handleScan}
                disabled={loading}
                className="flex-1 sm:flex-none bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-800 text-white font-medium px-6 py-3 rounded-xl flex items-center justify-center space-x-2 text-sm shadow-lg shadow-indigo-600/20"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <Sparkles className="w-4 h-4" />
                    <span>Scan QR</span>
                  </>
                )}
              </button>
            </div>
          </div>
        )}

        {error && (
          <div className="mt-4 p-4 bg-rose-950/30 border border-rose-900/50 rounded-xl flex items-center space-x-3 text-rose-300 text-sm">
            <AlertCircle className="w-5 h-5 text-rose-400" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {result && (
        <div className="space-y-6">
          <RiskMeter
            score={result.risk_assessment.score}
            level={result.risk_assessment.level}
            triggers={result.risk_assessment.triggers}
          />
          <AiExplanationCard explanation={result.explanation} />
          <EvidenceInspector evidence={result.evidence} />
          <ReportExport scanData={result} />
        </div>
      )}
    </div>
  )
}
