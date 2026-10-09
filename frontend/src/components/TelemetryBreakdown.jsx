import React from "react"
import { Brain, Globe, CheckCircle2, AlertTriangle, AlertOctagon, Shield, Clock, FileText, Copy, SlidersHorizontal } from "lucide-react"

export default function TelemetryBreakdown({ evidence }) {
  if (!evidence || !evidence.lexical_features) {
    return (
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm shadow-xl text-slate-400 text-sm">
        No telemetry data available for this scan.
      </div>
    )
  }

  const {
    lexical_features: lf,
    domain_age_days,
    ssl_valid,
    ssl_issuer,
    redirect_count,
    final_url,
    is_ip_address,
    brand_impersonation,
    safe_browsing_hit,
    ml_probability,
  } = evidence

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 backdrop-blur-sm shadow-xl space-y-6">
      <div className="flex items-center space-x-3 pb-4 border-b border-slate-800">
        <div className="bg-indigo-600/20 p-2.5 rounded-xl border border-indigo-500/30 text-indigo-400">
          <Brain className="w-5 h-5" />
        </div>
        <div>
          <h3 className="text-lg font-bold text-white">URL Lexical Telemetry</h3>
          <p className="text-xs text-slate-400">12 extracted lexical features from evidence JSON</p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 mb-6">
        <div className="bg-slate-950/60 border border-slate-800/50 rounded-xl p-3">
          <p className="text-sm font-medium text-slate-300">URL Length</p>
          <p className="text-xs text-slate-400">{lf?.url_length ?? "N/A"}</p>
        </div>
        <div className="bg-slate-950/60 border border-slate-800/50 rounded-xl p-3">
          <p className="text-sm font-medium text-slate-300">Hostname Length</p>
          <p className="text-xs text-slate-400">{lf?.hostname_length ?? "N/A"}</p>
        </div>
        <div className="bg-slate-950/60 border border-slate-800/50 rounded-xl p-3">
          <p className="text-sm font-medium text-slate-300">Path Length</p>
          <p className="text-xs text-slate-400">{lf?.path_length ?? "N/A"}</p>
        </div>
        <div className="bg-slate-950/60 border border-slate-800/50 rounded-xl p-3">
          <p className="text-sm font-medium text-slate-300">Shannon Entropy</p>
          <p className="text-xs text-slate-400">{lf?.shannon_entropy?.toFixed(3) ?? "N/A"}</p>
        </div>
        <div className="bg-slate-950/60 border border-slate-800/50 rounded-xl p-3">
          <p className="text-sm font-medium text-slate-300">Subdomain Count</p>
          <p className="text-xs text-slate-400">{lf?.subdomain_count ?? "N/A"}</p>
        </div>
        <div className="bg-slate-950/60 border border-slate-800/50 rounded-xl p-3">
          <p className="text-sm font-medium text-slate-300">Dot Count</p>
          <p className="text-xs text-slate-400">{lf?.dot_count ?? "N/A"}</p>
        </div>
        <div className="bg-slate-950/60 border border-slate-800/50 rounded-xl p-3">
          <p className="text-sm font-medium text-slate-300">Hyphen Count</p>
          <p className="text-xs text-slate-400">{lf?.hyphen_count ?? "N/A"}</p>
        </div>
        <div className="bg-slate-950/60 border border-slate-800/50 rounded-xl p-3">
          <p className="text-sm font-medium text-slate-300">Has IP</p>
          <p className="text-xs text-slate-400">{lf?.has_ip === 1 ? "Yes" : "No"}</p>
        </div>
        <div className="bg-slate-950/60 border border-slate-800/50 rounded-xl p-3">
          <p className="text-sm font-medium text-slate-300">Suspicious TLD</p>
          <p className="text-xs text-slate-400">{lf?.suspicious_tld === 1 ? "HIGH" : "LOW"}</p>
        </div>
        <div className="bg-slate-950/60 border border-slate-800/50 rounded-xl p-3">
          <p className="text-sm font-medium text-slate-300">Digit Ratio</p>
          <p className="text-xs text-slate-400">{lf?.digit_ratio?.toFixed(2) ?? "N/A"}</p>
        </div>
        <div className="bg-slate-950/60 border border-slate-800/50 rounded-xl p-3">
          <p className="text-sm font-medium text-slate-300">Path Depth</p>
          <p className="text-xs text-slate-400">{lf?.path_depth ?? "N/A"}</p>
        </div>
        <div className="bg-slate-950/60 border border-slate-800/50 rounded-xl p-3">
          <p className="text-sm font-medium text-slate-300">HTTPS Status</p>
          <p className="text-xs text-slate-400">{lf?.https_status === 1 ? "HTTPS" : "HTTP"}</p>
        </div>
      </div>

      <div>
        <h4 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-3">Evidence Snapshot</h4>
        <div className="grid grid-cols-2 gap-3 text-xs">
          <div className="bg-slate-950/60 border border-slate-800/50 rounded-xl p-2">
            <span className="text-slate-500">Domain Age:</span>
            <span className="text-slate-300 font-mono ms-1">{domain_age_days ?? "N/A"}</span>
          </div>
          <div className="bg-slate-950/60 border border-slate-800/50 rounded-xl p-2">
            <span className="text-slate-500">SSL Valid:</span>
            <span className="text-slate-300 font-mono ms-1">{ssl_valid ? "Yes" : "No"}</span>
          </div>
          <div className="bg-slate-950/60 border border-slate-800/50 rounded-xl p-2">
            <span className="text-slate-500">SSL Issuer:</span>
            <span className="text-slate-300 font-mono ms-1">{ssl_issuer ?? "N/A"}</span>
          </div>
          <div className="bg-slate-950/60 border border-slate-800/50 rounded-xl p-2">
            <span className="text-slate-500">Redirects:</span>
            <span className="text-slate-300 font-mono ms-1">{redirect_count}</span>
          </div>
          <div className="bg-slate-950/60 border border-slate-800/50 rounded-xl p-2">
            <span className="text-slate-500">Is IP:</span>
            <span className="text-slate-300 font-mono ms-1">{is_ip_address ? "Yes" : "No"}</span>
          </div>
          <div className="bg-slate-950/60 border border-slate-800/50 rounded-xl p-2">
            <span className="text-slate-500">Brand Impersonation:</span>
            <span className="text-slate-300 font-mono ms-1">{brand_impersonation ? "Yes" : "No"}</span>
          </div>
          <div className="bg-slate-950/60 border border-slate-800/50 rounded-xl p-2">
            <span className="text-slate-500">Safe Browsing Hit:</span>
            <span className="text-slate-300 font-mono ms-1">{safe_browsing_hit ? "Yes" : "No"}</span>
          </div>
          <div className="bg-slate-950/60 border border-slate-800/50 rounded-xl p-2">
            <span className="text-slate-500">ML Phishing Prob:</span>
            <span className="text-slate-300 font-mono ms-1">
              {ml_probability !== null ? (ml_probability * 100).toFixed(1) + "%" : "N/A"}
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}
