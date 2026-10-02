import React, { useState } from 'react';
import { X, ShieldAlert, Sparkles, Copy, Check, ExternalLink, Code2, AlertTriangle, Lightbulb, FileText, ArrowRight } from 'lucide-react';
import SeverityBadge from '../common/SeverityBadge';
import api from '../../services/api';

export default function FindingDrawer({ finding, isOpen, onClose, onAskAI, scanId }) {
  const [copied, setCopied] = useState(false);
  const [aiExplanation, setAiExplanation] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);

  if (!isOpen || !finding) return null;

  const copyCode = (code) => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const requestAiExplanation = async () => {
    setAiLoading(true);
    try {
      const res = await api.post('/ai/ask', {
        query: `Explain rule ${finding.rule_id} (${finding.title}) on endpoint ${finding.method} ${finding.endpoint} and show why it matters.`,
        findingId: finding.id || finding.rule_id,
        endpoint: finding.endpoint,
        scanId
      });
      if (res.data.success) {
        setAiExplanation(res.data.data.answer);
      }
    } catch (err) {
      setAiExplanation('Unable to contact AI Security Assistant at this moment.');
    } finally {
      setAiLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/30 backdrop-blur-sm flex justify-end animate-in fade-in duration-200">
      <div 
        className="w-full max-w-2xl bg-white h-full shadow-2xl flex flex-col border-l border-edge transform transition-transform animate-in slide-in-from-right duration-300 overflow-y-auto"
      >
        {/* Header */}
        <div className="p-6 border-b border-edge sticky top-0 bg-white/95 backdrop-blur z-10 flex items-start justify-between">
          <div className="space-y-2">
            <div className="flex items-center gap-2.5">
              <SeverityBadge severity={finding.severity} size="md" />
              <span className="font-mono text-xs font-bold text-sentinel-800 bg-sentinel-50 border border-sentinel-200 px-2 py-0.5 rounded">
                {finding.rule_id}
              </span>
              <span className="text-xs text-ink-muted">{finding.category}</span>
            </div>
            <h2 className="text-lg font-bold text-ink leading-snug">{finding.title}</h2>
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-surface-subtle border border-edge text-ink">
                {finding.method}
              </span>
              <span className="font-mono text-xs text-sentinel-900 break-all font-semibold">
                {finding.endpoint}
              </span>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-surface-subtle text-ink-muted hover:text-ink transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-6 flex-1">
          
          {/* Quick AI Action Card */}
          <div className="p-4 rounded-xl bg-sentinel-50 border border-sentinel-200 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-subtle">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-sentinel-700 text-white flex items-center justify-center flex-shrink-0">
                <Sparkles className="w-4 h-4" />
              </div>
              <div>
                <p className="text-xs font-bold text-sentinel-950">Ask Sentinel AI Security Assistant</p>
                <p className="text-[11px] text-sentinel-700">Get deep contextual explanation & defensive remediation</p>
              </div>
            </div>
            <button
              onClick={() => {
                if (onAskAI) onAskAI(finding);
                else requestAiExplanation();
              }}
              disabled={aiLoading}
              className="px-3 py-1.5 bg-sentinel-700 hover:bg-sentinel-800 text-white text-xs font-semibold rounded-lg shadow-sm transition-all flex items-center gap-1.5 flex-shrink-0"
            >
              {aiLoading ? 'Analyzing...' : 'Ask AI Reasoner'}
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          {/* AI Response Preview if requested locally */}
          {aiExplanation && (
            <div className="p-4 rounded-xl bg-surface-subtle border border-sentinel-300 space-y-2">
              <div className="flex items-center gap-2 text-xs font-bold text-sentinel-800">
                <Sparkles className="w-3.5 h-3.5 text-sentinel-600" />
                <span>AI Security Reasoning</span>
              </div>
              <div className="text-xs text-ink leading-relaxed whitespace-pre-line font-sans">
                {aiExplanation}
              </div>
            </div>
          )}

          {/* Section: Why This Matters */}
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-ink-muted">
              <Lightbulb className="w-4 h-4 text-amber-600" />
              <span>Why This Finding Matters</span>
            </div>
            <div className="p-3.5 rounded-xl bg-surface-subtle border border-edge text-xs text-ink leading-relaxed">
              {finding.description}
            </div>
          </div>

          {/* Section: Evidence from API Specification */}
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-ink-muted">
              <FileText className="w-4 h-4 text-sentinel-700" />
              <span>Specification Evidence & Metadata</span>
            </div>
            <div className="p-3.5 rounded-xl bg-surface-muted border border-edge font-mono text-xs text-sentinel-950 leading-relaxed break-words">
              {finding.evidence}
            </div>
          </div>

          {/* Section: Potential Impact */}
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-ink-muted">
              <AlertTriangle className="w-4 h-4 text-red-600" />
              <span>Potential Security Impact</span>
            </div>
            <div className="p-3.5 rounded-xl bg-red-50/50 border border-red-200/60 text-xs text-red-950 leading-relaxed">
              {finding.impact}
            </div>
          </div>

          {/* Section: Remediation & Defensive Code Example */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-ink-muted">
                <Code2 className="w-4 h-4 text-emerald-600" />
                <span>Recommended Remediation</span>
              </div>
              {finding.fix_code_example && (
                <button
                  onClick={() => copyCode(finding.fix_code_example)}
                  className="flex items-center gap-1 text-[11px] text-sentinel-700 hover:text-sentinel-900 font-semibold"
                >
                  {copied ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                  {copied ? 'Copied' : 'Copy Code'}
                </button>
              )}
            </div>
            <p className="text-xs text-ink leading-relaxed">{finding.recommendation}</p>

            {finding.fix_code_example && (
              <div className="relative mt-2 rounded-xl bg-zinc-900 text-zinc-100 p-4 font-mono text-xs overflow-x-auto shadow-inner border border-zinc-800">
                <pre className="text-[11px] leading-relaxed">{finding.fix_code_example}</pre>
              </div>
            )}
          </div>

          {/* Metadata & References Footer */}
          <div className="pt-4 border-t border-edge space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-ink-muted">
              <div className="flex items-center gap-4">
                <span>Confidence: <strong className="text-ink">{Math.round((finding.confidence || 0.85) * 100)}%</strong></span>
                {finding.cwe_id && <span>CWE: <strong className="text-ink">{finding.cwe_id}</strong></span>}
              </div>
              {finding.owasp_category && (
                <span className="text-[11px] bg-sentinel-50 text-sentinel-800 px-2 py-0.5 rounded border border-sentinel-200 font-semibold">
                  {finding.owasp_category}
                </span>
              )}
            </div>

            {finding.references && finding.references.length > 0 && (
              <div className="space-y-1.5">
                <p className="text-[11px] font-semibold text-ink-muted uppercase">Official Security References:</p>
                <div className="space-y-1">
                  {finding.references.map((ref, idx) => (
                    <a
                      key={idx}
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1.5 text-xs text-sentinel-700 hover:text-sentinel-900 hover:underline truncate"
                    >
                      <ExternalLink className="w-3 h-3 flex-shrink-0" />
                      <span className="truncate">{ref}</span>
                    </a>
                  ))}
                </div>
              </div>
            )}
          </div>

        </div>
      </div>
    </div>
  );
}
