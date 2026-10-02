import React, { useState, useEffect } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { GitCompare, ArrowRight, CheckCircle2, AlertOctagon, AlertTriangle, Shield, RefreshCw } from 'lucide-react';
import api from '../services/api';
import SeverityBadge from '../components/common/SeverityBadge';

export default function ScanCompare() {
  const [searchParams] = useSearchParams();
  const [scans, setScans] = useState([]);
  const [baseScanId, setBaseScanId] = useState(searchParams.get('base') || '');
  const [targetScanId, setTargetScanId] = useState(searchParams.get('target') || '');

  const [comparison, setComparison] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    const loadScans = async () => {
      try {
        const res = await api.get('/scans');
        if (res.data.success) {
          const list = res.data.scans || [];
          setScans(list);
          if (list.length >= 2 && !baseScanId) {
            setBaseScanId(list[1]._id || list[1].id);
            setTargetScanId(list[0]._id || list[0].id);
          } else if (list.length >= 1 && !baseScanId) {
            setBaseScanId(list[0]._id || list[0].id);
            setTargetScanId(list[0]._id || list[0].id);
          }
        }
      } catch (err) {
        console.error('Failed to load scans:', err);
      }
    };
    loadScans();
  }, []);

  const runComparison = async () => {
    if (!baseScanId || !targetScanId) return;
    setLoading(true);
    setError(null);
    try {
      const res = await api.post('/compare', {
        baseScanId,
        targetScanId
      });
      if (res.data.success) {
        setComparison(res.data.comparison);
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to compare scans.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (baseScanId && targetScanId) {
      runComparison();
    }
  }, [baseScanId, targetScanId]);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8 animate-in fade-in duration-300">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-edge">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-ink font-sans tracking-tight">
            API Scan Comparison
          </h1>
          <p className="text-xs sm:text-sm text-ink-muted mt-1">
            Compare security posture shifts, newly introduced risks, and resolved vulnerabilities across versions
          </p>
        </div>
      </div>

      {/* Selectors Bar */}
      <div className="p-6 bg-white rounded-2xl border border-edge shadow-card grid grid-cols-1 md:grid-cols-2 gap-6 items-center">
        
        {/* Base Scan */}
        <div className="space-y-2">
          <label className="text-xs font-bold text-ink-muted uppercase">Base Scan (Baseline / Previous)</label>
          <select
            value={baseScanId}
            onChange={(e) => setBaseScanId(e.target.value)}
            className="w-full bg-surface-subtle border border-edge rounded-xl p-3 text-xs font-semibold text-ink focus:outline-none focus:ring-2 focus:ring-sentinel-600"
          >
            {scans.map((s) => (
              <option key={s._id || s.id} value={s._id || s.id}>
                {s.apiTitle} ({s.fileName}) • Score: {s.riskScore} • {new Date(s.createdAt).toLocaleDateString()}
              </option>
            ))}
          </select>
        </div>

        {/* Target Scan */}
        <div className="space-y-2">
          <label className="text-xs font-bold text-ink-muted uppercase">Target Scan (Current / Updated)</label>
          <select
            value={targetScanId}
            onChange={(e) => setTargetScanId(e.target.value)}
            className="w-full bg-surface-subtle border border-edge rounded-xl p-3 text-xs font-semibold text-ink focus:outline-none focus:ring-2 focus:ring-sentinel-600"
          >
            {scans.map((s) => (
              <option key={s._id || s.id} value={s._id || s.id}>
                {s.apiTitle} ({s.fileName}) • Score: {s.riskScore} • {new Date(s.createdAt).toLocaleDateString()}
              </option>
            ))}
          </select>
        </div>

      </div>

      {/* Comparison Results */}
      {comparison && (
        <div className="space-y-6">
          
          {/* Delta Banner */}
          <div className="p-6 bg-white rounded-2xl border border-edge shadow-card grid grid-cols-1 sm:grid-cols-3 gap-6 text-center">
            
            <div className="p-4 rounded-xl bg-surface-subtle border border-edge">
              <span className="text-xs font-bold text-ink-muted uppercase">Base Risk Score</span>
              <p className="text-3xl font-extrabold font-mono text-ink mt-1">
                {comparison.base_score}/100
              </p>
              <p className="text-xs text-ink-muted mt-1">{comparison.baseScan?.apiTitle}</p>
            </div>

            <div className={`p-4 rounded-xl border flex flex-col items-center justify-center ${
              comparison.improvement ? 'bg-emerald-50 border-emerald-200 text-emerald-800' : 'bg-red-50 border-red-200 text-red-800'
            }`}>
              <span className="text-xs font-bold uppercase">Risk Delta</span>
              <p className="text-3xl font-extrabold font-mono mt-1">
                {comparison.score_delta > 0 ? `+${comparison.score_delta}` : comparison.score_delta}
              </p>
              <span className="text-xs font-semibold mt-1">
                {comparison.improvement ? 'Security Posture Improved' : (comparison.score_delta === 0 ? 'No Score Change' : 'Risk Elevated')}
              </span>
            </div>

            <div className="p-4 rounded-xl bg-surface-subtle border border-edge">
              <span className="text-xs font-bold text-ink-muted uppercase">Target Risk Score</span>
              <p className="text-3xl font-extrabold font-mono text-ink mt-1">
                {comparison.target_score}/100
              </p>
              <p className="text-xs text-ink-muted mt-1">{comparison.targetScan?.apiTitle}</p>
            </div>

          </div>

          {/* Tri-column diff: Fixed vs New vs Unchanged */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            
            {/* Fixed Findings */}
            <div className="p-5 bg-white rounded-2xl border border-edge shadow-card space-y-3">
              <div className="flex items-center justify-between pb-3 border-b border-edge">
                <span className="text-xs font-bold text-emerald-700 flex items-center gap-1.5 uppercase">
                  <CheckCircle2 className="w-4 h-4" /> Fixed ({comparison.findings_fixed?.length || 0})
                </span>
              </div>
              <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
                {(comparison.findings_fixed || []).length === 0 ? (
                  <p className="text-xs text-ink-muted py-4 text-center">No resolved findings detected.</p>
                ) : (
                  comparison.findings_fixed.map((f, i) => (
                    <div key={i} className="p-2.5 rounded-xl bg-emerald-50/50 border border-emerald-200 space-y-1">
                      <div className="flex items-center gap-1.5">
                        <SeverityBadge severity={f.severity} size="sm" />
                        <span className="font-mono text-[10px] font-bold text-emerald-800">{f.rule_id}</span>
                      </div>
                      <p className="text-xs font-bold text-ink truncate">{f.title}</p>
                      <p className="font-mono text-[10px] text-ink-muted truncate">{f.endpoint}</p>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* New Findings */}
            <div className="p-5 bg-white rounded-2xl border border-edge shadow-card space-y-3">
              <div className="flex items-center justify-between pb-3 border-b border-edge">
                <span className="text-xs font-bold text-red-700 flex items-center gap-1.5 uppercase">
                  <AlertOctagon className="w-4 h-4" /> New Risks ({comparison.findings_new?.length || 0})
                </span>
              </div>
              <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
                {(comparison.findings_new || []).length === 0 ? (
                  <p className="text-xs text-ink-muted py-4 text-center">No new vulnerabilities introduced.</p>
                ) : (
                  comparison.findings_new.map((f, i) => (
                    <div key={i} className="p-2.5 rounded-xl bg-red-50/50 border border-red-200 space-y-1">
                      <div className="flex items-center gap-1.5">
                        <SeverityBadge severity={f.severity} size="sm" />
                        <span className="font-mono text-[10px] font-bold text-red-800">{f.rule_id}</span>
                      </div>
                      <p className="text-xs font-bold text-ink truncate">{f.title}</p>
                      <p className="font-mono text-[10px] text-ink-muted truncate">{f.endpoint}</p>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Unchanged Findings */}
            <div className="p-5 bg-white rounded-2xl border border-edge shadow-card space-y-3">
              <div className="flex items-center justify-between pb-3 border-b border-edge">
                <span className="text-xs font-bold text-ink-muted flex items-center gap-1.5 uppercase">
                  <AlertTriangle className="w-4 h-4" /> Unchanged ({comparison.findings_unchanged?.length || 0})
                </span>
              </div>
              <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
                {(comparison.findings_unchanged || []).length === 0 ? (
                  <p className="text-xs text-ink-muted py-4 text-center">No persistent findings.</p>
                ) : (
                  comparison.findings_unchanged.map((f, i) => (
                    <div key={i} className="p-2.5 rounded-xl bg-surface-subtle border border-edge space-y-1">
                      <div className="flex items-center gap-1.5">
                        <SeverityBadge severity={f.severity} size="sm" />
                        <span className="font-mono text-[10px] font-bold text-ink">{f.rule_id}</span>
                      </div>
                      <p className="text-xs font-bold text-ink truncate">{f.title}</p>
                      <p className="font-mono text-[10px] text-ink-muted truncate">{f.endpoint}</p>
                    </div>
                  ))
                )}
              </div>
            </div>

          </div>

        </div>
      )}

    </div>
  );
}
