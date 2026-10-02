import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  Shield, Printer, ArrowLeft, Download, FileText, CheckCircle2,
  AlertOctagon, AlertTriangle, AlertCircle, Info, Lock
} from 'lucide-react';
import api from '../services/api';
import SeverityBadge from '../components/common/SeverityBadge';

export default function SecurityReport() {
  const { id } = useParams();
  const [reportData, setReportData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchReport = async () => {
      try {
        const res = await api.get(`/reports/${id}`);
        if (res.data.success) {
          setReportData(res.data.report);
        }
      } catch (err) {
        console.error('Failed to load report:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchReport();
  }, [id]);

  const handlePrint = () => {
    window.print();
  };

  if (loading) {
    return (
      <div className="max-w-4xl mx-auto py-20 text-center space-y-4">
        <div className="w-10 h-10 border-4 border-sentinel-700 border-t-transparent rounded-full animate-spin mx-auto"></div>
        <p className="text-xs text-ink-muted">Generating formal security report...</p>
      </div>
    );
  }

  if (!reportData) {
    return (
      <div className="max-w-xl mx-auto py-20 text-center space-y-4">
        <p className="text-sm font-bold text-ink">Report not found.</p>
        <Link to="/dashboard" className="text-xs text-sentinel-700 font-semibold underline">Return to Dashboard</Link>
      </div>
    );
  }

  const { meta, api: apiMeta, securityScore, executiveSummary, criticalFindings, highFindings, recommendations } = reportData;

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      
      {/* Top Action Bar (hidden on print) */}
      <div className="no-print flex items-center justify-between pb-4 border-b border-edge">
        <Link to={`/scan/${id}`} className="inline-flex items-center gap-1.5 text-xs text-ink-muted hover:text-ink font-semibold">
          <ArrowLeft className="w-4 h-4" /> Back to Interactive Scan
        </Link>
        <button
          onClick={handlePrint}
          className="inline-flex items-center gap-2 px-4 py-2 bg-sentinel-700 hover:bg-sentinel-800 text-white rounded-xl text-xs font-bold shadow-sm transition-all"
        >
          <Printer className="w-4 h-4" /> Print / Save as PDF
        </button>
      </div>

      {/* Formal Printable Document Card */}
      <div className="bg-white p-8 sm:p-12 rounded-2xl border border-edge shadow-lg space-y-8 font-sans print:shadow-none print:border-none print:p-0">
        
        {/* Document Header */}
        <div className="flex items-start justify-between pb-6 border-b-2 border-sentinel-800 gap-6">
          <div className="space-y-1">
            <div className="flex items-center gap-2.5">
              <div className="w-9 h-9 rounded-xl bg-sentinel-800 text-white flex items-center justify-center">
                <Shield className="w-5 h-5" />
              </div>
              <span className="text-xl font-extrabold text-sentinel-950 font-sans tracking-tight">API SENTINEL</span>
            </div>
            <p className="text-xs text-ink-muted uppercase font-bold tracking-wider mt-1">Enterprise API Security Posture Audit</p>
          </div>

          <div className="text-right text-xs space-y-0.5">
            <p className="font-mono font-bold text-ink">{meta.reportId}</p>
            <p className="text-ink-muted">Scan Date: {new Date(meta.scanDate).toLocaleDateString()}</p>
            <p className="text-sentinel-700 font-semibold font-mono text-[11px]">CONFIDENTIAL SECURITY AUDIT</p>
          </div>
        </div>

        {/* Executive Summary Section */}
        <section className="space-y-3">
          <h2 className="text-base font-extrabold text-ink uppercase tracking-wide border-b border-edge pb-1">
            1. Executive Summary & Security Posture
          </h2>
          <div className="p-5 rounded-xl bg-surface-subtle border border-edge text-xs leading-relaxed text-ink whitespace-pre-line">
            {executiveSummary}
          </div>
        </section>

        {/* API Specification Overview & Score */}
        <section className="space-y-3">
          <h2 className="text-base font-extrabold text-ink uppercase tracking-wide border-b border-edge pb-1">
            2. API Asset Metrics & Security Score
          </h2>
          
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            
            <div className="p-4 rounded-xl border border-edge bg-surface-muted text-center flex flex-col justify-center">
              <span className="text-[11px] font-bold text-ink-muted uppercase">Calculated Risk Score</span>
              <p className="text-3xl font-extrabold font-mono text-ink mt-1">
                {securityScore.score}/100
              </p>
              <span className="text-xs font-bold text-sentinel-800 mt-1 uppercase">
                {securityScore.level}
              </span>
            </div>

            <div className="p-4 rounded-xl border border-edge bg-surface-muted space-y-1.5 text-xs">
              <p className="font-bold text-ink-muted uppercase text-[10px]">Specification Details</p>
              <p><strong className="text-ink">API Title:</strong> {apiMeta.title}</p>
              <p><strong className="text-ink">Version:</strong> {apiMeta.version}</p>
              <p><strong className="text-ink">File:</strong> {apiMeta.fileName}</p>
            </div>

            <div className="p-4 rounded-xl border border-edge bg-surface-muted space-y-1.5 text-xs">
              <p className="font-bold text-ink-muted uppercase text-[10px]">Attack Surface Coverage</p>
              <p><strong className="text-ink">Total Endpoints:</strong> {apiMeta.endpointCount}</p>
              <p><strong className="text-ink">Critical Findings:</strong> {securityScore.severitySummary?.CRITICAL || 0}</p>
              <p><strong className="text-ink">High Findings:</strong> {securityScore.severitySummary?.HIGH || 0}</p>
            </div>

          </div>
        </section>

        {/* Urgent Findings Table */}
        <section className="space-y-3">
          <h2 className="text-base font-extrabold text-ink uppercase tracking-wide border-b border-edge pb-1">
            3. High-Priority Vulnerability Findings
          </h2>

          <div className="border border-edge rounded-xl overflow-hidden">
            <table className="w-full text-left text-xs border-collapse">
              <thead className="bg-surface-muted text-ink-muted font-bold text-[11px]">
                <tr>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Rule ID</th>
                  <th className="py-2.5 px-3">Vulnerability Title</th>
                  <th className="py-2.5 px-3">Affected Route</th>
                  <th className="py-2.5 px-3">OWASP Category</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-edge font-sans">
                {[...(criticalFindings || []), ...(highFindings || [])].map((f, idx) => (
                  <tr key={idx}>
                    <td className="py-2.5 px-3">
                      <SeverityBadge severity={f.severity} size="sm" />
                    </td>
                    <td className="py-2.5 px-3 font-mono font-bold text-sentinel-900">{f.rule_id}</td>
                    <td className="py-2.5 px-3 font-bold text-ink">{f.title}</td>
                    <td className="py-2.5 px-3 font-mono text-ink text-[11px]">{f.method} {f.endpoint}</td>
                    <td className="py-2.5 px-3 text-ink-muted">{f.owasp_category || f.category}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Prioritized Remediation Roadmap */}
        <section className="space-y-3">
          <h2 className="text-base font-extrabold text-ink uppercase tracking-wide border-b border-edge pb-1">
            4. Strategic Remediation Roadmap
          </h2>
          <div className="space-y-3">
            {(recommendations || []).slice(0, 5).map((rec, idx) => (
              <div key={idx} className="p-4 rounded-xl border border-edge bg-surface-subtle space-y-1.5 text-xs">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-sentinel-900 font-mono">[{rec.ruleId}] {rec.title}</span>
                  <span className="text-[10px] bg-white px-2 py-0.5 border rounded font-semibold text-ink-muted">
                    {rec.severity}
                  </span>
                </div>
                <p className="text-ink leading-relaxed">{rec.action}</p>
              </div>
            ))}
          </div>
        </section>

        {/* Methodology Footer */}
        <div className="pt-6 border-t border-edge text-center text-[11px] text-ink-muted space-y-1">
          <p>Generated by API Sentinel • Built on OWASP API Security Top 10 (2023) Standards</p>
          <p>This report contains static security posture observations for development and security assessment.</p>
        </div>

      </div>
    </div>
  );
}
