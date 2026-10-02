import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Shield, PlusCircle, AlertOctagon, AlertTriangle, AlertCircle, Info,
  TrendingUp, Activity, FileText, ArrowRight, ExternalLink, RefreshCw, Layers
} from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, PieChart, Pie, Cell } from 'recharts';
import api from '../services/api';
import ScoreGauge from '../components/common/ScoreGauge';
import SeverityBadge from '../components/common/SeverityBadge';

export default function Dashboard() {
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchScans = async () => {
    setLoading(true);
    try {
      const res = await api.get('/scans');
      if (res.data.success) {
        setScans(res.data.scans || []);
      }
    } catch (err) {
      console.error('Failed to load scans:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  // Aggregate metrics
  const totalScans = scans.length;
  const latestScan = scans[0] || null;
  const avgScore = totalScans > 0 ? Math.round(scans.reduce((acc, s) => acc + (s.riskScore || 0), 0) / totalScans) : 0;
  
  const totalFindings = scans.reduce((acc, s) => acc + (s.findingCount || (s.findings?.length || 0)), 0);
  const totalEndpoints = scans.reduce((acc, s) => acc + (s.endpointCount || 0), 0);

  const totalCritical = scans.reduce((acc, s) => acc + (s.severitySummary?.CRITICAL || 0), 0);
  const totalHigh = scans.reduce((acc, s) => acc + (s.severitySummary?.HIGH || 0), 0);
  const totalMedium = scans.reduce((acc, s) => acc + (s.severitySummary?.MEDIUM || 0), 0);
  const totalLow = scans.reduce((acc, s) => acc + ((s.severitySummary?.LOW || 0) + (s.severitySummary?.INFO || 0)), 0);

  // Severity Distribution Chart Data
  const severityData = [
    { name: 'Critical', value: totalCritical, color: '#DC2626' },
    { name: 'High', value: totalHigh, color: '#EA580C' },
    { name: 'Medium', value: totalMedium, color: '#D97706' },
    { name: 'Low/Info', value: totalLow, color: '#2563EB' }
  ];

  // Category distribution from latest scan
  const categoryData = latestScan?.categoryScores
    ? Object.entries(latestScan.categoryScores).map(([cat, score]) => ({
        category: cat.length > 18 ? cat.slice(0, 18) + '...' : cat,
        score: score
      }))
    : [];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8 animate-in fade-in duration-300">
      
      {/* Dashboard Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-edge">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-ink font-sans tracking-tight">
            Security Posture Dashboard
          </h1>
          <p className="text-xs sm:text-sm text-ink-muted mt-1">
            Real-time API posture analytics, risk scoring, and OWASP vulnerability distribution
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={fetchScans}
            className="p-2.5 rounded-xl border border-edge hover:bg-surface-subtle text-ink-muted transition-colors"
            title="Refresh Scan Data"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <Link
            to="/scan/new"
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold text-white bg-sentinel-700 hover:bg-sentinel-800 shadow-sm shadow-sentinel-700/25 transition-all"
          >
            <PlusCircle className="w-4 h-4" />
            New API Scan
          </Link>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 sm:gap-6">
        
        {/* Metric 1: Score Gauge Card */}
        <div className="col-span-2 md:col-span-1 p-5 rounded-2xl bg-white border border-edge shadow-card flex flex-col items-center justify-center text-center">
          <p className="text-xs font-bold text-ink-muted uppercase tracking-wider mb-2">Overall API Risk</p>
          <ScoreGauge score={latestScan ? latestScan.riskScore : 0} riskLevel={latestScan?.riskLevel || 'No Scans'} size={120} />
          <p className="text-[11px] text-ink-muted mt-2">
            {latestScan ? `Latest: ${latestScan.apiTitle}` : 'No active scans'}
          </p>
        </div>

        {/* Metric 2: Total Scans & APIs */}
        <div className="p-5 rounded-2xl bg-white border border-edge shadow-card flex flex-col justify-between">
          <div className="flex items-center justify-between text-ink-muted">
            <span className="text-xs font-bold uppercase tracking-wider">Audited Specs</span>
            <div className="w-7 h-7 rounded-lg bg-sentinel-50 text-sentinel-700 flex items-center justify-center">
              <FileText className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4">
            <p className="text-3xl font-extrabold text-ink font-mono">{totalScans}</p>
            <p className="text-xs text-ink-muted mt-1">{totalEndpoints} total endpoints mapped</p>
          </div>
        </div>

        {/* Metric 3: Critical & High Findings */}
        <div className="p-5 rounded-2xl bg-white border border-edge shadow-card flex flex-col justify-between">
          <div className="flex items-center justify-between text-ink-muted">
            <span className="text-xs font-bold uppercase tracking-wider text-red-700">Urgent Findings</span>
            <div className="w-7 h-7 rounded-lg bg-red-50 text-red-600 flex items-center justify-center">
              <AlertOctagon className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4">
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-red-600 font-mono">{totalCritical}</span>
              <span className="text-xs text-red-700 font-semibold">Critical</span>
              <span className="text-xl font-bold text-orange-600 font-mono ml-2">{totalHigh}</span>
              <span className="text-xs text-orange-700 font-semibold">High</span>
            </div>
            <p className="text-xs text-ink-muted mt-1">Requiring immediate remediation</p>
          </div>
        </div>

        {/* Metric 4: Total Findings */}
        <div className="p-5 rounded-2xl bg-white border border-edge shadow-card flex flex-col justify-between">
          <div className="flex items-center justify-between text-ink-muted">
            <span className="text-xs font-bold uppercase tracking-wider">Total Findings</span>
            <div className="w-7 h-7 rounded-lg bg-sentinel-50 text-sentinel-700 flex items-center justify-center">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4">
            <p className="text-3xl font-extrabold text-ink font-mono">{totalFindings}</p>
            <p className="text-xs text-ink-muted mt-1">{totalMedium} Medium • {totalLow} Low/Info</p>
          </div>
        </div>

      </div>

      {/* Main Charts & Visuals */}
      {totalScans > 0 ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          
          {/* Severity Distribution Pie Chart */}
          <div className="p-6 rounded-2xl bg-white border border-edge shadow-card space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-ink">Severity Breakdown</h3>
              <span className="text-xs text-ink-muted">{totalFindings} findings</span>
            </div>
            <div className="h-56 w-full flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityData}
                    innerRadius={50}
                    outerRadius={75}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#FFFFFF',
                      borderRadius: '0.75rem',
                      border: '1px solid #E4E4E7',
                      fontSize: '12px'
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              {severityData.map((item, idx) => (
                <div key={idx} className="flex items-center gap-2 p-1.5 rounded-lg bg-surface-subtle">
                  <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }}></span>
                  <span className="text-ink font-medium">{item.name}:</span>
                  <span className="font-mono font-bold text-ink ml-auto">{item.value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Risk Categories Bar Chart */}
          <div className="lg:col-span-2 p-6 rounded-2xl bg-white border border-edge shadow-card space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-ink">OWASP Risk by Category</h3>
                <p className="text-xs text-ink-muted">Weighted risk intensity from latest scan</p>
              </div>
              {latestScan && (
                <Link
                  to={`/scan/${latestScan._id || latestScan.id}`}
                  className="text-xs font-semibold text-sentinel-700 hover:text-sentinel-900 flex items-center gap-1"
                >
                  View Scan Results <ArrowRight className="w-3.5 h-3.5" />
                </Link>
              )}
            </div>

            <div className="h-64 w-full">
              {categoryData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={categoryData} layout="vertical" margin={{ top: 5, right: 20, left: 40, bottom: 5 }}>
                    <XAxis type="number" tick={{ fontSize: 11, fill: '#71717A' }} />
                    <YAxis dataKey="category" type="category" tick={{ fontSize: 11, fill: '#18181B' }} width={120} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#FFFFFF',
                        borderRadius: '0.75rem',
                        border: '1px solid #E4E4E7',
                        fontSize: '12px'
                      }}
                    />
                    <Bar dataKey="score" fill="#6D28D9" radius={[0, 6, 6, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex items-center justify-center text-xs text-ink-muted">
                  No categorical risk data recorded.
                </div>
              )}
            </div>
          </div>

        </div>
      ) : null}

      {/* Recent Scans Table */}
      <div className="p-6 rounded-2xl bg-white border border-edge shadow-card space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-ink">Recent API Security Scans</h3>
            <p className="text-xs text-ink-muted">Historical specifications analyzed with API Sentinel</p>
          </div>
          {totalScans > 0 && (
            <Link to="/scans" className="text-xs font-semibold text-sentinel-700 hover:underline">
              View All Scans
            </Link>
          )}
        </div>

        {totalScans === 0 ? (
          <div className="py-12 text-center space-y-4">
            <div className="w-12 h-12 rounded-2xl bg-sentinel-50 text-sentinel-700 mx-auto flex items-center justify-center">
              <Shield className="w-6 h-6" />
            </div>
            <div className="max-w-sm mx-auto">
              <h4 className="text-sm font-bold text-ink">No Scans Yet</h4>
              <p className="text-xs text-ink-muted mt-1">
                Upload your first API specification or run our vulnerable e-commerce demo to discover security risks.
              </p>
            </div>
            <div className="flex items-center justify-center gap-3">
              <Link
                to="/scan/new"
                className="px-4 py-2 bg-sentinel-700 text-white text-xs font-semibold rounded-xl hover:bg-sentinel-800 shadow-sm transition-all"
              >
                Start First Scan
              </Link>
              <button
                onClick={() => navigate('/scan/new?sample=ecommerce_vuln')}
                className="px-4 py-2 bg-sentinel-50 text-sentinel-900 border border-sentinel-200 text-xs font-semibold rounded-xl hover:bg-sentinel-100 transition-all"
              >
                Try Demo API
              </button>
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto -mx-6 px-6">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-edge text-ink-muted font-bold uppercase tracking-wider text-[11px]">
                  <th className="py-3 px-3">API Specification</th>
                  <th className="py-3 px-3">Format</th>
                  <th className="py-3 px-3">Endpoints</th>
                  <th className="py-3 px-3">Risk Score</th>
                  <th className="py-3 px-3">Severity Counts</th>
                  <th className="py-3 px-3">Date</th>
                  <th className="py-3 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-edge">
                {scans.slice(0, 8).map((scan) => {
                  const sId = scan._id || scan.id;
                  return (
                    <tr key={sId} className="hover:bg-surface-subtle transition-colors group">
                      <td className="py-3.5 px-3">
                        <Link to={`/scan/${sId}`} className="font-bold text-ink hover:text-sentinel-700 font-sans block">
                          {scan.apiTitle || scan.fileName}
                        </Link>
                        <span className="text-[11px] text-ink-muted font-mono">{scan.fileName}</span>
                      </td>
                      <td className="py-3.5 px-3">
                        <span className="px-2 py-0.5 rounded bg-surface-subtle border border-edge text-[10px] font-mono uppercase font-bold text-ink">
                          {scan.specFormat || scan.fileType}
                        </span>
                      </td>
                      <td className="py-3.5 px-3 font-mono text-ink">
                        {scan.endpointCount} routes
                      </td>
                      <td className="py-3.5 px-3">
                        <div className="flex items-center gap-2">
                          <span className={`font-mono font-bold text-sm ${
                            scan.riskScore > 60 ? 'text-red-600' : (scan.riskScore > 40 ? 'text-amber-600' : 'text-emerald-600')
                          }`}>
                            {scan.riskScore}/100
                          </span>
                          <span className={`text-[10px] font-semibold px-1.5 py-0.2 rounded border ${
                            scan.riskScore > 60 ? 'bg-red-50 text-red-700 border-red-200' : 'bg-amber-50 text-amber-700 border-amber-200'
                          }`}>
                            {scan.riskLevel}
                          </span>
                        </div>
                      </td>
                      <td className="py-3.5 px-3">
                        <div className="flex items-center gap-1.5">
                          {scan.severitySummary?.CRITICAL > 0 && (
                            <span className="px-1.5 py-0.2 bg-red-100 text-red-800 text-[10px] font-mono font-bold rounded">
                              {scan.severitySummary.CRITICAL}C
                            </span>
                          )}
                          {scan.severitySummary?.HIGH > 0 && (
                            <span className="px-1.5 py-0.2 bg-orange-100 text-orange-800 text-[10px] font-mono font-bold rounded">
                              {scan.severitySummary.HIGH}H
                            </span>
                          )}
                          {scan.severitySummary?.MEDIUM > 0 && (
                            <span className="px-1.5 py-0.2 bg-amber-100 text-amber-800 text-[10px] font-mono font-bold rounded">
                              {scan.severitySummary.MEDIUM}M
                            </span>
                          )}
                          {(!scan.severitySummary?.CRITICAL && !scan.severitySummary?.HIGH && !scan.severitySummary?.MEDIUM) && (
                            <span className="text-[11px] text-emerald-600 font-semibold">Clean Posture</span>
                          )}
                        </div>
                      </td>
                      <td className="py-3.5 px-3 text-ink-muted text-[11px] whitespace-nowrap">
                        {new Date(scan.createdAt).toLocaleDateString()}
                      </td>
                      <td className="py-3.5 px-3 text-right">
                        <Link
                          to={`/scan/${sId}`}
                          className="inline-flex items-center gap-1 text-xs font-semibold text-sentinel-700 hover:text-sentinel-900 group-hover:underline"
                        >
                          View Results <ArrowRight className="w-3 h-3" />
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

    </div>
  );
}
