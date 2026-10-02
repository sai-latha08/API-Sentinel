import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import {
  Shield, AlertOctagon, AlertTriangle, AlertCircle, Info, Sparkles,
  Download, GitCompare, ArrowLeft, Search, Filter, Layers, Code2,
  ListFilter, FileText, Bot, ExternalLink, ChevronRight, CheckCircle2,
  Share2, RefreshCw, Trash2
} from 'lucide-react';
import api from '../services/api';
import ScoreGauge from '../components/common/ScoreGauge';
import SeverityBadge from '../components/common/SeverityBadge';
import AttackSurfaceGraph from '../components/scan/AttackSurfaceGraph';
import FindingDrawer from '../components/scan/FindingDrawer';
import AskSentinelModal from '../components/scan/AskSentinelModal';

export default function ScanResults() {
  const { id } = useParams();
  const navigate = useNavigate();

  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Active Tab: 'overview', 'graph', 'findings', 'endpoints', 'roadmap', 'ai'
  const [activeTab, setActiveTab] = useState('findings');

  // Finding Drawer state
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  // Filters for Findings Explorer
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [selectedMethod, setSelectedMethod] = useState('ALL');

  // Endpoint explorer search
  const [endpointSearch, setEndpointSearch] = useState('');
  const [selectedEndpointMethod, setSelectedEndpointMethod] = useState('ALL');

  const fetchScan = async () => {
    setLoading(true);
    try {
      const res = await api.get(`/scans/${id}`);
      if (res.data.success) {
        setScan(res.data.scan);
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to retrieve scan data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScan();
  }, [id]);

  const handleDelete = async () => {
    if (window.confirm('Are you sure you want to delete this scan record?')) {
      try {
        await api.delete(`/scans/${id}`);
        navigate('/dashboard');
      } catch (err) {
        alert('Failed to delete scan.');
      }
    }
  };

  const handleOpenFinding = (f) => {
    setSelectedFinding(f);
    setDrawerOpen(true);
  };

  const handleAskAIFromFinding = (f) => {
    setDrawerOpen(false);
    setActiveTab('ai');
  };

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 py-20 text-center space-y-4">
        <div className="w-10 h-10 border-4 border-sentinel-700 border-t-transparent rounded-full animate-spin mx-auto"></div>
        <p className="text-xs font-semibold text-ink-muted">Loading API security analysis results...</p>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="max-w-xl mx-auto px-4 py-20 text-center space-y-4">
        <div className="w-12 h-12 rounded-2xl bg-red-50 text-red-600 flex items-center justify-center mx-auto">
          <AlertCircle className="w-6 h-6" />
        </div>
        <h2 className="text-lg font-bold text-ink">Scan Not Found</h2>
        <p className="text-xs text-ink-muted">{error || 'This scan record does not exist or has been removed.'}</p>
        <Link to="/dashboard" className="inline-flex items-center gap-1.5 px-4 py-2 bg-sentinel-700 text-white rounded-xl text-xs font-semibold">
          <ArrowLeft className="w-4 h-4" /> Return to Dashboard
        </Link>
      </div>
    );
  }

  const findings = scan.findings || [];
  const endpoints = scan.endpoints || [];
  const sev = scan.severitySummary || {};

  // Filter findings
  const filteredFindings = findings.filter((f) => {
    const matchesSearch =
      f.title?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.endpoint?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.rule_id?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.category?.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesSeverity = selectedSeverity === 'ALL' || f.severity === selectedSeverity;
    const matchesCategory = selectedCategory === 'ALL' || f.category === selectedCategory;
    const matchesMethod = selectedMethod === 'ALL' || f.method === selectedMethod;

    return matchesSearch && matchesSeverity && matchesCategory && matchesMethod;
  });

  // Filter endpoints
  const filteredEndpoints = endpoints.filter((ep) => {
    const matchesSearch =
      ep.path?.toLowerCase().includes(endpointSearch.toLowerCase()) ||
      ep.summary?.toLowerCase().includes(endpointSearch.toLowerCase());
    const matchesMethod = selectedEndpointMethod === 'ALL' || ep.method === selectedEndpointMethod;
    return matchesSearch && matchesMethod;
  });

  // Categories list
  const categories = Array.from(new Set(findings.map((f) => f.category))).filter(Boolean);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6 animate-in fade-in duration-300">
      
      {/* Breadcrumb & Navigation Bar */}
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2 text-xs text-ink-muted">
          <Link to="/dashboard" className="hover:text-sentinel-700 flex items-center gap-1">
            <ArrowLeft className="w-3.5 h-3.5" /> Dashboard
          </Link>
          <span>/</span>
          <span className="font-semibold text-ink truncate max-w-xs">{scan.apiTitle}</span>
        </div>

        <div className="flex items-center gap-2">
          <Link
            to={`/reports/${scan._id || scan.id}`}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-edge hover:bg-surface-subtle text-xs font-semibold text-ink transition-colors"
          >
            <FileText className="w-3.5 h-3.5 text-sentinel-600" />
            Security Report (PDF)
          </Link>
          <Link
            to={`/compare?base=${scan._id || scan.id}`}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-edge hover:bg-surface-subtle text-xs font-semibold text-ink transition-colors"
          >
            <GitCompare className="w-3.5 h-3.5 text-sentinel-600" />
            Compare
          </Link>
          <button
            onClick={handleDelete}
            className="p-1.5 rounded-lg border border-edge hover:bg-red-50 text-ink-muted hover:text-red-600 transition-colors"
            title="Delete Scan"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Top Banner: Score & Executive Snapshot */}
      <div className="p-6 rounded-2xl bg-white border border-edge shadow-card">
        <div className="flex flex-col lg:flex-row items-center justify-between gap-8">
          
          {/* Left: Score Gauge */}
          <div className="flex flex-col sm:flex-row items-center gap-6 text-center sm:text-left">
            <ScoreGauge score={scan.riskScore} riskLevel={scan.riskLevel} size={130} />
            
            <div className="space-y-2">
              <div className="flex flex-wrap items-center justify-center sm:justify-start gap-2">
                <span className="text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded bg-surface-subtle border border-edge text-ink">
                  {scan.specFormat}
                </span>
                <span className="text-xs text-ink-muted">v{scan.apiVersion}</span>
                <span className="text-xs text-ink-muted">•</span>
                <span className="text-xs text-ink-muted">{scan.endpointCount} endpoints</span>
              </div>
              <h1 className="text-xl sm:text-2xl font-extrabold text-ink tracking-tight font-sans">
                {scan.apiTitle}
              </h1>
              <p className="text-xs text-ink-muted font-mono">{scan.fileName}</p>
            </div>
          </div>

          {/* Right: Severity Summary Pills */}
          <div className="flex flex-wrap items-center justify-center gap-3">
            <div className="px-4 py-3 rounded-xl bg-red-50/70 border border-red-200 text-center min-w-[85px]">
              <p className="text-xl font-extrabold text-red-600 font-mono leading-tight">{sev.CRITICAL || 0}</p>
              <p className="text-[10px] font-bold text-red-700 uppercase tracking-wider mt-0.5">Critical</p>
            </div>

            <div className="px-4 py-3 rounded-xl bg-orange-50/70 border border-orange-200 text-center min-w-[85px]">
              <p className="text-xl font-extrabold text-orange-600 font-mono leading-tight">{sev.HIGH || 0}</p>
              <p className="text-[10px] font-bold text-orange-700 uppercase tracking-wider mt-0.5">High</p>
            </div>

            <div className="px-4 py-3 rounded-xl bg-amber-50/70 border border-amber-200 text-center min-w-[85px]">
              <p className="text-xl font-extrabold text-amber-600 font-mono leading-tight">{sev.MEDIUM || 0}</p>
              <p className="text-[10px] font-bold text-amber-700 uppercase tracking-wider mt-0.5">Medium</p>
            </div>

            <div className="px-4 py-3 rounded-xl bg-blue-50/70 border border-blue-200 text-center min-w-[85px]">
              <p className="text-xl font-extrabold text-blue-600 font-mono leading-tight">{sev.LOW || 0}</p>
              <p className="text-[10px] font-bold text-blue-700 uppercase tracking-wider mt-0.5">Low</p>
            </div>

            <div className="px-4 py-3 rounded-xl bg-zinc-100 border border-zinc-200 text-center min-w-[85px]">
              <p className="text-xl font-extrabold text-zinc-700 font-mono leading-tight">{sev.INFO || 0}</p>
              <p className="text-[10px] font-bold text-zinc-600 uppercase tracking-wider mt-0.5">Info</p>
            </div>
          </div>

        </div>
      </div>

      {/* Main Tabs Navigation */}
      <div className="flex border-b border-edge overflow-x-auto no-scrollbar gap-2 bg-white px-2 rounded-xl shadow-subtle">
        {[
          { id: 'findings', label: 'Security Findings', count: findings.length, icon: AlertTriangle },
          { id: 'graph', label: 'Attack Surface Graph', icon: Layers },
          { id: 'endpoints', label: 'Endpoint Explorer', count: endpoints.length, icon: ListFilter },
          { id: 'roadmap', label: 'Remediation Roadmap', icon: Code2 },
          { id: 'overview', label: 'Score Breakdown & Summary', icon: Shield },
          { id: 'ai', label: 'Ask Sentinel AI', icon: Sparkles, highlight: true }
        ].map((tab) => {
          const Icon = tab.icon;
          const active = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`py-3 px-4 text-xs font-bold transition-all border-b-2 whitespace-nowrap flex items-center gap-2 ${
                active
                  ? 'border-sentinel-700 text-sentinel-800 bg-sentinel-50/50'
                  : 'border-transparent text-ink-muted hover:text-ink'
              }`}
            >
              <Icon className={`w-4 h-4 ${active || tab.highlight ? 'text-sentinel-700' : 'text-ink-muted'}`} />
              {tab.label}
              {tab.count !== undefined && (
                <span className={`px-1.5 py-0.2 rounded-full text-[10px] font-mono ${
                  active ? 'bg-sentinel-200 text-sentinel-900' : 'bg-surface-subtle text-ink-muted'
                }`}>
                  {tab.count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Tab 1: Findings Explorer */}
      {activeTab === 'findings' && (
        <div className="space-y-4">
          
          {/* Filter Bar */}
          <div className="p-4 bg-white rounded-2xl border border-edge shadow-card flex flex-col md:flex-row items-center gap-3">
            
            {/* Search input */}
            <div className="relative flex-1 w-full">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-ink-muted" />
              <input
                type="text"
                placeholder="Search rule ID, endpoint path, title, or category..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-surface-subtle border border-edge rounded-xl pl-9 pr-4 py-2 text-xs text-ink placeholder:text-ink-muted focus:outline-none focus:ring-1 focus:ring-sentinel-600 focus:bg-white"
              />
            </div>

            {/* Severity Filter */}
            <div className="flex items-center gap-2 w-full md:w-auto overflow-x-auto">
              <select
                value={selectedSeverity}
                onChange={(e) => setSelectedSeverity(e.target.value)}
                className="text-xs bg-surface-subtle border border-edge rounded-xl px-3 py-2 text-ink font-semibold focus:outline-none focus:ring-1 focus:ring-sentinel-600"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
                <option value="INFO">Info</option>
              </select>

              {/* Category Filter */}
              <select
                value={selectedCategory}
                onChange={(e) => setSelectedCategory(e.target.value)}
                className="text-xs bg-surface-subtle border border-edge rounded-xl px-3 py-2 text-ink font-semibold focus:outline-none focus:ring-1 focus:ring-sentinel-600"
              >
                <option value="ALL">All Categories</option>
                {categories.map((cat) => (
                  <option key={cat} value={cat}>{cat}</option>
                ))}
              </select>

              {/* Method Filter */}
              <select
                value={selectedMethod}
                onChange={(e) => setSelectedMethod(e.target.value)}
                className="text-xs bg-surface-subtle border border-edge rounded-xl px-3 py-2 text-ink font-semibold focus:outline-none focus:ring-1 focus:ring-sentinel-600"
              >
                <option value="ALL">All Methods</option>
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="PATCH">PATCH</option>
                <option value="DELETE">DELETE</option>
              </select>
            </div>

          </div>

          {/* Findings List */}
          <div className="bg-white rounded-2xl border border-edge shadow-card overflow-hidden">
            {filteredFindings.length === 0 ? (
              <div className="p-12 text-center text-xs text-ink-muted">
                No security findings match your current filters.
              </div>
            ) : (
              <div className="divide-y divide-edge">
                {filteredFindings.map((finding) => (
                  <div
                    key={finding.id || finding.rule_id}
                    onClick={() => handleOpenFinding(finding)}
                    className="p-4 hover:bg-sentinel-50/40 transition-colors cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-4 group"
                  >
                    <div className="space-y-1.5 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={finding.severity} size="sm" />
                        <span className="font-mono text-[11px] font-bold text-sentinel-900 bg-sentinel-50 border border-sentinel-200 px-1.5 py-0.2 rounded">
                          {finding.rule_id}
                        </span>
                        <span className="text-xs text-ink-muted">{finding.category}</span>
                      </div>

                      <h3 className="text-sm font-bold text-ink group-hover:text-sentinel-800 transition-colors">
                        {finding.title}
                      </h3>

                      <div className="flex items-center gap-2 text-xs">
                        <span className="font-mono font-bold px-1.5 py-0.2 bg-surface-subtle border border-edge rounded text-[10px] text-ink">
                          {finding.method}
                        </span>
                        <span className="font-mono text-sentinel-950 truncate max-w-md font-semibold">
                          {finding.endpoint}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center gap-3 self-end sm:self-center">
                      <span className="text-[11px] text-ink-muted hidden md:inline">
                        Confidence: <strong className="text-ink">{Math.round((finding.confidence || 0.85) * 100)}%</strong>
                      </span>
                      <button className="p-2 rounded-xl bg-surface-subtle group-hover:bg-sentinel-700 group-hover:text-white transition-all text-ink-muted">
                        <ChevronRight className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

        </div>
      )}

      {/* Tab 2: Attack Surface Graph */}
      {activeTab === 'graph' && (
        <div className="space-y-4">
          <div className="p-4 bg-white rounded-2xl border border-edge shadow-card flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-ink">Attack Surface Topology Graph</h3>
              <p className="text-xs text-ink-muted">
                Visual relationship mapping between API Root, Authentication Schemes, Endpoints, and Threats
              </p>
            </div>
            <span className="text-xs text-sentinel-700 font-semibold bg-sentinel-50 border border-sentinel-200 px-2.5 py-1 rounded-lg">
              React Flow Engine
            </span>
          </div>

          <AttackSurfaceGraph graphData={scan.attackSurface} />
        </div>
      )}

      {/* Tab 3: Endpoint Explorer */}
      {activeTab === 'endpoints' && (
        <div className="space-y-4">
          
          <div className="p-4 bg-white rounded-2xl border border-edge shadow-card flex flex-col sm:flex-row items-center gap-3">
            <div className="relative flex-1 w-full">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-ink-muted" />
              <input
                type="text"
                placeholder="Search endpoints by path or summary..."
                value={endpointSearch}
                onChange={(e) => setEndpointSearch(e.target.value)}
                className="w-full bg-surface-subtle border border-edge rounded-xl pl-9 pr-4 py-2 text-xs text-ink placeholder:text-ink-muted focus:outline-none focus:ring-1 focus:ring-sentinel-600 focus:bg-white"
              />
            </div>
            <select
              value={selectedEndpointMethod}
              onChange={(e) => setSelectedEndpointMethod(e.target.value)}
              className="text-xs bg-surface-subtle border border-edge rounded-xl px-3 py-2 text-ink font-semibold focus:outline-none focus:ring-1 focus:ring-sentinel-600 w-full sm:w-auto"
            >
              <option value="ALL">All Methods</option>
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="PATCH">PATCH</option>
              <option value="DELETE">DELETE</option>
            </select>
          </div>

          <div className="bg-white rounded-2xl border border-edge shadow-card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-edge text-ink-muted font-bold uppercase tracking-wider text-[11px] bg-surface-muted">
                    <th className="py-3 px-4">Method</th>
                    <th className="py-3 px-4">Endpoint Path</th>
                    <th className="py-3 px-4">Authentication</th>
                    <th className="py-3 px-4">Parameters</th>
                    <th className="py-3 px-4">Sensitivity</th>
                    <th className="py-3 px-4">Risk Rating</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-edge font-sans">
                  {filteredEndpoints.map((ep) => (
                    <tr key={ep.id} className="hover:bg-surface-subtle transition-colors">
                      <td className="py-3.5 px-4 font-mono">
                        <span className={`px-2 py-0.5 rounded text-[11px] font-bold border ${
                          ep.method === 'GET' ? 'bg-blue-50 text-blue-700 border-blue-200' :
                          ep.method === 'POST' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' :
                          ep.method === 'DELETE' ? 'bg-red-50 text-red-700 border-red-200' : 'bg-amber-50 text-amber-700 border-amber-200'
                        }`}>
                          {ep.method}
                        </span>
                      </td>
                      <td className="py-3.5 px-4">
                        <p className="font-mono font-semibold text-ink break-all">{ep.path}</p>
                        {ep.summary && <p className="text-[11px] text-ink-muted mt-0.5">{ep.summary}</p>}
                      </td>
                      <td className="py-3.5 px-4">
                        {ep.is_authenticated ? (
                          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-700 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded">
                            <CheckCircle2 className="w-3 h-3" /> Declared
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-zinc-600 bg-zinc-100 border border-zinc-200 px-2 py-0.5 rounded">
                            Unauthenticated
                          </span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 text-ink-muted">
                        {ep.parameters?.length || 0} param{ep.parameters?.length === 1 ? '' : 's'}
                      </td>
                      <td className="py-3.5 px-4">
                        <div className="flex items-center gap-1.5">
                          <div className="w-16 bg-edge rounded-full h-1.5 overflow-hidden">
                            <div
                              className="bg-sentinel-700 h-1.5 rounded-full"
                              style={{ width: `${(ep.sensitivity_score || 0.2) * 100}%` }}
                            ></div>
                          </div>
                          <span className="font-mono text-[11px] text-ink-muted">
                            {Math.round((ep.sensitivity_score || 0.2) * 100)}%
                          </span>
                        </div>
                      </td>
                      <td className="py-3.5 px-4">
                        <SeverityBadge severity={ep.risk_level} size="sm" />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

        </div>
      )}

      {/* Tab 4: Remediation Roadmap */}
      {activeTab === 'roadmap' && (
        <div className="space-y-4">
          <div className="p-6 rounded-2xl bg-white border border-edge shadow-card space-y-2">
            <h3 className="text-sm font-bold text-ink">Prioritized Action Checklist</h3>
            <p className="text-xs text-ink-muted">
              Engineering recommendations ordered by exploitability impact to maximize security posture improvements.
            </p>
          </div>

          <div className="space-y-4">
            {(scan.recommendations || []).map((rec, idx) => (
              <div key={idx} className="p-6 rounded-2xl bg-white border border-edge shadow-card space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-edge">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={rec.severity} size="sm" />
                    <span className="font-mono text-xs font-bold text-sentinel-800 bg-sentinel-50 border border-sentinel-200 px-2 py-0.5 rounded">
                      {rec.ruleId}
                    </span>
                    <h4 className="text-sm font-bold text-ink">{rec.title}</h4>
                  </div>
                  <span className="text-xs text-ink-muted font-medium">
                    Affects {rec.affectedCount} endpoint{rec.affectedCount > 1 ? 's' : ''}
                  </span>
                </div>

                <p className="text-xs text-ink leading-relaxed">{rec.action}</p>

                {rec.codeExample && (
                  <div className="rounded-xl bg-zinc-900 text-zinc-100 p-4 font-mono text-xs overflow-x-auto border border-zinc-800">
                    <pre className="text-[11px] leading-relaxed">{rec.codeExample}</pre>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 5: Overview & Score Breakdown */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          
          {/* Executive Summary Card */}
          <div className="p-6 rounded-2xl bg-white border border-edge shadow-card space-y-4">
            <h3 className="text-sm font-bold text-ink flex items-center gap-2">
              <FileText className="w-4 h-4 text-sentinel-700" />
              Executive AI Security Assessment
            </h3>
            <div className="text-xs text-ink leading-relaxed whitespace-pre-line bg-surface-subtle p-5 rounded-xl border border-edge">
              {scan.executiveSummary}
            </div>
          </div>

          {/* Mathematical Multi-factor Score Breakdown */}
          {scan.scoreBreakdown && (
            <div className="p-6 rounded-2xl bg-white border border-edge shadow-card space-y-4">
              <h3 className="text-sm font-bold text-ink">Transparent Risk Calculation Factors</h3>
              <p className="text-xs text-ink-muted">
                Mathematical weights computed via OWASP Multi-Factor Risk Rating Methodology
              </p>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="p-4 rounded-xl bg-surface-subtle border border-edge text-center">
                  <span className="text-[11px] font-bold text-ink-muted uppercase">Base Score</span>
                  <p className="text-2xl font-bold font-mono text-ink mt-1">{scan.scoreBreakdown.base_score}</p>
                </div>
                <div className="p-4 rounded-xl bg-red-50 border border-red-200 text-center">
                  <span className="text-[11px] font-bold text-red-700 uppercase">Critical Penalty</span>
                  <p className="text-2xl font-bold font-mono text-red-600 mt-1">-{scan.scoreBreakdown.critical_penalty}</p>
                </div>
                <div className="p-4 rounded-xl bg-orange-50 border border-orange-200 text-center">
                  <span className="text-[11px] font-bold text-orange-700 uppercase">High Penalty</span>
                  <p className="text-2xl font-bold font-mono text-orange-600 mt-1">-{scan.scoreBreakdown.high_penalty}</p>
                </div>
                <div className="p-4 rounded-xl bg-sentinel-50 border border-sentinel-200 text-center">
                  <span className="text-[11px] font-bold text-sentinel-800 uppercase">Asset Multiplier</span>
                  <p className="text-2xl font-bold font-mono text-sentinel-900 mt-1">{scan.scoreBreakdown.sensitivity_multiplier}x</p>
                </div>
              </div>

              {scan.scoreBreakdown.factors && scan.scoreBreakdown.factors.length > 0 && (
                <div className="mt-4 border border-edge rounded-xl overflow-hidden">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead className="bg-surface-muted text-ink-muted font-bold text-[11px]">
                      <tr>
                        <th className="py-2.5 px-3">Factor</th>
                        <th className="py-2.5 px-3">Impact</th>
                        <th className="py-2.5 px-3">Description</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-edge font-sans">
                      {scan.scoreBreakdown.factors.map((f, fi) => (
                        <tr key={fi}>
                          <td className="py-2.5 px-3 font-bold text-ink">{f.name}</td>
                          <td className="py-2.5 px-3 font-mono font-semibold">{f.points}</td>
                          <td className="py-2.5 px-3 text-ink-muted">{f.description}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

        </div>
      )}

      {/* Tab 6: Ask Sentinel AI Assistant */}
      {activeTab === 'ai' && (
        <div className="space-y-4">
          <AskSentinelModal scan={scan} />
        </div>
      )}

      {/* Slide-out Finding Details Drawer */}
      <FindingDrawer
        finding={selectedFinding}
        isOpen={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        onAskAI={handleAskAIFromFinding}
        scanId={scan._id || scan.id}
      />

    </div>
  );
}
