import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { History, PlusCircle, Search, Trash2, ArrowRight, Shield, RefreshCw } from 'lucide-react';
import api from '../services/api';
import SeverityBadge from '../components/common/SeverityBadge';

export default function ScanHistory() {
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  const fetchScans = async () => {
    setLoading(true);
    try {
      const res = await api.get('/scans');
      if (res.data.success) {
        setScans(res.data.scans || []);
      }
    } catch (err) {
      console.error('Failed to load scan history:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  const handleDelete = async (id, e) => {
    e.stopPropagation();
    if (window.confirm('Delete this scan history entry?')) {
      try {
        await api.delete(`/scans/${id}`);
        setScans(prev => prev.filter(s => (s._id || s.id) !== id));
      } catch (err) {
        alert('Failed to delete scan.');
      }
    }
  };

  const filteredScans = scans.filter(s =>
    s.apiTitle?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    s.fileName?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6 animate-in fade-in duration-300">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-edge">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-ink font-sans tracking-tight">
            Scan Audit History
          </h1>
          <p className="text-xs sm:text-sm text-ink-muted mt-1">
            Complete historical inventory of analyzed API specifications and posture trends
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={fetchScans}
            className="p-2.5 rounded-xl border border-edge hover:bg-surface-subtle text-ink-muted transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <Link
            to="/scan/new"
            className="inline-flex items-center gap-2 px-4 py-2.5 bg-sentinel-700 hover:bg-sentinel-800 text-white rounded-xl text-xs font-bold shadow-sm transition-all"
          >
            <PlusCircle className="w-4 h-4" /> New Scan
          </Link>
        </div>
      </div>

      {/* Search Bar */}
      <div className="p-4 bg-white rounded-2xl border border-edge shadow-card">
        <div className="relative">
          <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-ink-muted" />
          <input
            type="text"
            placeholder="Filter scans by API title, file name..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-surface-subtle border border-edge rounded-xl pl-10 pr-4 py-2 text-xs text-ink placeholder:text-ink-muted focus:outline-none focus:ring-1 focus:ring-sentinel-600 focus:bg-white"
          />
        </div>
      </div>

      {/* History Table */}
      <div className="bg-white rounded-2xl border border-edge shadow-card overflow-hidden">
        {filteredScans.length === 0 ? (
          <div className="p-12 text-center text-xs text-ink-muted">
            No scan records found. Start your first scan from the button above.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-edge text-ink-muted font-bold uppercase tracking-wider text-[11px] bg-surface-muted">
                  <th className="py-3.5 px-4">API Title</th>
                  <th className="py-3.5 px-4">Format</th>
                  <th className="py-3.5 px-4">Endpoints</th>
                  <th className="py-3.5 px-4">Risk Score</th>
                  <th className="py-3.5 px-4">Severity Breakdown</th>
                  <th className="py-3.5 px-4">Date</th>
                  <th className="py-3.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-edge font-sans">
                {filteredScans.map((scan) => {
                  const sId = scan._id || scan.id;
                  return (
                    <tr
                      key={sId}
                      onClick={() => navigate(`/scan/${sId}`)}
                      className="hover:bg-surface-subtle transition-colors cursor-pointer group"
                    >
                      <td className="py-4 px-4">
                        <p className="font-bold text-ink group-hover:text-sentinel-700 font-sans">{scan.apiTitle}</p>
                        <p className="font-mono text-[11px] text-ink-muted">{scan.fileName}</p>
                      </td>
                      <td className="py-4 px-4">
                        <span className="px-2 py-0.5 rounded bg-surface-subtle border border-edge font-mono text-[10px] font-bold text-ink uppercase">
                          {scan.specFormat || scan.fileType}
                        </span>
                      </td>
                      <td className="py-4 px-4 font-mono font-semibold text-ink">
                        {scan.endpointCount}
                      </td>
                      <td className="py-4 px-4">
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
                      <td className="py-4 px-4">
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
                            <span className="text-[11px] text-emerald-600 font-semibold">Clean</span>
                          )}
                        </div>
                      </td>
                      <td className="py-4 px-4 text-ink-muted text-[11px] whitespace-nowrap">
                        {new Date(scan.createdAt).toLocaleDateString()}
                      </td>
                      <td className="py-4 px-4 text-right">
                        <div className="flex items-center justify-end gap-2" onClick={(e) => e.stopPropagation()}>
                          <Link
                            to={`/scan/${sId}`}
                            className="p-1.5 rounded-lg text-sentinel-700 hover:bg-sentinel-50"
                            title="Open Results"
                          >
                            <ArrowRight className="w-4 h-4" />
                          </Link>
                          <button
                            onClick={(e) => handleDelete(sId, e)}
                            className="p-1.5 rounded-lg text-ink-muted hover:text-red-600 hover:bg-red-50"
                            title="Delete"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
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
