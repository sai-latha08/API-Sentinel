import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  UploadCloud, FileCode, Sparkles, AlertCircle, CheckCircle2, Shield,
  ArrowRight, FileText, Code2, Layers, RefreshCw, Loader2
} from 'lucide-react';
import api from '../services/api';

export default function NewScan() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const [activeTab, setActiveTab] = useState('upload'); // 'upload', 'paste', 'samples'
  const [file, setFile] = useState(null);
  const [rawContent, setRawContent] = useState('');
  const [fileName, setFileName] = useState('pasted_spec.json');
  const [samples, setSamples] = useState([]);
  const [selectedSample, setSelectedSample] = useState(null);

  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [error, setError] = useState(null);

  const scanSteps = [
    'Validating specification format & schema syntax...',
    'Parsing endpoints, routes, parameters & methods...',
    'Analyzing authentication schemes & role scopes...',
    'Detecting potential BOLA & BFLA authorization patterns...',
    'Inspecting request/response schemas for sensitive data...',
    'Evaluating rate limiting, anti-abuse, and SSRF parameters...',
    'Calculating multi-factor risk score & building attack surface graph...'
  ];

  // Load sample specs
  useEffect(() => {
    const loadSamples = async () => {
      try {
        const res = await api.get('/scans/samples');
        if (res.data.success) {
          setSamples(res.data.samples || []);
          
          // Auto-select if requested via URL param ?sample=ecommerce_vuln
          const sampleKey = searchParams.get('sample');
          if (sampleKey) {
            const found = res.data.samples.find(s => s.id === sampleKey);
            if (found) {
              setSelectedSample(found);
              setActiveTab('samples');
            }
          }
        }
      } catch (err) {
        console.error('Failed to load sample specifications:', err);
      }
    };
    loadSamples();
  }, [searchParams]);

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
      setError(null);
    }
  };

  const executeScan = async () => {
    setError(null);
    setIsScanning(true);
    setScanStep(0);

    // Progress animation interval
    const stepInterval = setInterval(() => {
      setScanStep(prev => (prev < scanSteps.length - 1 ? prev + 1 : prev));
    }, 450);

    try {
      let response;

      if (activeTab === 'upload') {
        if (!file) {
          throw new Error('Please select an OpenAPI, Swagger, or Postman file to upload.');
        }
        const formData = new FormData();
        formData.append('specFile', file);
        formData.append('projectId', 'proj_default');

        response = await api.post('/scans/upload', formData, {
          headers: { 'Content-Type': 'multipart/form-data' }
        });
      } else if (activeTab === 'paste') {
        if (!rawContent.trim()) {
          throw new Error('Please paste your specification content into the editor.');
        }
        const fType = rawContent.trim().startsWith('{') || rawContent.trim().startsWith('[') ? 'json' : 'yaml';
        response = await api.post('/scans/raw', {
          specContent: rawContent,
          fileName: fileName || 'pasted_spec.json',
          fileType: fType,
          projectId: 'proj_default'
        });
      } else if (activeTab === 'samples') {
        if (!selectedSample) {
          throw new Error('Please select a sample specification to scan.');
        }
        response = await api.post('/scans/raw', {
          specContent: selectedSample.content,
          fileName: selectedSample.fileName,
          fileType: selectedSample.fileType,
          projectId: 'proj_default'
        });
      }

      clearInterval(stepInterval);
      setScanStep(scanSteps.length - 1);

      if (response && response.data.success) {
        const scanId = response.data.scan._id || response.data.scan.id;
        setTimeout(() => {
          navigate(`/scan/${scanId}`);
        }, 600);
      }
    } catch (err) {
      clearInterval(stepInterval);
      setIsScanning(false);
      setError(err.response?.data?.error || err.message || 'Scan failed. Please check specification syntax.');
    }
  };

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-8 animate-in fade-in duration-300">
      
      {/* Header */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sentinel-50 text-sentinel-800 text-xs font-semibold border border-sentinel-200">
          <Shield className="w-3.5 h-3.5 text-sentinel-600" />
          <span>Automated API Security Scanner</span>
        </div>
        <h1 className="text-3xl font-extrabold text-ink font-sans tracking-tight">
          New API Security Scan
        </h1>
        <p className="text-xs sm:text-sm text-ink-muted max-w-xl mx-auto">
          Upload an OpenAPI / Swagger definition or import a Postman Collection to analyze vulnerabilities, authorization gaps, and abuse risks.
        </p>
      </div>

      {/* Main Scan Container Card */}
      <div className="bg-white rounded-2xl border border-edge shadow-card overflow-hidden">
        
        {/* Navigation Tabs */}
        <div className="flex border-b border-edge bg-surface-muted">
          <button
            onClick={() => { setActiveTab('upload'); setError(null); }}
            disabled={isScanning}
            className={`flex-1 py-3.5 px-4 text-xs font-bold transition-all border-b-2 flex items-center justify-center gap-2 ${
              activeTab === 'upload'
                ? 'border-sentinel-700 text-sentinel-800 bg-white'
                : 'border-transparent text-ink-muted hover:text-ink'
            }`}
          >
            <UploadCloud className="w-4 h-4" />
            Upload File
          </button>
          <button
            onClick={() => { setActiveTab('paste'); setError(null); }}
            disabled={isScanning}
            className={`flex-1 py-3.5 px-4 text-xs font-bold transition-all border-b-2 flex items-center justify-center gap-2 ${
              activeTab === 'paste'
                ? 'border-sentinel-700 text-sentinel-800 bg-white'
                : 'border-transparent text-ink-muted hover:text-ink'
            }`}
          >
            <Code2 className="w-4 h-4" />
            Paste Raw Spec (JSON/YAML)
          </button>
          <button
            onClick={() => { setActiveTab('samples'); setError(null); }}
            disabled={isScanning}
            className={`flex-1 py-3.5 px-4 text-xs font-bold transition-all border-b-2 flex items-center justify-center gap-2 ${
              activeTab === 'samples'
                ? 'border-sentinel-700 text-sentinel-800 bg-white'
                : 'border-transparent text-ink-muted hover:text-ink'
            }`}
          >
            <Sparkles className="w-4 h-4 text-sentinel-600" />
            Preloaded Demo Specs
          </button>
        </div>

        {/* Tab 1: Upload File */}
        {activeTab === 'upload' && (
          <div className="p-8 space-y-6">
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleDrop}
              className={`border-2 border-dashed rounded-2xl p-8 text-center transition-all cursor-pointer ${
                file
                  ? 'border-sentinel-500 bg-sentinel-50/40'
                  : 'border-edge hover:border-sentinel-400 bg-surface-muted hover:bg-surface-subtle'
              }`}
              onClick={() => document.getElementById('file-upload-input').click()}
            >
              <input
                id="file-upload-input"
                type="file"
                accept=".json,.yaml,.yml"
                onChange={handleFileChange}
                className="hidden"
              />
              
              <div className="w-12 h-12 rounded-2xl bg-sentinel-100 text-sentinel-700 flex items-center justify-center mx-auto mb-4">
                <UploadCloud className="w-6 h-6" />
              </div>

              {file ? (
                <div className="space-y-1">
                  <p className="text-sm font-bold text-sentinel-950 font-mono">{file.name}</p>
                  <p className="text-xs text-ink-muted">{(file.size / 1024).toFixed(1)} KB • Click to change file</p>
                </div>
              ) : (
                <div className="space-y-1">
                  <p className="text-sm font-bold text-ink">
                    Drop your OpenAPI, Swagger, or Postman file here
                  </p>
                  <p className="text-xs text-ink-muted">
                    Supports OpenAPI 3.x (JSON/YAML), Swagger 2.0 (JSON/YAML), and Postman Collections (.json)
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Tab 2: Paste Raw Content */}
        {activeTab === 'paste' && (
          <div className="p-6 space-y-4">
            <div className="flex items-center justify-between">
              <label className="text-xs font-bold text-ink">Specification JSON or YAML</label>
              <input
                type="text"
                value={fileName}
                onChange={(e) => setFileName(e.target.value)}
                placeholder="filename.json or api.yaml"
                className="text-xs px-2.5 py-1 border border-edge rounded-lg font-mono text-ink focus:outline-none focus:ring-1 focus:ring-sentinel-600"
              />
            </div>
            <textarea
              rows={12}
              value={rawContent}
              onChange={(e) => setRawContent(e.target.value)}
              placeholder="Paste complete OpenAPI 3.0 / Swagger 2.0 or Postman Collection JSON/YAML here..."
              className="w-full bg-surface-muted border border-edge rounded-xl p-4 font-mono text-xs text-ink placeholder:text-ink-muted focus:outline-none focus:ring-2 focus:ring-sentinel-600 focus:bg-white resize-y"
            ></textarea>
          </div>
        )}

        {/* Tab 3: Preloaded Demo Specs */}
        {activeTab === 'samples' && (
          <div className="p-6 space-y-4">
            <p className="text-xs text-ink-muted">
              Select one of our curated specifications containing real-world API security patterns:
            </p>
            <div className="grid grid-cols-1 gap-3">
              {samples.map((sample) => (
                <div
                  key={sample.id}
                  onClick={() => setSelectedSample(sample)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer flex items-center justify-between ${
                    selectedSample?.id === sample.id
                      ? 'border-sentinel-600 bg-sentinel-50 shadow-subtle'
                      : 'border-edge hover:border-sentinel-300 bg-white'
                  }`}
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <h4 className="text-xs font-bold text-ink">{sample.name}</h4>
                      <span className="text-[10px] font-mono px-1.5 py-0.2 bg-surface-subtle text-ink-muted border rounded">
                        {sample.fileName}
                      </span>
                    </div>
                    <p className="text-[11px] text-ink-muted leading-relaxed">{sample.description}</p>
                  </div>
                  <div className="ml-4 flex-shrink-0">
                    <span className={`w-5 h-5 rounded-full border flex items-center justify-center ${
                      selectedSample?.id === sample.id
                        ? 'border-sentinel-700 bg-sentinel-700 text-white'
                        : 'border-edge bg-surface-subtle'
                    }`}>
                      {selectedSample?.id === sample.id && <CheckCircle2 className="w-3.5 h-3.5" />}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Error Alert */}
        {error && (
          <div className="mx-6 p-4 rounded-xl bg-red-50 border border-red-200 text-xs text-red-800 flex items-start gap-2.5">
            <AlertCircle className="w-4 h-4 text-red-600 flex-shrink-0 mt-0.5" />
            <div>
              <p className="font-bold">Specification Analysis Error</p>
              <p className="mt-0.5">{error}</p>
            </div>
          </div>
        )}

        {/* Scanning Progress Screen */}
        {isScanning ? (
          <div className="p-8 border-t border-edge bg-surface-subtle space-y-5 animate-in fade-in duration-200">
            <div className="flex items-center justify-between text-xs">
              <span className="font-bold text-sentinel-900 flex items-center gap-2">
                <Loader2 className="w-4 h-4 text-sentinel-700 animate-spin" />
                Analyzing API Specification...
              </span>
              <span className="font-mono font-bold text-sentinel-800">
                {Math.round(((scanStep + 1) / scanSteps.length) * 100)}%
              </span>
            </div>

            {/* Progress bar */}
            <div className="w-full bg-edge rounded-full h-2 overflow-hidden">
              <div
                className="bg-sentinel-700 h-2 rounded-full transition-all duration-300 ease-out"
                style={{ width: `${((scanStep + 1) / scanSteps.length) * 100}%` }}
              ></div>
            </div>

            {/* Current step text */}
            <p className="text-xs text-ink font-mono bg-white p-3 rounded-xl border border-edge shadow-subtle flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-sentinel-600 animate-pulse"></span>
              {scanSteps[scanStep]}
            </p>
          </div>
        ) : (
          /* Action Footer */
          <div className="p-6 border-t border-edge bg-surface-muted flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="text-xs text-ink-muted">
              <span>Security Engine: </span>
              <strong className="text-ink">OWASP API Security Top 10 (2023)</strong>
            </div>
            <button
              onClick={executeScan}
              className="w-full sm:w-auto px-6 py-3 bg-sentinel-700 hover:bg-sentinel-800 text-white text-xs font-bold rounded-xl shadow-sm shadow-sentinel-700/25 transition-all flex items-center justify-center gap-2"
            >
              <Shield className="w-4 h-4" />
              Run Security Analysis
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        )}

      </div>
    </div>
  );
}
