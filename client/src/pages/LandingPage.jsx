import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Shield, ArrowRight, Sparkles, CheckCircle2, Lock, AlertTriangle,
  FileCode2, Network, Cpu, FileCheck, Layers, ChevronRight, Zap
} from 'lucide-react';

export default function LandingPage() {
  const navigate = useNavigate();

  const features = [
    {
      icon: Lock,
      title: 'Authentication & Scope Gaps',
      description: 'Detect missing security schemes, unauthenticated admin routes, and inconsistent endpoint protections.'
    },
    {
      icon: Network,
      title: 'BOLA / IDOR Pattern Detection',
      description: 'Identifies unverified direct object identifiers in route paths without claiming false runtime proofs.'
    },
    {
      icon: AlertTriangle,
      title: 'Sensitive Data Exposure',
      description: 'Deep schema inspection for password hashes, API keys, private credentials, and high-risk PII.'
    },
    {
      icon: Zap,
      title: 'Anti-Abuse & Rate Limiting',
      description: 'Flags sensitive auth, payment, and computational flows lacking documented rate limits and throttling.'
    },
    {
      icon: Layers,
      title: 'Attack Surface Topology',
      description: 'Interactive React Flow graph mapping relationships between security schemes, endpoints, and risks.'
    },
    {
      icon: Cpu,
      title: 'Grounded AI Security Reasoner',
      description: 'AI assistant trained strictly on scan evidence providing actionable defensive remediation code.'
    }
  ];

  return (
    <div className="flex flex-col min-h-screen">
      
      {/* Hero Section */}
      <section className="relative pt-20 pb-28 px-4 sm:px-6 lg:px-8 overflow-hidden bg-gradient-to-b from-sentinel-50/50 via-white to-white">
        <div className="max-w-5xl mx-auto text-center space-y-8 relative z-10">
          
          {/* Badge */}
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-sentinel-100/80 border border-sentinel-200 text-sentinel-800 text-xs font-semibold shadow-subtle animate-in fade-in slide-in-from-top-3 duration-300">
            <Sparkles className="w-3.5 h-3.5 text-sentinel-600" />
            <span>AI-Assisted API Security Posture & Abuse Analysis</span>
          </div>

          {/* Heading */}
          <h1 className="text-4xl sm:text-6xl font-extrabold text-ink tracking-tight leading-[1.15] font-sans">
            Secure Your APIs Before <br className="hidden sm:inline" />
            <span className="bg-clip-text text-transparent bg-gradient-to-r from-sentinel-700 via-sentinel-800 to-sentinel-900">
              Attackers Find The Weaknesses.
            </span>
          </h1>

          {/* Subheading */}
          <p className="max-w-3xl mx-auto text-base sm:text-lg text-ink-muted leading-relaxed">
            API Sentinel analyzes OpenAPI, Swagger, and Postman collections, identifies OWASP API Top 10 vulnerabilities, calculates multi-factor risk scores, and generates actionable defensive remediation.
          </p>

          {/* CTA Buttons */}
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-4">
            <Link
              to="/scan/new"
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-7 py-3.5 rounded-xl font-bold text-sm text-white bg-sentinel-700 hover:bg-sentinel-800 shadow-lg shadow-sentinel-700/25 transition-all hover:-translate-y-0.5"
            >
              <Shield className="w-4 h-4" />
              Start Security Scan
              <ArrowRight className="w-4 h-4" />
            </Link>
            <button
              onClick={() => navigate('/scan/new?sample=ecommerce_vuln')}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3.5 rounded-xl font-semibold text-sm text-sentinel-900 bg-sentinel-50 hover:bg-sentinel-100 border border-sentinel-200 shadow-subtle transition-all"
            >
              <Sparkles className="w-4 h-4 text-sentinel-700" />
              Explore Vulnerable Demo API
            </button>
          </div>

          {/* Supported Specs Pill */}
          <div className="pt-8 flex flex-wrap items-center justify-center gap-6 text-xs text-ink-muted font-medium">
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-600" /> OpenAPI 3.0 & 3.1
            </span>
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-600" /> Swagger 2.0 (JSON/YAML)
            </span>
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-600" /> Postman Collections v2.1
            </span>
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-600" /> Zero Fake Results
            </span>
          </div>

        </div>
      </section>

      {/* Live Sample Preview Section */}
      <section className="py-16 bg-surface-subtle border-y border-edge">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-2xl mx-auto mb-12">
            <h2 className="text-2xl font-bold text-ink tracking-tight">Try 1-Click Preloaded Specifications</h2>
            <p className="text-xs sm:text-sm text-ink-muted mt-2">
              Instantly run real static analysis on curated API specifications to experience dynamic scoring, graph visualization, and AI remediation.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            
            {/* Sample 1: Vulnerable E-commerce */}
            <div className="p-6 rounded-2xl bg-white border border-edge hover:border-sentinel-300 shadow-card hover:shadow-card-hover transition-all flex flex-col justify-between">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-red-50 text-red-700 border border-red-200 font-bold">
                    HIGH RISK SAMPLE
                  </span>
                  <span className="text-xs text-ink-muted">OpenAPI 3.0</span>
                </div>
                <h3 className="text-base font-bold text-ink">ShopSentinel E-Commerce API</h3>
                <p className="text-xs text-ink-muted leading-relaxed">
                  Contains realistic BOLA/IDOR on order routes, unauthenticated administrative endpoints, passwordHash in response schemas, and SSRF webhooks.
                </p>
              </div>
              <button
                onClick={() => navigate('/scan/new?sample=ecommerce_vuln')}
                className="mt-6 w-full py-2.5 px-4 bg-sentinel-700 hover:bg-sentinel-800 text-white text-xs font-semibold rounded-xl shadow-sm transition-all flex items-center justify-center gap-1.5"
              >
                Scan Vulnerable Spec
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Sample 2: Secure Banking */}
            <div className="p-6 rounded-2xl bg-white border border-edge hover:border-sentinel-300 shadow-card hover:shadow-card-hover transition-all flex flex-col justify-between">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-bold">
                    HARDENED SAMPLE
                  </span>
                  <span className="text-xs text-ink-muted">OpenAPI 3.0 YAML</span>
                </div>
                <h3 className="text-base font-bold text-ink">Apex Secure FinTech Banking</h3>
                <p className="text-xs text-ink-muted leading-relaxed">
                  Hardened banking specification with OAuth2 granular scopes, strict parameter constraints, HTTPS enforcement, and rate-limiting headers.
                </p>
              </div>
              <button
                onClick={() => navigate('/scan/new?sample=banking_secure')}
                className="mt-6 w-full py-2.5 px-4 bg-sentinel-50 hover:bg-sentinel-100 text-sentinel-900 border border-sentinel-200 text-xs font-semibold rounded-xl shadow-subtle transition-all flex items-center justify-center gap-1.5"
              >
                Scan Hardened Spec
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Sample 3: Postman Collection */}
            <div className="p-6 rounded-2xl bg-white border border-edge hover:border-sentinel-300 shadow-card hover:shadow-card-hover transition-all flex flex-col justify-between">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200 font-bold">
                    POSTMAN V2.1
                  </span>
                  <span className="text-xs text-ink-muted">Collection JSON</span>
                </div>
                <h3 className="text-base font-bold text-ink">CloudFleet Microservices</h3>
                <p className="text-xs text-ink-muted leading-relaxed">
                  Microservice fleet collection demonstrating nested folders, query parameters, auth headers, and driver endpoint analysis.
                </p>
              </div>
              <button
                onClick={() => navigate('/scan/new?sample=postman_fleet')}
                className="mt-6 w-full py-2.5 px-4 bg-sentinel-50 hover:bg-sentinel-100 text-sentinel-900 border border-sentinel-200 text-xs font-semibold rounded-xl shadow-subtle transition-all flex items-center justify-center gap-1.5"
              >
                Scan Postman Collection
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>

          </div>
        </div>
      </section>

      {/* Feature Grid */}
      <section className="py-20 px-4 sm:px-6 lg:px-8 bg-white">
        <div className="max-w-7xl mx-auto">
          <div className="text-center max-w-2xl mx-auto mb-16">
            <h2 className="text-3xl font-extrabold text-ink tracking-tight font-sans">
              Comprehensive OWASP API Top 10 Coverage
            </h2>
            <p className="text-sm text-ink-muted mt-3">
              Deep static analysis engineered specifically for API security architecture, access control policies, and data flow hygiene.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {features.map((f, i) => {
              const Icon = f.icon;
              return (
                <div
                  key={i}
                  className="p-6 rounded-2xl border border-edge bg-white hover:border-sentinel-300 hover:shadow-card-hover transition-all space-y-3 group"
                >
                  <div className="w-10 h-10 rounded-xl bg-sentinel-50 text-sentinel-700 flex items-center justify-center group-hover:bg-sentinel-700 group-hover:text-white transition-colors">
                    <Icon className="w-5 h-5" />
                  </div>
                  <h3 className="text-base font-bold text-ink">{f.title}</h3>
                  <p className="text-xs text-ink-muted leading-relaxed">{f.description}</p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

    </div>
  );
}
