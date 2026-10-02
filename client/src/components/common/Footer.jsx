import React from 'react';
import { Shield, Lock, FileCheck, ExternalLink } from 'lucide-react';

export default function Footer() {
  return (
    <footer className="border-t border-edge bg-surface-muted py-10 mt-auto">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col md:flex-row items-center justify-between gap-6">
          
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-sentinel-700 flex items-center justify-center text-white">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <p className="text-sm font-bold text-ink">API SENTINEL</p>
              <p className="text-xs text-ink-muted">Find API security risks before attackers do.</p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-6 text-xs text-ink-muted">
            <div className="flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-sentinel-600" />
              <span>OWASP API Security Top 10 (2023) Rule Engine</span>
            </div>
            <div className="flex items-center gap-1.5">
              <FileCheck className="w-3.5 h-3.5 text-sentinel-600" />
              <span>OpenAPI 3.x • Swagger 2.0 • Postman Collection</span>
            </div>
          </div>

          <div className="text-xs text-ink-muted text-center md:text-right">
            <p>© {new Date().getFullYear()} API Sentinel Security Platform.</p>
            <p className="text-[11px] text-ink-subtle">Designed for Developers & AppSec Teams</p>
          </div>

        </div>
      </div>
    </footer>
  );
}
