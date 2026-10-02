import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { Shield, PlusCircle, LayoutDashboard, GitCompare, History, BookOpen, User, LogOut, ChevronDown, Sparkles } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

export default function Navbar() {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const [profileOpen, setProfileOpen] = useState(false);

  const isActive = (path) => location.pathname === path;

  const navLinks = [
    { name: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
    { name: 'New Scan', path: '/scan/new', icon: PlusCircle, highlight: true },
    { name: 'Scan History', path: '/scans', icon: History },
    { name: 'Compare', path: '/compare', icon: GitCompare },
  ];

  return (
    <header className="sticky top-0 z-40 w-full border-b border-edge bg-white/95 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        
        {/* Brand Logo */}
        <div className="flex items-center gap-8">
          <Link to="/" className="flex items-center gap-3 group">
            <div className="w-10 h-10 rounded-xl bg-sentinel-700 flex items-center justify-center shadow-md shadow-sentinel-700/20 group-hover:bg-sentinel-800 transition-colors">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="font-extrabold text-lg tracking-tight text-ink font-sans">API SENTINEL</span>
                <span className="px-1.5 py-0.5 text-[10px] font-semibold bg-sentinel-100 text-sentinel-800 rounded border border-sentinel-200">
                  AI CORE
                </span>
              </div>
              <p className="text-[11px] text-ink-muted leading-none hidden sm:block">Security Posture & Abuse Analysis</p>
            </div>
          </Link>

          {/* Main Navigation Links */}
          <nav className="hidden md:flex items-center gap-1">
            {navLinks.map((item) => {
              const Icon = item.icon;
              const active = isActive(item.path);
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium transition-all ${
                    active
                      ? 'bg-sentinel-50 text-sentinel-800 font-semibold shadow-subtle'
                      : item.highlight
                      ? 'text-sentinel-700 hover:bg-sentinel-50/80 font-medium'
                      : 'text-ink-muted hover:text-ink hover:bg-surface-subtle'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${active || item.highlight ? 'text-sentinel-700' : 'text-ink-muted'}`} />
                  {item.name}
                  {item.highlight && !active && (
                    <span className="flex h-2 w-2 relative">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-sentinel-400 opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-sentinel-600"></span>
                    </span>
                  )}
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Right Action Header */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/scan/new')}
            className="hidden sm:inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold text-white bg-sentinel-700 hover:bg-sentinel-800 shadow-sm shadow-sentinel-700/25 transition-all"
          >
            <Sparkles className="w-3.5 h-3.5" />
            Quick Scan API
          </button>

          {/* User Profile Menu */}
          <div className="relative">
            <button
              onClick={() => setProfileOpen(!profileOpen)}
              className="flex items-center gap-2.5 p-1.5 sm:px-3 sm:py-1.5 rounded-lg border border-edge hover:bg-surface-subtle transition-colors text-left"
            >
              <div className="w-7 h-7 rounded-full bg-sentinel-100 text-sentinel-800 flex items-center justify-center font-bold text-xs">
                {user?.name ? user.name[0].toUpperCase() : 'A'}
              </div>
              <div className="hidden lg:block">
                <p className="text-xs font-semibold text-ink leading-tight">{user?.name || 'Security Lead'}</p>
                <p className="text-[10px] text-ink-muted leading-tight">{user?.role || 'ADMIN'}</p>
              </div>
              <ChevronDown className="w-3.5 h-3.5 text-ink-muted hidden sm:block" />
            </button>

            {profileOpen && (
              <div className="absolute right-0 mt-2 w-56 bg-white rounded-xl shadow-modal border border-edge py-1.5 z-50 animate-in fade-in slide-in-from-top-2 duration-150">
                <div className="px-3.5 py-2 border-b border-edge">
                  <p className="text-xs font-semibold text-ink">{user?.name || 'Security Analyst'}</p>
                  <p className="text-[11px] text-ink-muted truncate">{user?.email || 'security.lead@apisentinel.dev'}</p>
                  <span className="inline-block mt-1 text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200 px-1.5 py-0.5 rounded">
                    Active Session ({user?.role || 'ADMIN'})
                  </span>
                </div>
                <Link
                  to="/dashboard"
                  onClick={() => setProfileOpen(false)}
                  className="flex items-center gap-2.5 px-3.5 py-2 text-xs text-ink hover:bg-surface-subtle"
                >
                  <LayoutDashboard className="w-4 h-4 text-ink-muted" />
                  Security Dashboard
                </Link>
                <Link
                  to="/scans"
                  onClick={() => setProfileOpen(false)}
                  className="flex items-center gap-2.5 px-3.5 py-2 text-xs text-ink hover:bg-surface-subtle"
                >
                  <History className="w-4 h-4 text-ink-muted" />
                  Audit History
                </Link>
                <div className="my-1 border-t border-edge"></div>
                <button
                  onClick={() => {
                    setProfileOpen(false);
                    logout();
                    navigate('/login');
                  }}
                  className="w-full flex items-center gap-2.5 px-3.5 py-2 text-xs text-red-600 hover:bg-red-50 text-left"
                >
                  <LogOut className="w-4 h-4 text-red-500" />
                  Sign Out / Switch User
                </button>
              </div>
            )}
          </div>
        </div>

      </div>
    </header>
  );
}
