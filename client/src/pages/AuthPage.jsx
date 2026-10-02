import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, Lock, Mail, User, ArrowRight, Sparkles, AlertCircle } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function AuthPage({ isRegister = false }) {
  const navigate = useNavigate();
  const { login, register, loading } = useAuth();

  const [mode, setMode] = useState(isRegister ? 'register' : 'login');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('demo@apisentinel.dev');
  const [password, setPassword] = useState('SentinelDemoPass123!');
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);

    if (mode === 'register') {
      const res = await register(name, email, password);
      if (res.success) {
        navigate('/dashboard');
      } else {
        setError(res.error);
      }
    } else {
      const res = await login(email, password);
      if (res.success) {
        navigate('/dashboard');
      } else {
        setError(res.error);
      }
    }
  };

  const handleDemoSignIn = () => {
    setEmail('demo@apisentinel.dev');
    setPassword('SentinelDemoPass123!');
    navigate('/dashboard');
  };

  return (
    <div className="min-h-[85vh] flex items-center justify-center px-4 py-12 bg-gradient-to-b from-sentinel-50/40 to-white">
      <div className="w-full max-w-md bg-white p-8 rounded-2xl border border-edge shadow-card space-y-6 animate-in fade-in duration-300">
        
        {/* Brand Header */}
        <div className="text-center space-y-2">
          <div className="w-12 h-12 rounded-2xl bg-sentinel-700 text-white flex items-center justify-center mx-auto shadow-md shadow-sentinel-700/20">
            <Shield className="w-6 h-6" />
          </div>
          <h2 className="text-xl font-extrabold text-ink font-sans tracking-tight">
            {mode === 'register' ? 'Create API Sentinel Account' : 'Welcome to API Sentinel'}
          </h2>
          <p className="text-xs text-ink-muted">
            {mode === 'register'
              ? 'Start auditing API specifications against OWASP vulnerabilities'
              : 'Sign in to access your security posture dashboard'}
          </p>
        </div>

        {/* Mode Switcher */}
        <div className="flex rounded-xl bg-surface-muted p-1 border border-edge">
          <button
            type="button"
            onClick={() => { setMode('login'); setError(null); }}
            className={`flex-1 py-2 text-xs font-bold rounded-lg transition-all ${
              mode === 'login' ? 'bg-white text-sentinel-800 shadow-subtle' : 'text-ink-muted hover:text-ink'
            }`}
          >
            Sign In
          </button>
          <button
            type="button"
            onClick={() => { setMode('register'); setError(null); }}
            className={`flex-1 py-2 text-xs font-bold rounded-lg transition-all ${
              mode === 'register' ? 'bg-white text-sentinel-800 shadow-subtle' : 'text-ink-muted hover:text-ink'
            }`}
          >
            Register
          </button>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="p-3 rounded-xl bg-red-50 border border-red-200 text-xs text-red-800 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-red-600 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          {mode === 'register' && (
            <div className="space-y-1">
              <label className="font-bold text-ink">Full Name</label>
              <div className="relative">
                <User className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-ink-muted" />
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Alex Rivera"
                  className="w-full bg-surface-subtle border border-edge rounded-xl pl-9 pr-3 py-2.5 text-xs text-ink focus:outline-none focus:ring-2 focus:ring-sentinel-600 focus:bg-white"
                />
              </div>
            </div>
          )}

          <div className="space-y-1">
            <label className="font-bold text-ink">Work Email</label>
            <div className="relative">
              <Mail className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-ink-muted" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="name@company.com"
                className="w-full bg-surface-subtle border border-edge rounded-xl pl-9 pr-3 py-2.5 text-xs text-ink focus:outline-none focus:ring-2 focus:ring-sentinel-600 focus:bg-white"
              />
            </div>
          </div>

          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <label className="font-bold text-ink">Password</label>
              {mode === 'login' && (
                <span className="text-[11px] text-sentinel-700 hover:underline cursor-pointer">
                  Forgot password?
                </span>
              )}
            </div>
            <div className="relative">
              <Lock className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-ink-muted" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-surface-subtle border border-edge rounded-xl pl-9 pr-3 py-2.5 text-xs text-ink focus:outline-none focus:ring-2 focus:ring-sentinel-600 focus:bg-white"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 bg-sentinel-700 hover:bg-sentinel-800 disabled:opacity-50 text-white rounded-xl text-xs font-bold shadow-sm shadow-sentinel-700/25 transition-all flex items-center justify-center gap-1.5"
          >
            {loading ? 'Authenticating...' : (mode === 'register' ? 'Create Account' : 'Sign In')}
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        {/* Demo Mode Quick Access */}
        <div className="pt-2 border-t border-edge text-center space-y-2">
          <p className="text-[11px] text-ink-muted">Evaluating API Sentinel?</p>
          <button
            type="button"
            onClick={handleDemoSignIn}
            className="w-full py-2.5 bg-sentinel-50 hover:bg-sentinel-100 text-sentinel-900 border border-sentinel-200 rounded-xl text-xs font-semibold shadow-subtle transition-colors flex items-center justify-center gap-1.5"
          >
            <Sparkles className="w-3.5 h-3.5 text-sentinel-700" />
            Continue as Demo Security Lead (1-Click)
          </button>
        </div>

      </div>
    </div>
  );
}
