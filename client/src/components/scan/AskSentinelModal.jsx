import React, { useState } from 'react';
import { Sparkles, Send, Bot, User, Code2, Copy, Check, ShieldAlert, ArrowRight } from 'lucide-react';
import api from '../../services/api';

export default function AskSentinelModal({ scan, initialQuestion = null }) {
  const [query, setQuery] = useState(initialQuestion || '');
  const [messages, setMessages] = useState([
    {
      sender: 'sentinel',
      text: `Hello! I am **Sentinel AI**, your dedicated API Security Assistant for **${scan?.apiTitle || 'this specification'}**.\n\nI have indexed all **${scan?.findingCount || scan?.findings?.length || 0} security observations** and **${scan?.endpointCount || scan?.endpoints?.length || 0} endpoints**.\n\nHow can I assist your team today?`,
      code: null,
      evidence: []
    }
  ]);
  const [loading, setLoading] = useState(false);
  const [copiedIdx, setCopiedIdx] = useState(null);

  const suggestedPrompts = [
    "Which findings should I fix first?",
    "How do I fix the BOLA / IDOR issue?",
    "Why is this API considered high risk?",
    "What is the difference between authentication and authorization?",
    "Explain the sensitive data exposure risks in this API"
  ];

  const handleSend = async (customText = null) => {
    const textToSend = customText || query;
    if (!textToSend.trim() || loading) return;

    const userMessage = { sender: 'user', text: textToSend };
    setMessages((prev) => [...prev, userMessage]);
    setQuery('');
    setLoading(true);

    try {
      const res = await api.post('/ai/ask', {
        query: textToSend,
        scanId: scan?._id || scan?.id
      });

      if (res.data.success) {
        const aiData = res.data.data;
        setMessages((prev) => [
          ...prev,
          {
            sender: 'sentinel',
            text: aiData.answer,
            code: aiData.code_snippet,
            evidence: aiData.grounded_evidence || [],
            rules: aiData.relevant_rules || []
          }
        ]);
      }
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          sender: 'sentinel',
          text: 'Unable to process question at this time. Please check security service connection.',
          code: null
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  const copyCode = (code, idx) => {
    navigator.clipboard.writeText(code);
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 2000);
  };

  return (
    <div className="flex flex-col h-[640px] bg-white border border-edge rounded-2xl overflow-hidden shadow-card">
      
      {/* Header */}
      <div className="p-4 border-b border-edge bg-sentinel-50/50 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-xl bg-sentinel-700 text-white flex items-center justify-center shadow-sm">
            <Sparkles className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-ink flex items-center gap-1.5">
              Ask Sentinel AI Security Assistant
              <span className="text-[10px] bg-sentinel-100 text-sentinel-800 border border-sentinel-200 px-1.5 py-0.2 rounded font-mono font-semibold">
                Grounded Reasoning
              </span>
            </h3>
            <p className="text-xs text-ink-muted">Trained on OWASP API Security & active scan findings</p>
          </div>
        </div>
      </div>

      {/* Suggested Chips */}
      <div className="p-3 bg-surface-subtle border-b border-edge overflow-x-auto flex items-center gap-2 text-xs no-scrollbar">
        <span className="text-[11px] font-semibold text-ink-muted whitespace-nowrap">Suggested:</span>
        {suggestedPrompts.map((p, i) => (
          <button
            key={i}
            onClick={() => handleSend(p)}
            className="px-2.5 py-1 rounded-full bg-white border border-edge hover:border-sentinel-400 hover:text-sentinel-800 text-[11px] font-medium text-ink whitespace-nowrap transition-colors shadow-subtle flex items-center gap-1"
          >
            {p}
            <ArrowRight className="w-3 h-3 text-sentinel-600" />
          </button>
        ))}
      </div>

      {/* Messages Feed */}
      <div className="flex-1 p-4 overflow-y-auto space-y-4">
        {messages.map((msg, idx) => (
          <div
            key={idx}
            className={`flex gap-3 ${msg.sender === 'user' ? 'justify-end' : 'justify-start'}`}
          >
            {msg.sender === 'sentinel' && (
              <div className="w-7 h-7 rounded-lg bg-sentinel-700 text-white flex items-center justify-center flex-shrink-0 mt-0.5">
                <Bot className="w-4 h-4" />
              </div>
            )}

            <div
              className={`max-w-[85%] rounded-2xl p-4 text-xs leading-relaxed shadow-subtle ${
                msg.sender === 'user'
                  ? 'bg-sentinel-700 text-white rounded-br-none'
                  : 'bg-surface-subtle border border-edge text-ink rounded-tl-none'
              }`}
            >
              <div className="whitespace-pre-line font-sans space-y-2">
                {msg.text}
              </div>

              {/* Code block if returned */}
              {msg.code && (
                <div className="mt-3 rounded-xl bg-zinc-900 text-zinc-100 p-3.5 font-mono text-[11px] border border-zinc-800 relative">
                  <div className="flex items-center justify-between pb-2 mb-2 border-b border-zinc-800 text-[10px] text-zinc-400">
                    <span className="flex items-center gap-1 font-mono">
                      <Code2 className="w-3 h-3 text-sentinel-400" /> Defensive Implementation
                    </span>
                    <button
                      onClick={() => copyCode(msg.code, idx)}
                      className="flex items-center gap-1 text-zinc-300 hover:text-white"
                    >
                      {copiedIdx === idx ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      {copiedIdx === idx ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <pre className="overflow-x-auto">{msg.code}</pre>
                </div>
              )}

              {/* Grounded rules chips */}
              {msg.rules && msg.rules.length > 0 && (
                <div className="mt-2.5 pt-2 border-t border-edge/60 flex flex-wrap items-center gap-1.5">
                  <span className="text-[10px] font-semibold text-ink-muted">Referenced Rules:</span>
                  {msg.rules.map((r, ri) => (
                    <span key={ri} className="font-mono text-[10px] bg-sentinel-100 text-sentinel-800 px-1.5 py-0.2 rounded font-bold">
                      {r}
                    </span>
                  ))}
                </div>
              )}
            </div>

            {msg.sender === 'user' && (
              <div className="w-7 h-7 rounded-lg bg-zinc-800 text-white flex items-center justify-center flex-shrink-0 mt-0.5">
                <User className="w-4 h-4" />
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex gap-3 justify-start items-center">
            <div className="w-7 h-7 rounded-lg bg-sentinel-700 text-white flex items-center justify-center">
              <Bot className="w-4 h-4 animate-pulse" />
            </div>
            <div className="bg-surface-subtle border border-edge rounded-2xl p-3 text-xs text-ink-muted flex items-center gap-2">
              <span className="animate-spin w-3.5 h-3.5 border-2 border-sentinel-700 border-t-transparent rounded-full"></span>
              Sentinel AI reasoning through scan findings...
            </div>
          </div>
        )}
      </div>

      {/* Input bar */}
      <div className="p-3 border-t border-edge bg-white flex items-center gap-2">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSend()}
          placeholder="Ask Sentinel AI about vulnerabilities, BOLA fixes, or priority roadmap..."
          className="flex-1 bg-surface-subtle border border-edge rounded-xl px-4 py-2.5 text-xs text-ink placeholder:text-ink-muted focus:outline-none focus:ring-2 focus:ring-sentinel-600 focus:border-transparent"
        />
        <button
          onClick={() => handleSend()}
          disabled={!query.trim() || loading}
          className="p-2.5 bg-sentinel-700 hover:bg-sentinel-800 disabled:opacity-50 text-white rounded-xl shadow-sm transition-colors"
        >
          <Send className="w-4 h-4" />
        </button>
      </div>

    </div>
  );
}
