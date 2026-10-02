import React from 'react';
import { AlertOctagon, AlertTriangle, AlertCircle, Info, ShieldAlert } from 'lucide-react';

export default function SeverityBadge({ severity, size = 'md', showIcon = true }) {
  const sev = (severity || 'INFO').toUpperCase();

  const configs = {
    CRITICAL: {
      bg: 'bg-red-50 text-red-700 border-red-200',
      iconColor: 'text-red-600',
      icon: AlertOctagon,
      label: 'CRITICAL'
    },
    HIGH: {
      bg: 'bg-orange-50 text-orange-700 border-orange-200',
      iconColor: 'text-orange-600',
      icon: AlertTriangle,
      label: 'HIGH'
    },
    MEDIUM: {
      bg: 'bg-amber-50 text-amber-700 border-amber-200',
      iconColor: 'text-amber-600',
      icon: AlertCircle,
      label: 'MEDIUM'
    },
    LOW: {
      bg: 'bg-blue-50 text-blue-700 border-blue-200',
      iconColor: 'text-blue-600',
      icon: Info,
      label: 'LOW'
    },
    INFO: {
      bg: 'bg-zinc-100 text-zinc-700 border-zinc-200',
      iconColor: 'text-zinc-600',
      icon: Info,
      label: 'INFO'
    }
  };

  const current = configs[sev] || configs.INFO;
  const Icon = current.icon;

  const sizeClasses = {
    sm: 'text-[10px] px-1.5 py-0.5 gap-1',
    md: 'text-xs px-2.5 py-1 gap-1.5 font-semibold',
    lg: 'text-sm px-3.5 py-1.5 gap-2 font-bold'
  };

  const iconSizes = {
    sm: 'w-3 h-3',
    md: 'w-3.5 h-3.5',
    lg: 'w-4 h-4'
  };

  return (
    <span className={`inline-flex items-center rounded-md border font-mono uppercase tracking-wider ${current.bg} ${sizeClasses[size]}`}>
      {showIcon && <Icon className={`${iconSizes[size]} ${current.iconColor}`} />}
      {current.label}
    </span>
  );
}
