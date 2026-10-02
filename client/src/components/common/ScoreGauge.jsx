import React from 'react';

export default function ScoreGauge({ score = 0, riskLevel = 'Moderate', size = 160 }) {
  const normalizedScore = Math.min(100, Math.max(0, score));

  // Determine stroke color and status styling
  let strokeColor = '#10B981'; // Green (0-20)
  let levelColorClass = 'text-emerald-700 bg-emerald-50 border-emerald-200';
  let badgeText = 'EXCELLENT';

  if (normalizedScore > 80) {
    strokeColor = '#DC2626'; // Red (81-100)
    levelColorClass = 'text-red-700 bg-red-50 border-red-200';
    badgeText = 'CRITICAL RISK';
  } else if (normalizedScore > 60) {
    strokeColor = '#EA580C'; // Orange (61-80)
    levelColorClass = 'text-orange-700 bg-orange-50 border-orange-200';
    badgeText = 'HIGH RISK';
  } else if (normalizedScore > 40) {
    strokeColor = '#D97706'; // Amber (41-60)
    levelColorClass = 'text-amber-700 bg-amber-50 border-amber-200';
    badgeText = 'MODERATE RISK';
  } else if (normalizedScore > 20) {
    strokeColor = '#2563EB'; // Blue (21-40)
    levelColorClass = 'text-blue-700 bg-blue-50 border-blue-200';
    badgeText = 'GOOD POSTURE';
  }

  const radius = (size - 24) / 2;
  const circumference = 2 * Math.PI * radius;
  // Use a 270-degree arc gauge
  const strokeDashoffset = circumference - (normalizedScore / 100) * circumference;

  return (
    <div className="flex flex-col items-center justify-center relative select-none">
      <div className="relative" style={{ width: size, height: size }}>
        <svg className="w-full h-full -rotate-90 transform" viewBox={`0 0 ${size} ${size}`}>
          {/* Background track circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="#EDE9FE"
            strokeWidth="12"
            fill="transparent"
          />
          {/* Progress circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={strokeColor}
            strokeWidth="12"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Center score label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className="text-3xl font-extrabold text-ink font-mono tracking-tight leading-none">
            {normalizedScore}
          </span>
          <span className="text-[11px] font-semibold text-ink-muted mt-1 uppercase tracking-wider">
            / 100 RISK
          </span>
        </div>
      </div>

      <div className="mt-2">
        <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold border font-mono tracking-wide ${levelColorClass}`}>
          {riskLevel || badgeText}
        </span>
      </div>
    </div>
  );
}
