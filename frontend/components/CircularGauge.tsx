import React from "react";

interface CircularGaugeProps {
  score: number;
  level?: string;
  size?: number;
  strokeWidth?: number;
}

export function CircularGauge({
  score,
  level,
  size = 140,
  strokeWidth = 10,
}: CircularGaugeProps) {
  const normalizedScore = Math.max(0, Math.min(100, score));
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (normalizedScore / 100) * circumference;

  let strokeColor = "#10B981"; // emerald
  let labelColor = "text-emerald-400";
  let bgGlow = "shadow-emerald-500/10";

  if (normalizedScore >= 70) {
    strokeColor = "#F43F5E"; // rose
    labelColor = "text-rose-400";
    bgGlow = "shadow-rose-500/20";
  } else if (normalizedScore >= 40) {
    strokeColor = "#F59E0B"; // amber
    labelColor = "text-amber-400";
    bgGlow = "shadow-amber-500/20";
  } else if (normalizedScore >= 15) {
    strokeColor = "#38BDF8"; // sky
    labelColor = "text-sky-400";
    bgGlow = "shadow-sky-500/10";
  }

  return (
    <div className={`relative inline-flex flex-col items-center justify-center ${bgGlow}`}>
      <svg width={size} height={size} className="rotate-[-90deg]">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="#1E293B"
          strokeWidth={strokeWidth}
          fill="transparent"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={strokeColor}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          fill="transparent"
          className="transition-all duration-700 ease-out"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
        <span className={`text-2xl font-bold font-mono ${labelColor}`}>
          {normalizedScore}
        </span>
        <span className="text-[10px] uppercase tracking-wider text-slate-400 font-medium">
          {level || (normalizedScore >= 70 ? "Critical" : normalizedScore >= 40 ? "High" : normalizedScore >= 15 ? "Medium" : "Low")}
        </span>
      </div>
    </div>
  );
}
