import React from "react";
import { SeverityLevel } from "@/lib/api";

interface SeverityChipProps {
  severity: SeverityLevel | string;
  count?: number;
}

export function SeverityChip({ severity, count }: SeverityChipProps) {
  const sev = severity.toLowerCase();

  const styles: Record<string, string> = {
    critical: "bg-rose-950/60 border-rose-500/40 text-rose-300",
    high: "bg-amber-950/60 border-amber-500/40 text-amber-300",
    medium: "bg-sky-950/60 border-sky-500/40 text-sky-300",
    low: "bg-slate-900 border-slate-700 text-slate-300",
  };

  const currentStyle = styles[sev] || styles.low;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border text-xs font-mono font-medium capitalize ${currentStyle}`}
    >
      <span>{severity}</span>
      {typeof count === "number" && (
        <span className="px-1.5 py-0.2 rounded bg-black/40 text-[10px] tabular-nums font-semibold">
          {count}
        </span>
      )}
    </span>
  );
}
