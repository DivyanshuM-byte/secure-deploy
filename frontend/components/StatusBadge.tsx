import React from "react";
import { ShieldAlert, ShieldCheck, Clock, Loader2, XCircle } from "lucide-react";
import { ScanStatus } from "@/lib/api";

interface StatusBadgeProps {
  status: ScanStatus;
  size?: "sm" | "md" | "lg";
}

export function StatusBadge({ status, size = "md" }: StatusBadgeProps) {
  const sizeClasses = {
    sm: "px-2 py-0.5 text-xs gap-1",
    md: "px-2.5 py-1 text-xs gap-1.5 font-medium",
    lg: "px-3.5 py-1.5 text-sm gap-2 font-semibold",
  };

  const iconSizes = {
    sm: "w-3 h-3",
    md: "w-3.5 h-3.5",
    lg: "w-4 h-4",
  };

  switch (status) {
    case "blocked":
      return (
        <span
          className={`inline-flex items-center rounded-md border border-rose-500/30 bg-rose-950/60 text-rose-400 ${sizeClasses[size]}`}
        >
          <ShieldAlert className={`${iconSizes[size]} shrink-0`} />
          <span className="uppercase tracking-wide">Blocked</span>
        </span>
      );
    case "passed":
      return (
        <span
          className={`inline-flex items-center rounded-md border border-emerald-500/30 bg-emerald-950/60 text-emerald-400 ${sizeClasses[size]}`}
        >
          <ShieldCheck className={`${iconSizes[size]} shrink-0`} />
          <span className="uppercase tracking-wide">Passed</span>
        </span>
      );
    case "running":
      return (
        <span
          className={`inline-flex items-center rounded-md border border-amber-500/30 bg-amber-950/60 text-amber-300 ${sizeClasses[size]}`}
        >
          <Loader2 className={`${iconSizes[size]} shrink-0 animate-spin`} />
          <span className="uppercase tracking-wide">Running</span>
        </span>
      );
    case "queued":
      return (
        <span
          className={`inline-flex items-center rounded-md border border-slate-700 bg-slate-900 text-slate-300 ${sizeClasses[size]}`}
        >
          <Clock className={`${iconSizes[size]} shrink-0`} />
          <span className="uppercase tracking-wide">Queued</span>
        </span>
      );
    case "failed":
      return (
        <span
          className={`inline-flex items-center rounded-md border border-red-800 bg-red-950/80 text-red-300 ${sizeClasses[size]}`}
        >
          <XCircle className={`${iconSizes[size]} shrink-0`} />
          <span className="uppercase tracking-wide">Failed</span>
        </span>
      );
    default:
      return (
        <span className={`inline-flex items-center rounded-md bg-slate-800 text-slate-300 ${sizeClasses[size]}`}>
          {status}
        </span>
      );
  }
}
