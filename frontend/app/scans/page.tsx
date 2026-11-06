"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  Shield,
  RefreshCw,
  ArrowRight,
  ShieldCheck,
  ShieldAlert,
  Flame,
  FileCode,
  Clock,
  Loader2,
} from "lucide-react";
import { fetchScans, ScanSummary } from "@/lib/api";
import { StatusBadge } from "@/components/StatusBadge";

export default function ScansHistoryPage() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadScans = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchScans();
      setScans(data);
    } catch (err: any) {
      setError(err?.message || "Failed to load scan history");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadScans();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white flex items-center gap-3">
            <Shield className="w-7 h-7 text-emerald-400" />
            Security Scan History
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Audit logs of all inspected repositories, ZIP packages, and project workspaces.
          </p>
        </div>
        <button
          onClick={loadScans}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-800 bg-[#0D1322] hover:bg-slate-800 text-slate-300 transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          <span>Refresh</span>
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl border border-red-900/50 bg-red-950/20 text-red-400 text-sm">
          {error}
        </div>
      )}

      {/* Scans Table */}
      <div className="bg-[#0B101E] border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-[#0D1424] text-xs uppercase font-medium text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Scan ID</th>
                <th className="py-3 px-4">Target Source</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Findings</th>
                <th className="py-3 px-4">Created</th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
              {loading && scans.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500 font-sans">
                    <Loader2 className="w-6 h-6 animate-spin mx-auto text-emerald-400 mb-2" />
                    Loading scan records...
                  </td>
                </tr>
              ) : scans.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-16 text-center text-slate-500 font-sans">
                    No scans found. Start a scan to inspect source code.
                  </td>
                </tr>
              ) : (
                scans.map((s) => (
                  <tr key={s.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3 px-4 font-bold text-slate-200">#{s.id}</td>
                    <td className="py-3 px-4 max-w-xs truncate text-slate-400 font-sans">{s.source}</td>
                    <td className="py-3 px-4 font-sans">
                      <StatusBadge status={s.status} />
                    </td>
                    <td className="py-3 px-4 font-sans">
                      <span className="font-bold text-slate-200">{s.risk_score}</span>{" "}
                      <span className="text-[10px] text-slate-500 uppercase">({s.risk_level})</span>
                    </td>
                    <td className="py-3 px-4 font-sans">{s.findings_count} detected</td>
                    <td className="py-3 px-4 text-slate-500">
                      {new Date(s.created_at).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 text-right font-sans">
                      <Link
                        href={`/scans/${s.id}`}
                        className="text-emerald-400 hover:text-emerald-300 font-semibold inline-flex items-center gap-1 text-xs"
                      >
                        View Report <ArrowRight className="w-3 h-3" />
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
