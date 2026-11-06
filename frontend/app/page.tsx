"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  ShieldCheck,
  Activity,
  FileCode,
  ArrowRight,
  RefreshCw,
  Plus,
  Flame,
  AlertTriangle,
  UploadCloud,
} from "lucide-react";
import { fetchStats, fetchScans, Stats, ScanSummary } from "@/lib/api";
import { StatusBadge } from "@/components/StatusBadge";
import { SeverityChip } from "@/components/SeverityChip";
import { CircularGauge } from "@/components/CircularGauge";

export default function DashboardPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [recentScans, setRecentScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadDashboardData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsData, scansData] = await Promise.all([
        fetchStats().catch(() => null),
        fetchScans().catch(() => []),
      ]);

      if (statsData) {
        setStats(statsData);
      } else {
        // Fallback calculations if /api/stats failed
        const completed = scansData.filter((s) => s.status === "passed" || s.status === "blocked");
        const blocked = scansData.filter((s) => s.status === "blocked").length;
        const passed = scansData.filter((s) => s.status === "passed").length;
        const avg = completed.length
          ? round(completed.reduce((acc, s) => acc + s.risk_score, 0) / completed.length, 1)
          : 0;
        setStats({
          total_scans: scansData.length,
          blocked_count: blocked,
          passed_count: passed,
          total_findings: scansData.reduce((acc, s) => acc + s.findings_count, 0),
          findings_by_severity: { critical: 0, high: 0, medium: 0, low: 0 },
          avg_risk_score: avg,
        });
      }

      setRecentScans(scansData.slice(0, 5));
    } catch (err: any) {
      setError(err?.message || "Failed to load dashboard metrics");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboardData();
  }, []);

  function round(val: number, decimals: number) {
    return Number(Math.round(Number(val + "e" + decimals)) + "e-" + decimals);
  }

  const totalFindings = stats?.total_findings || 0;
  const criticalCount = stats?.findings_by_severity.critical || 0;
  const highCount = stats?.findings_by_severity.high || 0;
  const mediumCount = stats?.findings_by_severity.medium || 0;
  const lowCount = stats?.findings_by_severity.low || 0;

  return (
    <div className="space-y-8">
      {/* Top Banner / Hero */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white">
            DevSecOps Gate Overview
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Continuous static analysis of secrets, PII, and infrastructure keys before production deployments.
          </p>
        </div>
        <div className="flex items-center gap-2.5">
          <button
            onClick={loadDashboardData}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-800 bg-[#0D1322] hover:bg-slate-800 text-slate-300 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </button>
          <Link
            href="/scan"
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>New Scan</span>
          </Link>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-lg border border-rose-800/80 bg-rose-950/40 text-rose-300 text-sm flex items-center gap-2.5">
          <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Ingestion Scanner Banner */}
      <div className="p-5 rounded-xl border border-slate-800 bg-[#0D1322] flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 shrink-0">
            <UploadCloud className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-white">Start New Security Scan</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Upload a .zip package, clone a GitHub repository, scan a local directory, or live-inspect code snippets.
            </p>
          </div>
        </div>
        <Link
          href="/scan"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 text-slate-950 transition-colors shadow-sm shrink-0"
        >
          <span>Open Scanner (4 Sources)</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </Link>
      </div>

      {/* Stats Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Total Scans */}
        <div className="p-5 rounded-xl border border-slate-800 bg-[#0D1322] flex items-center justify-between">
          <div>
            <div className="text-xs uppercase font-mono tracking-wider text-slate-400">
              Total Scans
            </div>
            <div className="mt-2 text-3xl font-bold font-mono text-white tabular-nums">
              {loading ? "--" : stats?.total_scans ?? 0}
            </div>
            <div className="mt-1 text-xs text-slate-500">
              Repository &amp; archive inspections
            </div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-slate-800/60 border border-slate-700/60 flex items-center justify-center text-slate-300">
            <Activity className="w-5 h-5" />
          </div>
        </div>

        {/* Card 2: Blocked Deployments */}
        <div className="p-5 rounded-xl border border-rose-900/40 bg-[#0D1322] flex items-center justify-between">
          <div>
            <div className="text-xs uppercase font-mono tracking-wider text-rose-400">
              Blocked Deploys
            </div>
            <div className="mt-2 text-3xl font-bold font-mono text-rose-400 tabular-nums">
              {loading ? "--" : stats?.blocked_count ?? 0}
            </div>
            <div className="mt-1 text-xs text-rose-300/60">
              Violations with risk $\ge$ 40 or critical
            </div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-rose-950/80 border border-rose-800/60 flex items-center justify-center text-rose-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
        </div>

        {/* Card 3: Passed Deployments */}
        <div className="p-5 rounded-xl border border-emerald-900/40 bg-[#0D1322] flex items-center justify-between">
          <div>
            <div className="text-xs uppercase font-mono tracking-wider text-emerald-400">
              Passed Deploys
            </div>
            <div className="mt-2 text-3xl font-bold font-mono text-emerald-400 tabular-nums">
              {loading ? "--" : stats?.passed_count ?? 0}
            </div>
            <div className="mt-1 text-xs text-emerald-300/60">
              Zero blocking security issues
            </div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-emerald-950/80 border border-emerald-800/60 flex items-center justify-center text-emerald-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
        </div>

        {/* Card 4: Average Risk Score */}
        <div className="p-5 rounded-xl border border-slate-800 bg-[#0D1322] flex items-center justify-between">
          <div>
            <div className="text-xs uppercase font-mono tracking-wider text-slate-400">
              Avg Risk Score
            </div>
            <div className="mt-2 text-3xl font-bold font-mono text-white tabular-nums">
              {loading ? "--" : `${stats?.avg_risk_score ?? 0}/100`}
            </div>
            <div className="mt-1 text-xs text-slate-500">
              Overall security risk index
            </div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-slate-800/60 border border-slate-700/60 flex items-center justify-center text-slate-300">
            <Flame className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Severity Breakdown Bar */}
      <div className="p-6 rounded-xl border border-slate-800 bg-[#0D1322]">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div>
            <h2 className="text-base font-semibold text-white">
              Findings Breakdown by Severity
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Aggregated detection tally across all scanned repositories.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <SeverityChip severity="critical" count={criticalCount} />
            <SeverityChip severity="high" count={highCount} />
            <SeverityChip severity="medium" count={mediumCount} />
            <SeverityChip severity="low" count={lowCount} />
          </div>
        </div>

        {/* Stacked Proportional Bar */}
        <div className="w-full h-3 rounded-full bg-slate-800 overflow-hidden flex">
          {totalFindings > 0 ? (
            <>
              <div
                style={{ width: `${(criticalCount / totalFindings) * 100}%` }}
                className="bg-rose-500 h-full"
                title={`Critical: ${criticalCount}`}
              />
              <div
                style={{ width: `${(highCount / totalFindings) * 100}%` }}
                className="bg-amber-500 h-full"
                title={`High: ${highCount}`}
              />
              <div
                style={{ width: `${(mediumCount / totalFindings) * 100}%` }}
                className="bg-sky-500 h-full"
                title={`Medium: ${mediumCount}`}
              />
              <div
                style={{ width: `${(lowCount / totalFindings) * 100}%` }}
                className="bg-slate-400 h-full"
                title={`Low: ${lowCount}`}
              />
            </>
          ) : (
            <div className="w-full h-full bg-slate-800/60" />
          )}
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="rounded-xl border border-slate-800 bg-[#0D1322] overflow-hidden">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-white">Recent Security Scans</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Latest pipeline triggers, uploads, and repository inspections.
            </p>
          </div>
          <Link
            href="/scans"
            className="text-xs font-semibold text-emerald-400 hover:text-emerald-300 inline-flex items-center gap-1"
          >
            <span>View All</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        {loading ? (
          <div className="p-8 text-center text-sm text-slate-400">Loading scans...</div>
        ) : recentScans.length === 0 ? (
          <div className="p-12 text-center">
            <FileCode className="w-8 h-8 text-slate-600 mx-auto mb-2" />
            <p className="text-sm font-semibold text-slate-300">No scans recorded yet</p>
            <p className="text-xs text-slate-500 mt-1">Upload a zip or inspect a GitHub repository to begin.</p>
            <Link
              href="/scan"
              className="mt-4 inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold rounded-lg bg-emerald-500 text-slate-950"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Start First Scan</span>
            </Link>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-xs font-mono text-slate-400">
                  <th className="py-3 px-4 font-medium">ID</th>
                  <th className="py-3 px-4 font-medium">Source</th>
                  <th className="py-3 px-4 font-medium">Status</th>
                  <th className="py-3 px-4 font-medium">Risk Score</th>
                  <th className="py-3 px-4 font-medium text-right">Findings</th>
                  <th className="py-3 px-4 font-medium text-right">Date</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-xs font-mono">
                {recentScans.map((scan) => (
                  <tr
                    key={scan.id}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                    onClick={() => (window.location.href = `/scans/${scan.id}`)}
                  >
                    <td className="py-3 px-4 text-slate-400 font-semibold">#{scan.id}</td>
                    <td className="py-3 px-4 text-slate-200 font-mono truncate max-w-xs sm:max-w-md">
                      <Link href={`/scans/${scan.id}`} className="hover:underline">
                        {scan.source}
                      </Link>
                    </td>
                    <td className="py-3 px-4">
                      <StatusBadge status={scan.status} size="sm" />
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`font-bold ${
                          scan.risk_score >= 70
                            ? "text-rose-400"
                            : scan.risk_score >= 40
                            ? "text-amber-400"
                            : scan.risk_score >= 15
                            ? "text-sky-400"
                            : "text-emerald-400"
                        }`}
                      >
                        {scan.risk_score}/100
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right text-slate-300 tabular-nums">
                      {scan.findings_count}
                    </td>
                    <td className="py-3 px-4 text-right text-slate-400 tabular-nums">
                      {new Date(scan.created_at).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
