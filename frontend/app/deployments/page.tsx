"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  Server,
  RefreshCw,
  ExternalLink,
  Square,
  Terminal,
  Clock,
  ArrowRight,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Loader2,
  AlertTriangle,
} from "lucide-react";
import { fetchDeployments, stopDeployment, Deployment } from "@/lib/api";

export default function DeploymentsPage() {
  const [deployments, setDeployments] = useState<Deployment[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedLogs, setSelectedLogs] = useState<{ id: number; logs: string; name: string } | null>(null);
  const [stoppingId, setStoppingId] = useState<number | null>(null);

  const loadDeployments = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchDeployments();
      setDeployments(data);
    } catch (err: any) {
      setError(err?.message || "Failed to load deployments");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDeployments();
    const interval = setInterval(loadDeployments, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleStop = async (id: number) => {
    setStoppingId(id);
    try {
      const updated = await stopDeployment(id);
      setDeployments((prev) => prev.map((d) => (d.id === id ? updated : d)));
    } catch (err: any) {
      alert(err?.message || "Failed to stop deployment");
    } finally {
      setStoppingId(null);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "deployed":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-3.5 h-3.5" /> Deployed
          </span>
        );
      case "exposed":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-red-500/10 text-red-400 border border-red-500/30">
            <AlertTriangle className="w-3.5 h-3.5" /> Exposed
          </span>
        );
      case "probing":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <Loader2 className="w-3.5 h-3.5 animate-spin" /> Probing
          </span>
        );
      case "failed":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-red-500/10 text-red-400 border border-red-500/30">
            <XCircle className="w-3.5 h-3.5" /> Failed
          </span>
        );
      case "stopped":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-500/10 text-slate-400 border border-slate-700">
            <Square className="w-3 h-3" /> Stopped
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-sky-500/10 text-sky-400 border border-sky-500/30">
            <Loader2 className="w-3.5 h-3.5 animate-spin" /> {status}
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white flex items-center gap-3">
            <Server className="w-7 h-7 text-emerald-400" />
            Active Deployments
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Hardened Docker container instances running on isolated loopback ports with Nginx reverse proxying.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadDeployments}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-800 bg-[#0D1322] hover:bg-slate-800 text-slate-300 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl border border-red-900/50 bg-red-950/20 text-red-400 text-sm flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Deployments Table */}
      <div className="bg-[#0B101E] border border-slate-800/80 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-[#0D1424] text-xs uppercase font-medium text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Deployment</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Host Target</th>
                <th className="py-3 px-4">Port / URL</th>
                <th className="py-3 px-4">Scan Reference</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
              {loading && deployments.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500 font-sans">
                    Loading deployment pipeline records...
                  </td>
                </tr>
              ) : deployments.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-16 text-center text-slate-500 font-sans">
                    <Server className="w-10 h-10 mx-auto mb-3 opacity-30 text-slate-400" />
                    <p className="text-sm font-medium text-slate-400">No active deployments found</p>
                    <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
                      Only scans that pass DevSecOps inspection can be deployed. Run a scan to initiate a safe deployment.
                    </p>
                    <Link
                      href="/scan"
                      className="inline-flex items-center gap-1.5 mt-4 px-4 py-2 text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 text-slate-950 rounded-lg transition-colors"
                    >
                      Start Scan & Deploy
                    </Link>
                  </td>
                </tr>
              ) : (
                deployments.map((dep) => (
                  <tr key={dep.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3.5 px-4 font-sans">
                      <div className="font-semibold text-slate-200">{dep.container_name}</div>
                      <div className="text-xs text-slate-500 font-mono mt-0.5">{dep.image_tag}</div>
                    </td>
                    <td className="py-3.5 px-4 font-sans">{getStatusBadge(dep.status)}</td>
                    <td className="py-3.5 px-4">
                      <span className="uppercase text-[11px] font-bold tracking-wider px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                        {dep.host_type}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      {dep.url ? (
                        <a
                          href={dep.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-emerald-400 hover:underline inline-flex items-center gap-1"
                        >
                          {dep.url}
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      ) : (
                        <span className="text-slate-600">Pending</span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 font-sans">
                      <Link
                        href={`/scans/${dep.scan_id}`}
                        className="text-slate-400 hover:text-emerald-400 transition-colors inline-flex items-center gap-1 text-xs"
                      >
                        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                        Scan #{dep.scan_id}
                      </Link>
                    </td>
                    <td className="py-3.5 px-4 text-right font-sans">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => setSelectedLogs({ id: dep.id, logs: dep.logs, name: dep.container_name })}
                          className="px-2.5 py-1 text-xs rounded border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-slate-300 inline-flex items-center gap-1 transition-colors"
                        >
                          <Terminal className="w-3 h-3" />
                          Logs
                        </button>
                        {dep.status === "deployed" && (
                          <button
                            onClick={() => handleStop(dep.id)}
                            disabled={stoppingId === dep.id}
                            className="px-2.5 py-1 text-xs rounded border border-red-900/60 bg-red-950/40 hover:bg-red-900/50 text-red-300 inline-flex items-center gap-1 transition-colors"
                          >
                            <Square className="w-3 h-3" />
                            {stoppingId === dep.id ? "Stopping..." : "Stop"}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Logs Modal */}
      {selectedLogs && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0B101E] border border-slate-800 rounded-xl max-w-3xl w-full max-h-[80vh] flex flex-col shadow-2xl">
            <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800">
              <div className="flex items-center gap-2 text-slate-200 font-semibold text-sm">
                <Terminal className="w-4 h-4 text-emerald-400" />
                <span>Logs for {selectedLogs.name} (Deployment #{selectedLogs.id})</span>
              </div>
              <button
                onClick={() => setSelectedLogs(null)}
                className="text-slate-400 hover:text-white text-xs px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 transition-colors"
              >
                Close
              </button>
            </div>
            <div className="p-4 overflow-y-auto flex-1 bg-black/60 font-mono text-xs text-slate-300 whitespace-pre-wrap leading-relaxed">
              {selectedLogs.logs || "No logs recorded."}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
