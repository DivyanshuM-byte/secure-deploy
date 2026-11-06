"use client";

import React, { useEffect, useState, useRef } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import {
  ShieldAlert,
  ShieldCheck,
  Server,
  Play,
  Square,
  RefreshCw,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Terminal,
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  XCircle,
  Loader2,
  Clock,
  Layers,
  FileCode,
  Key,
  Lock,
  Trash2,
  Plus,
  EyeOff,
  Shield,
  Search,
} from "lucide-react";
import {
  fetchScan,
  triggerDeploy,
  fetchDeployment,
  stopDeployment,
  fetchSecrets,
  putSecret,
  deleteSecret,
  fetchProbeResults,
  rerunProbe,
  ScanDetail,
  Deployment,
  SecretMetadata,
  ProbeResultResponse,
  getReportDownloadUrl,
  getHowToFixHint,
} from "@/lib/api";
import { StatusBadge } from "@/components/StatusBadge";
import { SeverityChip } from "@/components/SeverityChip";
import { CircularGauge } from "@/components/CircularGauge";

export default function ScanReportPage() {
  const params = useParams();
  const scanId = params?.id as string;

  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Deployment state
  const [deployment, setDeployment] = useState<Deployment | null>(null);
  const [deploying, setDeploying] = useState(false);
  const [deployError, setDeployError] = useState<string | null>(null);
  const [showLogs, setShowLogs] = useState(true);
  const [stopping, setStopping] = useState(false);
  const [projectSlug, setProjectSlug] = useState("");

  // Secrets Panel state
  const [activeSecretsSlug, setActiveSecretsSlug] = useState("production");
  const [secrets, setSecrets] = useState<SecretMetadata[]>([]);
  const [secretsLoading, setSecretsLoading] = useState(false);
  const [secretsMsg, setSecretsMsg] = useState<{ type: "success" | "error"; text: string } | null>(null);
  const [newSecretName, setNewSecretName] = useState("");
  const secretValueInputRef = useRef<HTMLInputElement>(null);

  // Probe state
  const [probeResult, setProbeResult] = useState<ProbeResultResponse | null>(null);
  const [probeLoading, setProbeLoading] = useState(false);

  const logsEndRef = useRef<HTMLDivElement>(null);

  // Load scan details
  const loadScan = async () => {
    if (!scanId) return;
    try {
      const data = await fetchScan(scanId);
      setScan(data);
    } catch (err: any) {
      setError(err?.message || `Failed to load scan #${scanId}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadScan();
  }, [scanId]);

  // Load secrets for active project slug
  const loadSecretsForSlug = async (slug: string) => {
    if (!slug) return;
    setSecretsLoading(true);
    try {
      const list = await fetchSecrets(slug);
      setSecrets(list);
    } catch {
      setSecrets([]);
    } finally {
      setSecretsLoading(false);
    }
  };

  useEffect(() => {
    if (activeSecretsSlug) {
      loadSecretsForSlug(activeSecretsSlug);
    }
  }, [activeSecretsSlug]);

  // Load probe results when deployment changes
  const loadProbe = async (depId: number) => {
    try {
      const res = await fetchProbeResults(depId);
      if (res && res.items && res.items.length > 0) {
        setProbeResult(res);
      }
    } catch {
      // Probe might not have run yet
    }
  };

  // Deployment polling (every 2s while in progress)
  useEffect(() => {
    if (!deployment) return;
    if (["deployed", "exposed", "failed", "stopped"].includes(deployment.status)) {
      loadProbe(deployment.id);
      return;
    }

    const interval = setInterval(async () => {
      try {
        const updated = await fetchDeployment(deployment.id);
        setDeployment(updated);
        if (["probing", "deployed", "exposed"].includes(updated.status)) {
          loadProbe(updated.id);
        }
        if (logsEndRef.current) {
          logsEndRef.current.scrollIntoView({ behavior: "smooth" });
        }
      } catch (err) {
        console.error("Polling deployment error:", err);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [deployment?.id, deployment?.status]);

  // Trigger deploy
  const handleDeploy = async () => {
    if (!scan || scan.status !== "passed") return;
    setDeploying(true);
    setDeployError(null);
    try {
      const slugToSend = projectSlug.trim() ? projectSlug.trim() : undefined;
      const dep = await triggerDeploy(scan.id, slugToSend);
      setDeployment(dep);
      if (slugToSend) {
        setActiveSecretsSlug(slugToSend);
      }
    } catch (err: any) {
      setDeployError(err?.message || "Failed to trigger deployment.");
    } finally {
      setDeploying(false);
    }
  };

  // Stop active deployment
  const handleStop = async () => {
    if (!deployment) return;
    setStopping(true);
    try {
      const stopped = await stopDeployment(deployment.id);
      setDeployment(stopped);
    } catch (err: any) {
      alert(err?.message || "Failed to stop deployment");
    } finally {
      setStopping(false);
    }
  };

  // Re-run probe on demand
  const handleRerunProbe = async () => {
    if (!deployment) return;
    setProbeLoading(true);
    try {
      const res = await rerunProbe(deployment.id);
      setProbeResult(res);
      const updated = await fetchDeployment(deployment.id);
      setDeployment(updated);
    } catch (err: any) {
      alert(err?.message || "Failed to re-run probe");
    } finally {
      setProbeLoading(false);
    }
  };

  // Add a secret (write-only, value never kept in state)
  const handleAddSecret = async (e: React.FormEvent) => {
    e.preventDefault();
    setSecretsMsg(null);
    const name = newSecretName.trim().toUpperCase();
    const value = secretValueInputRef.current?.value || "";

    if (!name || !value) {
      setSecretsMsg({ type: "error", text: "Please enter both secret name and value" });
      return;
    }

    try {
      await putSecret(activeSecretsSlug, name, value);
      // Immediately clear the input DOM value and never retain in state
      if (secretValueInputRef.current) {
        secretValueInputRef.current.value = "";
      }
      setNewSecretName("");
      setSecretsMsg({ type: "success", text: `Secret ${name} safely stored (write-only)` });
      loadSecretsForSlug(activeSecretsSlug);
    } catch (err: any) {
      setSecretsMsg({ type: "error", text: err?.message || "Failed to save secret" });
    }
  };

  // Delete a secret
  const handleDeleteSecret = async (name: string) => {
    if (!confirm(`Are you sure you want to delete secret ${name}?`)) return;
    try {
      await deleteSecret(activeSecretsSlug, name);
      loadSecretsForSlug(activeSecretsSlug);
    } catch (err: any) {
      alert(err?.message || "Failed to delete secret");
    }
  };

  if (loading) {
    return (
      <div className="py-20 text-center">
        <Loader2 className="w-8 h-8 animate-spin mx-auto text-emerald-400 mb-4" />
        <p className="text-sm text-slate-400">Loading scan report #{scanId}...</p>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="py-12 space-y-4">
        <div className="p-5 rounded-xl border border-red-900/50 bg-red-950/20 text-red-400 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 flex-shrink-0" />
          <span>{error || "Scan not found"}</span>
        </div>
        <Link
          href="/scans"
          className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-white"
        >
          <ArrowLeft className="w-4 h-4" /> Back to Scans
        </Link>
      </div>
    );
  }

  const isPassed = scan.status === "passed";
  const isBlocked = scan.status === "blocked";
  const isFailed = scan.status === "failed";

  // Stepper helper: Build -> Deploy -> Probe -> Live
  const getStepStatus = (step: "build" | "deploy" | "probe" | "live") => {
    if (!deployment) return "pending";
    const st = deployment.status;
    if (st === "failed") return "failed";

    if (step === "build") {
      if (st === "building") return "active";
      if (["deploying", "probing", "deployed", "exposed"].includes(st)) return "completed";
      return "pending";
    }
    if (step === "deploy") {
      if (st === "deploying") return "active";
      if (["probing", "deployed", "exposed"].includes(st)) return "completed";
      return "pending";
    }
    if (step === "probe") {
      if (st === "probing") return "active";
      if (st === "exposed") return "failed";
      if (st === "deployed") return "completed";
      return "pending";
    }
    if (step === "live") {
      if (st === "deployed") return "completed";
      if (st === "exposed") return "failed";
      return "pending";
    }
    return "pending";
  };

  return (
    <div className="space-y-8">
      {/* Back Link */}
      <div>
        <Link
          href="/"
          className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" /> Back to Dashboard
        </Link>
      </div>

      {/* Header Bar */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white flex items-center gap-2.5">
              {isPassed ? (
                <ShieldCheck className="w-8 h-8 text-emerald-400" />
              ) : (
                <ShieldAlert className="w-8 h-8 text-red-400" />
              )}
              Scan Report #{scan.id}
            </h1>
            <StatusBadge status={scan.status} />
          </div>
          <p className="text-xs font-mono text-slate-400 mt-2 truncate max-w-xl">
            Target Source: {scan.source}
          </p>
        </div>

        {/* Deploy & Export Actions */}
        <div className="flex flex-wrap items-center gap-3">
          <a
            href={getReportDownloadUrl(scan.id)}
            download
            className="px-3.5 py-2 text-xs font-semibold rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-slate-200 transition-colors inline-flex items-center gap-1.5"
          >
            Export JSON
          </a>

          {/* Optional Project Slug Input for Secrets injection */}
          {isPassed && !deployment && (
            <input
              type="text"
              placeholder="Project slug (optional)"
              value={projectSlug}
              onChange={(e) => setProjectSlug(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""))}
              className="px-3 py-2 text-xs bg-slate-900 border border-slate-700 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 w-44 font-mono"
            />
          )}

          {/* Deploy Button */}
          {isPassed ? (
            <button
              onClick={handleDeploy}
              disabled={deploying || (deployment !== null && ["pending", "building", "deploying", "probing"].includes(deployment.status))}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-bold rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 transition-colors shadow-lg shadow-emerald-500/20 disabled:opacity-50"
            >
              {deploying ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Initiating Build...</span>
                </>
              ) : (
                <>
                  <Server className="w-4 h-4" />
                  <span>Deploy this project</span>
                </>
              )}
            </button>
          ) : (
            <div className="relative group">
              <button
                disabled
                className="inline-flex items-center gap-2 px-4 py-2 text-xs font-bold rounded-lg bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700/50"
              >
                <Server className="w-4 h-4" />
                <span>Deploy this project</span>
              </button>
              <div className="absolute right-0 bottom-full mb-2 hidden group-hover:flex flex-col items-center z-50">
                <div className="bg-red-950 text-red-200 text-xs rounded-lg py-1.5 px-3 border border-red-800 whitespace-nowrap shadow-xl">
                  {isBlocked
                    ? "Deployment blocked: Critical vulnerabilities or sensitive credentials detected"
                    : `Deployment disabled: scan status is ${scan.status}`}
                </div>
                <div className="w-2 h-2 bg-red-950 border-r border-b border-red-800 rotate-45 -mt-1" />
              </div>
            </div>
          )}
        </div>
      </div>

      {deployError && (
        <div className="p-4 rounded-xl border border-red-900/50 bg-red-950/20 text-red-400 text-sm flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 flex-shrink-0" />
          <span>{deployError}</span>
        </div>
      )}

      {/* Deployment Stepper & Monitor */}
      {deployment && (
        <div className="bg-[#0B101E] border border-emerald-500/30 rounded-xl p-6 shadow-2xl space-y-6">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="flex items-center gap-2.5">
              <Server className="w-5 h-5 text-emerald-400" />
              <h2 className="text-base font-semibold text-white">
                Deployment Pipeline (#{deployment.id} &bull; {deployment.container_name})
              </h2>
              {deployment.project && (
                <span className="px-2 py-0.5 rounded text-xs font-mono bg-sky-500/10 text-sky-400 border border-sky-500/30">
                  project: {deployment.project}
                </span>
              )}
            </div>
            {deployment.status === "deployed" && deployment.url && (
              <div className="flex items-center gap-2">
                <a
                  href={deployment.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 text-xs font-bold transition-colors shadow-md"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  <span>Open Live App ({deployment.url})</span>
                </a>
                <button
                  onClick={handleStop}
                  disabled={stopping}
                  className="px-3 py-1.5 text-xs font-semibold rounded-lg border border-red-900/60 bg-red-950/50 hover:bg-red-900/50 text-red-300 inline-flex items-center gap-1 transition-colors"
                >
                  <Square className="w-3.5 h-3.5" />
                  <span>{stopping ? "Stopping..." : "Stop"}</span>
                </button>
              </div>
            )}
          </div>

          {/* Stepper (Build -> Deploy -> Probe -> Live) */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {/* Step 1: Build */}
            <div
              className={`p-3.5 rounded-lg border flex items-center gap-3 transition-colors ${
                getStepStatus("build") === "completed"
                  ? "bg-emerald-500/10 border-emerald-500/40 text-emerald-400"
                  : getStepStatus("build") === "active"
                  ? "bg-sky-500/10 border-sky-500/40 text-sky-400"
                  : getStepStatus("build") === "failed"
                  ? "bg-red-500/10 border-red-500/40 text-red-400"
                  : "bg-slate-900/40 border-slate-800 text-slate-500"
              }`}
            >
              {getStepStatus("build") === "completed" ? (
                <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0" />
              ) : getStepStatus("build") === "active" ? (
                <Loader2 className="w-5 h-5 animate-spin text-sky-400 flex-shrink-0" />
              ) : (
                <div className="w-5 h-5 rounded-full border border-current flex items-center justify-center text-xs font-bold">1</div>
              )}
              <div>
                <div className="text-xs font-bold uppercase tracking-wider">Step 1: Build</div>
                <div className="text-xs opacity-80">Hardened Image & Lint</div>
              </div>
            </div>

            {/* Step 2: Deploy */}
            <div
              className={`p-3.5 rounded-lg border flex items-center gap-3 transition-colors ${
                getStepStatus("deploy") === "completed"
                  ? "bg-emerald-500/10 border-emerald-500/40 text-emerald-400"
                  : getStepStatus("deploy") === "active"
                  ? "bg-sky-500/10 border-sky-500/40 text-sky-400"
                  : getStepStatus("deploy") === "failed"
                  ? "bg-red-500/10 border-red-500/40 text-red-400"
                  : "bg-slate-900/40 border-slate-800 text-slate-500"
              }`}
            >
              {getStepStatus("deploy") === "completed" ? (
                <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0" />
              ) : getStepStatus("deploy") === "active" ? (
                <Loader2 className="w-5 h-5 animate-spin text-sky-400 flex-shrink-0" />
              ) : (
                <div className="w-5 h-5 rounded-full border border-current flex items-center justify-center text-xs font-bold">2</div>
              )}
              <div>
                <div className="text-xs font-bold uppercase tracking-wider">Step 2: Deploy</div>
                <div className="text-xs opacity-80">Runtime Secrets Injection</div>
              </div>
            </div>

            {/* Step 3: Probe */}
            <div
              className={`p-3.5 rounded-lg border flex items-center gap-3 transition-colors ${
                getStepStatus("probe") === "completed"
                  ? "bg-emerald-500/10 border-emerald-500/40 text-emerald-400"
                  : getStepStatus("probe") === "active"
                  ? "bg-amber-500/10 border-amber-500/40 text-amber-400"
                  : getStepStatus("probe") === "failed"
                  ? "bg-red-500/10 border-red-500/40 text-red-400"
                  : "bg-slate-900/40 border-slate-800 text-slate-500"
              }`}
            >
              {getStepStatus("probe") === "completed" ? (
                <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0" />
              ) : getStepStatus("probe") === "active" ? (
                <Loader2 className="w-5 h-5 animate-spin text-amber-400 flex-shrink-0" />
              ) : getStepStatus("probe") === "failed" ? (
                <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
              ) : (
                <div className="w-5 h-5 rounded-full border border-current flex items-center justify-center text-xs font-bold">3</div>
              )}
              <div>
                <div className="text-xs font-bold uppercase tracking-wider">Step 3: Probe</div>
                <div className="text-xs opacity-80">Post-Deploy Exposure Audit</div>
              </div>
            </div>

            {/* Step 4: Live */}
            <div
              className={`p-3.5 rounded-lg border flex items-center gap-3 transition-colors ${
                getStepStatus("live") === "completed"
                  ? "bg-emerald-500/10 border-emerald-500/40 text-emerald-400"
                  : getStepStatus("live") === "failed"
                  ? "bg-red-500/10 border-red-500/40 text-red-400"
                  : "bg-slate-900/40 border-slate-800 text-slate-500"
              }`}
            >
              {getStepStatus("live") === "completed" ? (
                <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0" />
              ) : (
                <div className="w-5 h-5 rounded-full border border-current flex items-center justify-center text-xs font-bold">4</div>
              )}
              <div>
                <div className="text-xs font-bold uppercase tracking-wider">Step 4: Live</div>
                <div className="text-xs opacity-80">Nginx Reverse Proxy Active</div>
              </div>
            </div>
          </div>

          {/* Security Probe Card */}
          {probeResult && (
            <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-950/70 p-5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <Shield className="w-5 h-5 text-sky-400" />
                  <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                    Post-Deploy Security Probe Audit
                  </h3>
                </div>
                <button
                  onClick={handleRerunProbe}
                  disabled={probeLoading}
                  className="px-3 py-1.5 text-xs font-semibold rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-200 inline-flex items-center gap-1.5 transition-colors self-start sm:self-auto"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${probeLoading ? "animate-spin" : ""}`} />
                  <span>Re-run probe</span>
                </button>
              </div>

              {/* Overall Banner */}
              {probeResult.overall_verdict === "exposed" ? (
                <div className="p-4 rounded-lg bg-red-950/50 border border-red-800 text-red-300 flex items-center gap-3">
                  <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
                  <div>
                    <div className="font-bold text-sm">EXPOSED, container stopped</div>
                    <div className="text-xs text-red-400 mt-0.5">
                      {probeResult.exposed_count} sensitive endpoint(s) publicly exposed. Container automatically stopped per AUTO_STOP_ON_EXPOSURE policy.
                    </div>
                  </div>
                </div>
              ) : probeResult.overall_verdict === "warning" ? (
                <div className="p-4 rounded-lg bg-amber-950/40 border border-amber-800 text-amber-300 flex items-center gap-3">
                  <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0" />
                  <div>
                    <div className="font-bold text-sm">Security Warnings Detected</div>
                    <div className="text-xs text-amber-400 mt-0.5">
                      No sensitive files exposed, but {probeResult.warning_count} security header warning(s) were flagged.
                    </div>
                  </div>
                </div>
              ) : (
                <div className="p-4 rounded-lg bg-emerald-950/40 border border-emerald-800 text-emerald-300 flex items-center gap-3">
                  <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0" />
                  <div>
                    <div className="font-bold text-sm">No exposure detected</div>
                    <div className="text-xs text-emerald-400 mt-0.5">
                      All sensitive files, git metadata, and backup artifacts are safely unreachable.
                    </div>
                  </div>
                </div>
              )}

              {/* Probed Paths Table */}
              <div className="overflow-x-auto max-h-64 border border-slate-800 rounded-lg">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] tracking-wider sticky top-0">
                    <tr>
                      <th className="px-3.5 py-2">Probed Path / Header</th>
                      <th className="px-3.5 py-2">HTTP Status</th>
                      <th className="px-3.5 py-2">Verdict</th>
                      <th className="px-3.5 py-2">Audit Note</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-300">
                    {probeResult.items.map((item, idx) => (
                      <tr key={idx} className="hover:bg-slate-900/30">
                        <td className="px-3.5 py-2 text-slate-200 font-semibold">{item.path}</td>
                        <td className="px-3.5 py-2 text-slate-400">{item.status ?? "None"}</td>
                        <td className="px-3.5 py-2">
                          {item.verdict === "exposed" ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/40">
                              EXPOSED
                            </span>
                          ) : item.verdict === "warning" ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/40">
                              WARNING
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
                              SAFE
                            </span>
                          )}
                        </td>
                        <td className="px-3.5 py-2 text-slate-400 font-sans text-xs">{item.note}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Collapsible Logs Viewer */}
          <div className="border border-slate-800 rounded-lg overflow-hidden bg-black/60">
            <button
              onClick={() => setShowLogs(!showLogs)}
              className="w-full flex items-center justify-between px-4 py-2.5 bg-slate-900/60 hover:bg-slate-900 text-xs font-semibold text-slate-300 transition-colors"
            >
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-emerald-400" />
                <span>Deployment Logs (Monospace, Sanitized & Redacted)</span>
              </div>
              {showLogs ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>
            {showLogs && (
              <div className="p-4 max-h-64 overflow-y-auto font-mono text-xs text-slate-300 whitespace-pre-wrap leading-relaxed border-t border-slate-800/80">
                {deployment.logs || "Awaiting build output..."}
                <div ref={logsEndRef} />
              </div>
            )}
          </div>
        </div>
      )}

      {/* Secrets Management Panel - hidden for failed scans */}
      {!isFailed && (
        <div className="bg-[#0B101E] border border-slate-800 rounded-xl p-6 shadow-xl space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
            <div className="flex items-center gap-2.5">
              <Key className="w-5 h-5 text-amber-400" />
              <div>
                <h2 className="text-base font-bold text-white">Project Secrets Manager</h2>
                <p className="text-xs text-slate-400">
                  Encrypted at rest (Fernet/AWS SSM) and injected via isolated runtime env-files.
                </p>
              </div>
            </div>
            {/* Project slug selector */}
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400">Project Slug:</span>
              <input
                type="text"
                value={activeSecretsSlug}
                onChange={(e) => setActiveSecretsSlug(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""))}
                placeholder="e.g. production"
                className="px-2.5 py-1 text-xs bg-slate-900 border border-slate-700 rounded text-slate-200 font-mono w-36 focus:outline-none focus:border-amber-400"
              />
            </div>
          </div>

          {/* Notice: Write-only */}
          <div className="text-xs text-slate-400 flex items-center gap-2 bg-slate-900/50 p-2.5 rounded-lg border border-slate-800/80">
            <EyeOff className="w-4 h-4 text-slate-500 flex-shrink-0" />
            <span>Values are write-only and cannot be viewed again.</span>
          </div>

          {secretsMsg && (
            <div
              className={`p-3 rounded-lg text-xs font-semibold flex items-center gap-2 ${
                secretsMsg.type === "success"
                  ? "bg-emerald-950/40 text-emerald-400 border border-emerald-800"
                  : "bg-red-950/40 text-red-400 border border-red-800"
              }`}
            >
              {secretsMsg.type === "success" ? <CheckCircle2 className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
              <span>{secretsMsg.text}</span>
            </div>
          )}

          {/* Add Secret Form */}
          <form onSubmit={handleAddSecret} className="grid grid-cols-1 sm:grid-cols-12 gap-3 items-end">
            <div className="sm:col-span-4">
              <label className="block text-[11px] font-semibold uppercase text-slate-400 mb-1">
                Secret Name
              </label>
              <input
                type="text"
                placeholder="e.g. DATABASE_PASSWORD"
                value={newSecretName}
                onChange={(e) => setNewSecretName(e.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, ""))}
                className="w-full px-3 py-2 text-xs bg-slate-900 border border-slate-700 rounded-lg text-slate-200 font-mono focus:outline-none focus:border-amber-400"
                required
              />
            </div>
            <div className="sm:col-span-5">
              <label className="block text-[11px] font-semibold uppercase text-slate-400 mb-1">
                Secret Value
              </label>
              <input
                ref={secretValueInputRef}
                type="password"
                autoComplete="off"
                placeholder="••••••••••••••••"
                className="w-full px-3 py-2 text-xs bg-slate-900 border border-slate-700 rounded-lg text-slate-200 font-mono focus:outline-none focus:border-amber-400"
                required
              />
            </div>
            <div className="sm:col-span-3">
              <button
                type="submit"
                className="w-full inline-flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-bold rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 transition-colors shadow-md"
              >
                <Plus className="w-4 h-4" />
                <span>Store Secret</span>
              </button>
            </div>
          </form>

          {/* Secrets List Table */}
          <div className="border border-slate-800 rounded-lg overflow-hidden">
            {secretsLoading ? (
              <div className="py-8 text-center text-xs text-slate-500 flex items-center justify-center gap-2">
                <Loader2 className="w-4 h-4 animate-spin text-amber-400" />
                <span>Loading project secrets...</span>
              </div>
            ) : secrets.length === 0 ? (
              <div className="py-8 text-center text-xs text-slate-500">
                No secrets configured for project <span className="font-mono text-slate-400">"{activeSecretsSlug}"</span>. Add your first secret above.
              </div>
            ) : (
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] tracking-wider">
                  <tr>
                    <th className="px-4 py-2.5">Name</th>
                    <th className="px-4 py-2.5">Masked Value</th>
                    <th className="px-4 py-2.5">Updated</th>
                    <th className="px-4 py-2.5 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {secrets.map((sec) => (
                    <tr key={sec.name} className="hover:bg-slate-900/30">
                      <td className="px-4 py-2.5 font-bold text-amber-400">{sec.name}</td>
                      <td className="px-4 py-2.5 text-slate-500">{sec.masked}</td>
                      <td className="px-4 py-2.5 text-slate-500 text-[11px]">
                        {sec.updated_at ? new Date(sec.updated_at).toLocaleString() : "Never"}
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        <button
                          onClick={() => handleDeleteSecret(sec.name)}
                          className="p-1 rounded text-slate-500 hover:text-red-400 hover:bg-red-950/40 transition-colors"
                          title="Delete secret"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* Risk & Summary Cards */}
      {isFailed ? (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Neutral / Amber Failure Card (spans 2 columns on desktop) */}
          <div className="md:col-span-2 bg-[#0B101E] border border-amber-500/40 rounded-xl p-6 shadow-lg flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-2.5 text-amber-400 font-bold text-base">
                <AlertTriangle className="w-5 h-5 flex-shrink-0 text-amber-400" />
                <span>Scan failed - this code was NOT scanned</span>
              </div>
              <p className="mt-3 text-xs sm:text-sm text-slate-300 font-mono bg-black/40 p-3.5 rounded-lg border border-slate-800 break-words">
                {scan.blocked_reason || "Repository could not be cloned or scanned."}
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-slate-800/80 text-xs text-amber-400/90 font-medium">
              Deployment is blocked until a scan succeeds.
            </div>
          </div>

          {/* Red BLOCKED gate */}
          <div className="bg-[#0B101E] border border-slate-800 rounded-xl p-6 shadow-lg flex flex-col justify-between">
            <div className="text-xs uppercase tracking-wider text-slate-400 font-semibold">Deployment Gate</div>
            <div className="mt-2">
              <span className="text-red-400 text-lg font-bold flex items-center gap-1.5">
                <XCircle className="w-5 h-5 flex-shrink-0" /> BLOCKED (Deployment Prohibited)
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-2 font-mono truncate">
              {scan.blocked_reason || "Deployment prohibited: scan failed."}
            </p>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Risk Score Gauge */}
          <div className="bg-[#0B101E] border border-slate-800 rounded-xl p-6 flex items-center justify-between shadow-lg">
            <div>
              <div className="text-xs uppercase tracking-wider text-slate-400 font-semibold">Risk Score</div>
              <div className="text-2xl font-bold text-white mt-1 capitalize">{scan.risk_level} Risk</div>
              <p className="text-xs text-slate-500 mt-1 max-w-[200px]">
                Calculated using weighted severity analysis of detected findings.
              </p>
            </div>
            <CircularGauge score={scan.risk_score} size={84} strokeWidth={8} />
          </div>

          {/* Findings Count */}
          <div className="bg-[#0B101E] border border-slate-800 rounded-xl p-6 shadow-lg flex flex-col justify-between">
            <div className="text-xs uppercase tracking-wider text-slate-400 font-semibold">Total Findings</div>
            <div className="text-3xl font-bold text-white mt-2">{scan.findings.length}</div>
            <p className="text-xs text-slate-500 mt-2">
              {scan.findings.length === 0
                ? "Zero security anomalies found. Code approved for deployment."
                : `${scan.findings.length} sensitive patterns detected in source code.`}
            </p>
          </div>

          {/* Scan Status */}
          <div className="bg-[#0B101E] border border-slate-800 rounded-xl p-6 shadow-lg flex flex-col justify-between">
            <div className="text-xs uppercase tracking-wider text-slate-400 font-semibold">Deployment Gate</div>
            <div className="mt-2">
              {isPassed ? (
                <span className="text-emerald-400 text-lg font-bold flex items-center gap-1.5">
                  <CheckCircle2 className="w-5 h-5" /> PASSED (Safe to Deploy)
                </span>
              ) : (
                <span className="text-red-400 text-lg font-bold flex items-center gap-1.5">
                  <XCircle className="w-5 h-5" /> BLOCKED (Deployment Prohibited)
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500 mt-2 font-mono truncate">
              {scan.blocked_reason || "All security rules and policies satisfied."}
            </p>
          </div>
        </div>
      )}

      {/* Findings Table - hidden for failed scans since code was not scanned */}
      {!isFailed && (
        <div className="bg-[#0B101E] border border-slate-800 rounded-xl overflow-hidden shadow-xl">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <FileCode className="w-4 h-4 text-emerald-400" />
              Detected Findings ({scan.findings.length})
            </h3>
          </div>
          {scan.findings.length === 0 ? (
            <div className="py-12 text-center text-slate-500 text-sm">
              <ShieldCheck className="w-10 h-10 mx-auto text-emerald-400/40 mb-2" />
              No secrets, sensitive files, or PII detected. Clean project!
            </div>
          ) : (
            <div className="divide-y divide-slate-800/60 font-mono text-xs">
              {scan.findings.map((finding) => (
                <div key={finding.id} className="p-4 hover:bg-slate-900/30 transition-colors">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2.5 font-sans">
                      <SeverityChip severity={finding.severity} />
                      <span className="font-semibold text-slate-200">{finding.type}</span>
                      <span className="text-slate-500 text-xs">
                        {finding.file}:{finding.line}
                      </span>
                    </div>
                  </div>
                  <div className="mt-2.5 p-2.5 bg-black/50 rounded-lg text-slate-300 font-mono text-xs border border-slate-800/60">
                    {finding.masked_preview}
                  </div>
                  <div className="mt-2 text-xs text-slate-400 font-sans flex items-start gap-1.5">
                    <span className="text-emerald-400 font-semibold">Remediation:</span>
                    <span>{getHowToFixHint(finding.type)}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
