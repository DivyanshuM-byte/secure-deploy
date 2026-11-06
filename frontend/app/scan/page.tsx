"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  UploadCloud,
  GitBranch,
  Folder,
  Code2,
  AlertTriangle,
  Loader2,
  FileText,
  X,
  ArrowRight,
  Info,
} from "lucide-react";
import {
  uploadZipScan,
  submitGithubScan,
  submitLocalScan,
  scanSnippet,
  SnippetScanResult,
} from "@/lib/api";
import { SeverityChip } from "@/components/SeverityChip";
import { StatusBadge } from "@/components/StatusBadge";

type TabKey = "zip" | "github" | "local" | "snippet";

const GITHUB_URL_REGEX = /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\.git)?\/?$/;
const MAX_ZIP_BYTES = 25 * 1024 * 1024; // 25 MB
const MAX_SNIPPET_BYTES = 100 * 1024; // 100 KB

const SAMPLE_REPO_CHIPS = [
  "tests/sample-repos/leaky-app",
  "tests/sample-repos/clean-app",
  "tests/sample-repos/pii-app",
  "tests/sample-repos/key-files-app",
];

export default function NewScanPage() {
  const router = useRouter();
  const [activeTab, setActiveTab] = useState<TabKey>("zip");

  // Tab 1: ZIP Upload state
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [zipLoading, setZipLoading] = useState(false);
  const [zipError, setZipError] = useState<string | null>(null);

  // Tab 2: GitHub URL state
  const [githubUrl, setGithubUrl] = useState("");
  const [githubBranch, setGithubBranch] = useState("");
  const [githubLoading, setGithubLoading] = useState(false);
  const [githubError, setGithubError] = useState<string | null>(null);

  // Tab 3: Local Path state
  const [localPath, setLocalPath] = useState("");
  const [localLoading, setLocalLoading] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  // Tab 4: Live Snippet state
  const [snippetContent, setSnippetContent] = useState("");
  const [snippetFilename, setSnippetFilename] = useState("snippet.txt");
  const [snippetLoading, setSnippetLoading] = useState(false);
  const [snippetError, setSnippetError] = useState<string | null>(null);
  const [snippetResult, setSnippetResult] = useState<SnippetScanResult | null>(null);

  // --- Handlers for Tab 1: ZIP Upload ---
  const handleZipSelect = (file: File) => {
    setZipError(null);
    if (!file.name.toLowerCase().endsWith(".zip")) {
      setZipError("Only .zip files are accepted.");
      setZipFile(null);
      return;
    }
    if (file.size > MAX_ZIP_BYTES) {
      setZipError(`File size exceeds 25 MB limit (${(file.size / (1024 * 1024)).toFixed(1)} MB).`);
      setZipFile(null);
      return;
    }
    setZipFile(file);
  };

  const handleZipDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleZipSelect(e.dataTransfer.files[0]);
    }
  };

  const handleZipSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!zipFile) {
      setZipError("Please select a .zip archive first.");
      return;
    }
    setZipLoading(true);
    setZipError(null);
    try {
      const scan = await uploadZipScan(zipFile);
      router.push(`/scans/${scan.id}`);
    } catch (err: any) {
      setZipError(err?.message || "Failed to upload and scan ZIP package.");
    } finally {
      setZipLoading(false);
    }
  };

  // --- Handlers for Tab 2: GitHub Scan ---
  const handleGithubSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setGithubError(null);
    const trimmedUrl = githubUrl.trim();
    if (!trimmedUrl) {
      setGithubError("GitHub repository URL is required.");
      return;
    }
    if (!GITHUB_URL_REGEX.test(trimmedUrl)) {
      setGithubError("Invalid GitHub URL format. Expected: https://github.com/owner/repo");
      return;
    }

    setGithubLoading(true);
    try {
      const scan = await submitGithubScan(trimmedUrl, githubBranch.trim() || undefined);
      router.push(`/scans/${scan.id}`);
    } catch (err: any) {
      setGithubError(err?.message || "Failed to trigger GitHub scan.");
    } finally {
      setGithubLoading(false);
    }
  };

  // --- Handlers for Tab 3: Local Path Scan ---
  const handleLocalSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError(null);
    const trimmedPath = localPath.trim();
    if (!trimmedPath) {
      setLocalError("Local folder path is required.");
      return;
    }

    setLocalLoading(true);
    try {
      const scan = await submitLocalScan(trimmedPath, true);
      router.push(`/scans/${scan.id}`);
    } catch (err: any) {
      setLocalError(err?.message || "Failed to scan local path.");
    } finally {
      setLocalLoading(false);
    }
  };

  // --- Handlers for Tab 4: Live Snippet Scanner ---
  const handleSnippetSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSnippetError(null);
    setSnippetResult(null);

    if (!snippetContent.trim()) {
      setSnippetError("Please enter or paste snippet code to scan.");
      return;
    }

    const byteLen = new Blob([snippetContent]).size;
    if (byteLen > MAX_SNIPPET_BYTES) {
      setSnippetError(`Snippet size (${(byteLen / 1024).toFixed(1)} KB) exceeds 100 KB limit.`);
      return;
    }

    setSnippetLoading(true);
    try {
      const result = await scanSnippet(snippetContent, snippetFilename.trim() || "snippet.txt");
      setSnippetResult(result);
    } catch (err: any) {
      setSnippetError(err?.message || "Snippet scan failed.");
    } finally {
      setSnippetLoading(false);
    }
  };

  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      {/* Header */}
      <div className="pb-6 border-b border-slate-800">
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white flex items-center gap-3">
          <Shield className="w-7 h-7 text-emerald-400" />
          New Security Scan
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Select an ingestion source to analyze code for hardcoded credentials, sensitive PII, and infrastructure keys.
        </p>
      </div>

      {/* Tabs Bar */}
      <div className="flex border-b border-slate-800 space-x-1 sm:space-x-2 overflow-x-auto pb-px">
        <button
          onClick={() => setActiveTab("zip")}
          className={`flex items-center gap-2 py-3 px-4 text-xs sm:text-sm font-medium border-b-2 whitespace-nowrap transition-colors ${
            activeTab === "zip"
              ? "border-emerald-500 text-emerald-400 bg-emerald-500/5"
              : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/30"
          }`}
        >
          <UploadCloud className="w-4 h-4" />
          <span>Upload ZIP</span>
        </button>

        <button
          onClick={() => setActiveTab("github")}
          className={`flex items-center gap-2 py-3 px-4 text-xs sm:text-sm font-medium border-b-2 whitespace-nowrap transition-colors ${
            activeTab === "github"
              ? "border-emerald-500 text-emerald-400 bg-emerald-500/5"
              : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/30"
          }`}
        >
          <GitBranch className="w-4 h-4" />
          <span>GitHub URL</span>
        </button>

        <button
          onClick={() => setActiveTab("local")}
          className={`flex items-center gap-2 py-3 px-4 text-xs sm:text-sm font-medium border-b-2 whitespace-nowrap transition-colors ${
            activeTab === "local"
              ? "border-emerald-500 text-emerald-400 bg-emerald-500/5"
              : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/30"
          }`}
        >
          <Folder className="w-4 h-4" />
          <span>Local Path</span>
        </button>

        <button
          onClick={() => setActiveTab("snippet")}
          className={`flex items-center gap-2 py-3 px-4 text-xs sm:text-sm font-medium border-b-2 whitespace-nowrap transition-colors ${
            activeTab === "snippet"
              ? "border-emerald-500 text-emerald-400 bg-emerald-500/5"
              : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/30"
          }`}
        >
          <Code2 className="w-4 h-4" />
          <span>Live Snippet Scanner</span>
        </button>
      </div>

      {/* Tab 1: Upload ZIP */}
      {activeTab === "zip" && (
        <div className="bg-[#0D1322] border border-slate-800 rounded-xl p-6 space-y-6">
          <div>
            <h2 className="text-base font-semibold text-white">Upload ZIP Package</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Drag and drop an application archive (.zip) up to 25 MB. The bundle will be extracted in a sandboxed directory and scanned.
            </p>
          </div>

          {zipError && (
            <div className="p-4 rounded-lg border border-rose-800/80 bg-rose-950/40 text-rose-300 text-xs sm:text-sm flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400 mt-0.5" />
              <span className="break-all">{zipError}</span>
            </div>
          )}

          <form onSubmit={handleZipSubmit} className="space-y-5">
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setDragActive(true);
              }}
              onDragLeave={(e) => {
                e.preventDefault();
                setDragActive(false);
              }}
              onDrop={handleZipDrop}
              className={`border-2 border-dashed rounded-xl p-8 sm:p-12 text-center transition-all ${
                dragActive
                  ? "border-emerald-500 bg-emerald-950/20"
                  : "border-slate-800 hover:border-slate-700 bg-slate-900/30"
              }`}
            >
              <UploadCloud className="w-12 h-12 mx-auto text-slate-500 mb-3" />
              <div className="text-sm font-medium text-slate-200">
                {zipFile ? (
                  <span className="text-emerald-400 font-semibold">{zipFile.name}</span>
                ) : (
                  <span>Drag and drop your .zip file here, or browse</span>
                )}
              </div>
              <p className="text-xs text-slate-500 mt-1">
                {zipFile
                  ? `${(zipFile.size / (1024 * 1024)).toFixed(2)} MB • Ready to scan`
                  : "ZIP archives only, maximum 25 MB"}
              </p>

              <label className="mt-4 inline-block">
                <input
                  type="file"
                  accept=".zip"
                  onChange={(e) => {
                    if (e.target.files && e.target.files[0]) {
                      handleZipSelect(e.target.files[0]);
                    }
                  }}
                  className="hidden"
                />
                <span className="cursor-pointer inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-lg border border-slate-700 bg-slate-800 text-slate-200 hover:bg-slate-700 transition-colors">
                  {zipFile ? "Choose Different File" : "Select File"}
                </span>
              </label>
            </div>

            <div className="flex justify-end">
              <button
                type="submit"
                disabled={!zipFile || zipLoading}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 disabled:bg-slate-800 disabled:text-slate-500 text-slate-950 transition-colors shadow-sm"
              >
                {zipLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Uploading &amp; Scanning...</span>
                  </>
                ) : (
                  <>
                    <span>Upload &amp; Scan ZIP</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Tab 2: GitHub URL */}
      {activeTab === "github" && (
        <div className="bg-[#0D1322] border border-slate-800 rounded-xl p-6 space-y-6">
          <div>
            <h2 className="text-base font-semibold text-white">GitHub Repository Scan</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Provide a public GitHub repository HTTPS URL. The scanner executes a shallow clone and performs static analysis.
            </p>
          </div>

          <div className="p-3.5 rounded-lg border border-sky-900/60 bg-sky-950/30 text-sky-300 text-xs flex items-start gap-2.5">
            <Info className="w-4 h-4 shrink-0 text-sky-400 mt-0.5" />
            <div>
              <span className="font-semibold">Public Repositories Only:</span> Private repositories, SSH git clone URLs, and personal access tokens are not supported in this gate.
            </div>
          </div>

          {githubError && (
            <div className="p-4 rounded-lg border border-rose-800/80 bg-rose-950/40 text-rose-300 text-xs sm:text-sm flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400 mt-0.5" />
              <span className="break-all">{githubError}</span>
            </div>
          )}

          <form onSubmit={handleGithubSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                GitHub Repository URL <span className="text-rose-400">*</span>
              </label>
              <input
                type="text"
                placeholder="https://github.com/owner/repo"
                value={githubUrl}
                onChange={(e) => setGithubUrl(e.target.value)}
                className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-sm font-mono placeholder:text-slate-600 focus:outline-none focus:border-emerald-500"
              />
              <p className="text-[11px] text-slate-500 mt-1">Must strictly match https://github.com/&lt;owner&gt;/&lt;repo&gt;</p>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Branch or Tag <span className="text-slate-500">(Optional)</span>
              </label>
              <input
                type="text"
                placeholder="main (default)"
                value={githubBranch}
                onChange={(e) => setGithubBranch(e.target.value)}
                className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-sm font-mono placeholder:text-slate-600 focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div className="flex justify-end pt-2">
              <button
                type="submit"
                disabled={githubLoading || !githubUrl.trim()}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 disabled:bg-slate-800 disabled:text-slate-500 text-slate-950 transition-colors shadow-sm"
              >
                {githubLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Cloning &amp; Scanning...</span>
                  </>
                ) : (
                  <>
                    <span>Submit GitHub Scan</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Tab 3: Local Path */}
      {activeTab === "local" && (
        <div className="bg-[#0D1322] border border-slate-800 rounded-xl p-6 space-y-6">
          <div>
            <h2 className="text-base font-semibold text-white">Local Workspace Directory</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Inspect an existing folder within the allowed workspace boundary. Path traversal attempts outside allowed directories will be rejected by the backend gate.
            </p>
          </div>

          {/* Quick-target chips */}
          <div className="space-y-2">
            <span className="text-xs font-medium text-slate-400">Quick-target test fixtures:</span>
            <div className="flex flex-wrap gap-2">
              {SAMPLE_REPO_CHIPS.map((chip) => (
                <button
                  key={chip}
                  type="button"
                  onClick={() => setLocalPath(chip)}
                  className={`text-xs font-mono px-2.5 py-1 rounded-md border transition-colors ${
                    localPath === chip
                      ? "bg-emerald-950/60 border-emerald-500/60 text-emerald-300"
                      : "bg-slate-900 border-slate-800 text-slate-300 hover:border-slate-700 hover:text-white"
                  }`}
                >
                  {chip}
                </button>
              ))}
            </div>
          </div>

          {localError && (
            <div className="p-4 rounded-lg border border-rose-800/80 bg-rose-950/40 text-rose-300 text-xs sm:text-sm flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400 mt-0.5" />
              <div className="space-y-1">
                <div className="font-semibold">Backend 400 Validation Error:</div>
                <div className="break-all">{localError}</div>
              </div>
            </div>
          )}

          <form onSubmit={handleLocalSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Local Workspace Path <span className="text-rose-400">*</span>
              </label>
              <input
                type="text"
                placeholder="tests/sample-repos/leaky-app"
                value={localPath}
                onChange={(e) => setLocalPath(e.target.value)}
                className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-sm font-mono placeholder:text-slate-600 focus:outline-none focus:border-emerald-500"
              />
              <p className="text-[11px] text-slate-500 mt-1">
                Directory must exist inside the configured workspace or sample-repos folder.
              </p>
            </div>

            <div className="flex justify-end pt-2">
              <button
                type="submit"
                disabled={localLoading || !localPath.trim()}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 disabled:bg-slate-800 disabled:text-slate-500 text-slate-950 transition-colors shadow-sm"
              >
                {localLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Scanning Directory...</span>
                  </>
                ) : (
                  <>
                    <span>Scan Local Path</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Tab 4: Live Snippet Scanner */}
      {activeTab === "snippet" && (
        <div className="bg-[#0D1322] border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
            <div>
              <h2 className="text-base font-semibold text-white">Live Snippet Scanner</h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Paste any source code, environment file, or config snippet to run immediate static inspection.
              </p>
            </div>
            <span className="px-2.5 py-1 text-[11px] font-mono rounded bg-slate-900 border border-slate-800 text-slate-400">
              Ephemeral • Zero DB Persistence
            </span>
          </div>

          {snippetError && (
            <div className="p-4 rounded-lg border border-rose-800/80 bg-rose-950/40 text-rose-300 text-xs sm:text-sm flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400 mt-0.5" />
              <span className="break-all">{snippetError}</span>
            </div>
          )}

          <form onSubmit={handleSnippetSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Optional Filename <span className="text-slate-500">(influences file-type scanner rules)</span>
              </label>
              <input
                type="text"
                placeholder="snippet.txt (e.g. app.py, .env, id_rsa, terraform.tfstate)"
                value={snippetFilename}
                onChange={(e) => setSnippetFilename(e.target.value)}
                className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs sm:text-sm font-mono placeholder:text-slate-600 focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-xs font-medium text-slate-300">
                  Snippet Content <span className="text-rose-400">*</span>
                </label>
                <span className="text-[11px] font-mono text-slate-500">
                  Max 100 KB ({new Blob([snippetContent]).size} / 102400 bytes)
                </span>
              </div>
              <textarea
                rows={10}
                value={snippetContent}
                onChange={(e) => setSnippetContent(e.target.value)}
                placeholder={`# Paste your code, config, or credentials here...\nAWS_SECRET_KEY = "..."\nAPI_KEY = "..."`}
                className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs sm:text-sm font-mono leading-relaxed placeholder:text-slate-600 focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div className="flex justify-between items-center pt-2">
              <button
                type="button"
                onClick={() => {
                  setSnippetContent("");
                  setSnippetResult(null);
                  setSnippetError(null);
                }}
                className="text-xs text-slate-400 hover:text-slate-200 transition-colors"
              >
                Clear Content
              </button>
              <button
                type="submit"
                disabled={snippetLoading || !snippetContent.trim()}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 disabled:bg-slate-800 disabled:text-slate-500 text-slate-950 transition-colors shadow-sm"
              >
                {snippetLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Scanning Snippet...</span>
                  </>
                ) : (
                  <>
                    <Shield className="w-4 h-4" />
                    <span>Scan Snippet</span>
                  </>
                )}
              </button>
            </div>
          </form>

          {/* Results Display */}
          {snippetResult && (
            <div className="mt-6 pt-6 border-t border-slate-800 space-y-4">
              {/* Verdict Banner */}
              {snippetResult.status === "passed" ? (
                <div className="p-4 rounded-xl border border-emerald-500/40 bg-emerald-950/40 text-emerald-300 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <ShieldCheck className="w-6 h-6 text-emerald-400 shrink-0" />
                    <div>
                      <h3 className="font-semibold text-sm">No secrets or PII found</h3>
                      <p className="text-xs text-emerald-300/80 mt-0.5">
                        The snippet passed all static rules cleanly without triggering security barriers.
                      </p>
                    </div>
                  </div>
                  <div className="text-right font-mono text-xs">
                    <div className="text-emerald-400 font-bold">Risk: 0/100</div>
                    <div className="text-[10px] uppercase text-emerald-500">Passed</div>
                  </div>
                </div>
              ) : (
                <div className="p-4 rounded-xl border border-rose-500/40 bg-rose-950/40 text-rose-300 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <ShieldAlert className="w-6 h-6 text-rose-400 shrink-0" />
                    <div>
                      <h3 className="font-semibold text-sm">Would be blocked</h3>
                      <p className="text-xs text-rose-300/80 mt-0.5">
                        {snippetResult.blocked_reason || "Critical credentials or high-risk findings detected."}
                      </p>
                    </div>
                  </div>
                  <div className="text-right font-mono text-xs">
                    <div className="text-rose-400 font-bold">{snippetResult.risk_score}/100</div>
                    <div className="text-[10px] uppercase text-rose-500">{snippetResult.risk_level} Risk</div>
                  </div>
                </div>
              )}

              {/* Inline Findings Table */}
              {snippetResult.findings.length > 0 && (
                <div className="border border-slate-800 rounded-lg overflow-hidden bg-slate-950">
                  <div className="px-4 py-3 border-b border-slate-800 bg-[#0B101E] flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-200">
                      Detected Findings ({snippetResult.findings.length})
                    </span>
                    <span className="text-[10px] font-mono text-slate-500">
                      Masked previews only
                    </span>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-xs font-mono">
                      <thead className="border-b border-slate-800 text-slate-400 bg-slate-900/40">
                        <tr>
                          <th className="py-2.5 px-3">Rule / Type</th>
                          <th className="py-2.5 px-3">Line</th>
                          <th className="py-2.5 px-3">Severity</th>
                          <th className="py-2.5 px-3">Masked Preview</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {snippetResult.findings.map((f, idx) => (
                          <tr key={idx} className="hover:bg-slate-900/40 transition-colors">
                            <td className="py-2.5 px-3 text-slate-300 font-sans font-medium">
                              {f.type}
                            </td>
                            <td className="py-2.5 px-3 text-slate-400">
                              L{f.line}
                            </td>
                            <td className="py-2.5 px-3">
                              <SeverityChip severity={f.severity} />
                            </td>
                            <td className="py-2.5 px-3 text-rose-300 max-w-md break-all">
                              <span className="bg-slate-900 border border-slate-800 px-2 py-0.5 rounded">
                                {f.masked_preview}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
