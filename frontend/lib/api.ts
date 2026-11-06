export type ScanStatus = "queued" | "running" | "passed" | "blocked" | "failed";
export type SeverityLevel = "critical" | "high" | "medium" | "low";

export interface Finding {
  id: number;
  scan_id?: number;
  file: string;
  line: number;
  type: string;
  severity: SeverityLevel;
  masked_preview: string;
}

export interface ScanSummary {
  id: number;
  source: string;
  status: ScanStatus;
  risk_score: number;
  risk_level: string;
  created_at: string;
  findings_count: number;
}

export interface ScanDetail {
  id: number;
  source: string;
  status: ScanStatus;
  risk_score: number;
  risk_level: string;
  created_at: string;
  blocked_reason?: string | null;
  findings_by_type?: Record<string, number>;
  findings: Finding[];
}

export interface Stats {
  total_scans: number;
  blocked_count: number;
  passed_count: number;
  total_findings: number;
  findings_by_severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  avg_risk_score: number;
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export async function fetchStats(): Promise<Stats> {
  const res = await fetch(`${API_BASE}/api/stats`, { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`Failed to fetch stats: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchScans(): Promise<ScanSummary[]> {
  const res = await fetch(`${API_BASE}/api/scans`, { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`Failed to list scans: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchScan(id: number | string): Promise<ScanDetail> {
  const res = await fetch(`${API_BASE}/api/scans/${id}`, { cache: "no-store" });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Scan #${id} not found`);
  }
  return res.json();
}

export interface SnippetFinding {
  file: string;
  line: number;
  type: string;
  severity: SeverityLevel | string;
  masked_preview: string;
}

export interface SnippetScanResult {
  findings: SnippetFinding[];
  risk_score: number;
  risk_level: string;
  status: "passed" | "blocked";
  blocked_reason?: string | null;
}

export async function uploadZipScan(file: File): Promise<ScanDetail> {
  const formData = new FormData();
  formData.append("file", file);

  const url = `${API_BASE}/api/scans/upload`;
  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      body: formData,
    });
  } catch (netErr: any) {
    throw new Error(`Upload failed at ${url} - is the backend running? (${netErr?.message || netErr})`);
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Upload failed (${res.status}) at ${url} - is the backend running?`);
  }
  return res.json();
}

export async function submitGithubScan(repoUrl: string, branch?: string): Promise<ScanDetail> {
  const url = `${API_BASE}/api/scans/github`;
  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repo_url: repoUrl, branch: branch || undefined }),
    });
  } catch (netErr: any) {
    throw new Error(`GitHub scan request failed at ${url} - is the backend running? (${netErr?.message || netErr})`);
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `GitHub scan request failed (${res.status}) at ${url} - is the backend running?`);
  }
  return res.json();
}

export async function submitLocalScan(path: string, sync: boolean = true): Promise<ScanDetail> {
  const url = `${API_BASE}/api/scans`;
  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path, sync }),
    });
  } catch (netErr: any) {
    throw new Error(`Scan request failed at ${url} - is the backend running? (${netErr?.message || netErr})`);
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Scan request failed (${res.status}) at ${url} - is the backend running?`);
  }
  return res.json();
}

export async function scanSnippet(content: string, filename?: string): Promise<SnippetScanResult> {
  const url = `${API_BASE}/api/scans/snippet`;
  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content, filename: filename || "snippet.txt" }),
    });
  } catch (netErr: any) {
    throw new Error(`Snippet scan failed at ${url} - is the backend running? (${netErr?.message || netErr})`);
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Snippet scan failed (${res.status}) at ${url} - is the backend running?`);
  }
  return res.json();
}

export function getReportDownloadUrl(id: number | string): string {
  return `${API_BASE}/api/scans/${id}/report`;
}

export type DeploymentStatus =
  | "pending"
  | "building"
  | "deploying"
  | "probing"
  | "deployed"
  | "exposed"
  | "failed"
  | "stopped";

export interface Deployment {
  id: number;
  scan_id: number;
  project?: string | null;
  status: DeploymentStatus;
  image_tag: string;
  container_name: string;
  port: number | null;
  url: string | null;
  host_type: "local" | "ec2" | string;
  logs: string;
  created_at: string;
  finished_at: string | null;
}

export async function triggerDeploy(scanId: number | string, project?: string): Promise<Deployment> {
  const body = project ? JSON.stringify({ project }) : undefined;
  const res = await fetch(`${API_BASE}/api/scans/${scanId}/deploy`, {
    method: "POST",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Deployment trigger failed with status ${res.status}`);
  }
  return res.json();
}

export interface SecretMetadata {
  name: string;
  masked: string;
  updated_at: string | null;
}

export async function fetchSecrets(project: string): Promise<SecretMetadata[]> {
  const res = await fetch(`${API_BASE}/api/projects/${encodeURIComponent(project)}/secrets`, {
    cache: "no-store",
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch secrets for project ${project}`);
  }
  return res.json();
}

export async function putSecret(
  project: string,
  name: string,
  value: string
): Promise<{ name: string; project: string }> {
  const res = await fetch(`${API_BASE}/api/projects/${encodeURIComponent(project)}/secrets/${encodeURIComponent(name)}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ value }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to store secret ${name}`);
  }
  return res.json();
}

export async function deleteSecret(
  project: string,
  name: string
): Promise<{ name: string; project: string }> {
  const res = await fetch(`${API_BASE}/api/projects/${encodeURIComponent(project)}/secrets/${encodeURIComponent(name)}`, {
    method: "DELETE",
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to delete secret ${name}`);
  }
  return res.json();
}

export interface ProbeItem {
  path: string;
  status: number | null;
  verdict: "safe" | "exposed" | "warning";
  note: string;
  created_at?: string;
}

export interface ProbeResultResponse {
  deployment_id: number;
  status?: string;
  overall_verdict: "safe" | "exposed" | "warning";
  exposed_count: number;
  warning_count: number;
  items: ProbeItem[];
}

export async function fetchProbeResults(deploymentId: number | string): Promise<ProbeResultResponse> {
  const res = await fetch(`${API_BASE}/api/deployments/${deploymentId}/probe`, {
    cache: "no-store",
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch probe results for deployment #${deploymentId}`);
  }
  return res.json();
}

export async function rerunProbe(deploymentId: number | string): Promise<ProbeResultResponse> {
  const res = await fetch(`${API_BASE}/api/deployments/${deploymentId}/probe`, {
    method: "POST",
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to re-run probe for deployment #${deploymentId}`);
  }
  return res.json();
}

export async function fetchDeployments(): Promise<Deployment[]> {
  const res = await fetch(`${API_BASE}/api/deployments`, { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`Failed to list deployments: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchDeployment(id: number | string): Promise<Deployment> {
  const res = await fetch(`${API_BASE}/api/deployments/${id}`, { cache: "no-store" });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Deployment #${id} not found`);
  }
  return res.json();
}

export async function stopDeployment(id: number | string): Promise<Deployment> {
  const res = await fetch(`${API_BASE}/api/deployments/${id}/stop`, {
    method: "POST",
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to stop deployment #${id}`);
  }
  return res.json();
}

export const HOW_TO_FIX_HINTS: Record<string, string> = {
  aws_access_key: "Revoke this key in AWS IAM now, rotate credentials, and load access keys from environment variables or AWS Secrets Manager.",
  aws_secret_key: "Immediately deactivate this secret access key in AWS IAM and never commit static AWS credentials into git.",
  stripe_live_key: "Revoke and roll this live key in Stripe Dashboard under Developers > API Keys. Use restricted test keys for local dev.",
  google_api_key: "Restrict this key by IP or HTTP referrer in Google Cloud Console, or migrate to Google Secret Manager.",
  github_token: "Revoke this personal access token in GitHub Settings > Developer settings > Personal access tokens immediately.",
  jwt_token: "Ensure JWT secrets are not hardcoded in source; store signing keys in a secure key management service (KMS).",
  private_key_block: "Remove the private key from git history (git-filter-repo), reissue the certificate pair, and store keys in Vault or KMS.",
  ssh_private_key_file: "Remove this SSH key immediately and generate a new key pair with ssh-keygen. Store under ~/.ssh/ or use an SSH agent.",
  certificate_or_key_file: "Do not commit private certificates (*.pem, *.key, *.pfx). Place them in .gitignore and provision via CI secrets.",
  generic_secret_assignment: "Move this secret into a .env file that is excluded via .gitignore, and inject it at runtime.",
  high_entropy_string: "Audit this high-entropy string; if it is a sensitive signing secret or salt, move it to runtime environment configuration.",
  committed_env_file: "Add .env to your .gitignore immediately and remove the file from git tracking using 'git rm --cached .env'.",
  sensitive_env_file: "Ensure production environment files are not checked into version control. Use .env.example with dummy placeholders instead.",
  committed_git_dir: "Remove the committed .git directory from your upload bundle before deploying.",
  terraform_state_file: "Terraform state files often contain unencrypted database passwords and cloud tokens. Store state in an encrypted remote S3/GCS backend.",
  credentials_file: "Remove credentials.json from repository. Use Google Workload Identity Federation or cloud IAM roles instead of static service account files.",
  service_account_key_file: "Delete and rotate this service account key in GCP IAM. Use metadata identity or short-lived OAuth tokens.",
  connection_string_password: "Remove embedded plaintext passwords from database URIs. Inject user/pass at runtime using dynamic connection builders.",
  aadhaar_number: "Mask or redact this 12-digit Aadhaar number to comply with DPDP and UIDAI data storage regulations.",
  credit_card_number: "PCI-DSS prohibits storing plaintext credit card numbers in application code. Use a tokenized payment vault.",
  pan_number: "Redact or tokenize Indian PAN identifiers to comply with local financial data protection guidelines.",
  email_address: "Ensure personal email addresses are not exposed in public repositories or logs without explicit user consent.",
  indian_mobile_number: "Redact customer phone numbers or encrypt stored PII to prevent unauthorized access and harassment.",
};

export function getHowToFixHint(ruleType: string): string {
  return HOW_TO_FIX_HINTS[ruleType] || "Remove this sensitive credential or PII from source control and load it securely from runtime secret storage.";
}
