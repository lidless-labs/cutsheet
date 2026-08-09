// Fetch wrapper for the Cutsheet REST API. Same-origin /api/v1, optional
// bearer token from localStorage, and the server's error envelope
// ({"error":{"code","message"}}) surfaced as ApiError.

const BASE = "/api/v1";
const TOKEN_KEY = "cutsheet_api_token";

export function getToken(): string {
  return localStorage.getItem(TOKEN_KEY) ?? "";
}

export function setToken(token: string): void {
  if (token) {
    localStorage.setItem(TOKEN_KEY, token);
  } else {
    localStorage.removeItem(TOKEN_KEY);
  }
}

export class ApiError extends Error {
  code: string;
  status: number;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function headers(extra?: Record<string, string>): Record<string, string> {
  const h: Record<string, string> = { ...extra };
  const token = getToken();
  if (token) {
    h["Authorization"] = `Bearer ${token}`;
  }
  return h;
}

async function parseError(res: Response): Promise<ApiError> {
  try {
    const body = await res.json();
    if (body?.error?.code) {
      return new ApiError(res.status, body.error.code, body.error.message);
    }
  } catch {
    // fall through to generic error
  }
  return new ApiError(res.status, "http_error", `HTTP ${res.status}`);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, {
    ...init,
    headers: headers(init?.headers as Record<string, string> | undefined),
  });
  if (!res.ok) {
    throw await parseError(res);
  }
  if (res.status === 204) {
    return undefined as T;
  }
  return (await res.json()) as T;
}

export function apiGet<T>(path: string): Promise<T> {
  return request<T>(path);
}

export function apiPost<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, {
    method: "POST",
    headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

export function apiPatch<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export function apiDelete(path: string): Promise<void> {
  return request<void>(path, { method: "DELETE" });
}

// fetchReportBlob fetches a report file with auth headers and returns it as a
// Blob. Used because <iframe src> and <a href> cannot carry the bearer token.
export async function fetchReportBlob(changeId: number, name: string): Promise<Blob> {
  const res = await fetch(`${BASE}/changes/${changeId}/reports/${name}`, {
    headers: headers(),
  });
  if (!res.ok) {
    throw await parseError(res);
  }
  return await res.blob();
}

// --- Wire types (mirror internal/api JSON) ---

export type Severity = "none" | "low" | "medium" | "high";

export interface Device {
  id: string;
  name: string;
  vendor: string;
  address: string;
  collector_type: string;
  collector_config: Record<string, unknown>;
  poll_interval_seconds: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface Change {
  id: number;
  device_id: string;
  detected_at: string;
  commit_hash: string;
  prev_commit_hash: string;
  summary: string;
  max_severity: Severity;
  has_report: boolean;
  changed_by: string;
}

export interface Finding {
  id: number;
  finding_id: string;
  severity: Severity;
  category: string;
  title: string;
  recommendation: string;
}

// Analysis is the configdiff document (diff-analysis-v1). Only the parts the
// UI reads are typed.
export interface AnalysisRiskFinding {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  details: string[];
  evidence: string[];
  recommendation: string;
}

export interface Analysis {
  schema_version?: string;
  risk_findings?: AnalysisRiskFinding[];
}

export interface ChangeDetail extends Change {
  analysis: Analysis | null;
  findings: Finding[];
}

export interface ReportFile {
  name: string;
  size: number;
}

export const SEVERITY_RANK: Record<Severity, number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
};
