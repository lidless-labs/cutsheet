import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  apiGet,
  fetchReportBlob,
  SEVERITY_RANK,
  type AnalysisRiskFinding,
  type ChangeDetail,
  type Device,
  type ReportFile,
  type Severity,
} from "../api";
import { SeverityBadge } from "../components/SeverityBadge";
import { createReportPreviewController } from "../reportPreviewBlob";
import { useToast } from "../toast";
import { formatBytes, formatTimestamp, timeAgo } from "../util";

type Tab = "findings" | "report" | "files";

interface MergedFinding {
  findingId: string;
  severity: Severity;
  category: string;
  title: string;
  recommendation: string;
  details: string[];
  evidence: string[];
}

export default function ChangeDetailPage() {
  const { id } = useParams();
  const [change, setChange] = useState<ChangeDetail | null>(null);
  const [device, setDevice] = useState<Device | null>(null);
  const [reports, setReports] = useState<ReportFile[]>([]);
  const [tab, setTab] = useState<Tab>("findings");
  const [reportUrl, setReportUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const toast = useToast();
  // Owns load/cancel + revoke: setReportUrl rerenders must not revoke;
  // id change / unmount must cancel in-flight work and dispose the live URL.
  const preview = useRef(
    createReportPreviewController({
      fetchReport: (changeId) => fetchReportBlob(changeId, "report.html"),
    }),
  );

  useEffect(() => {
    setChange(null);
    setError(null);
    apiGet<ChangeDetail>(`/changes/${id}`)
      .then((c) => {
        setChange(c);
        apiGet<Device>(`/devices/${c.device_id}`)
          .then(setDevice)
          .catch(() => {
            // Device may have been deleted; the id still renders.
          });
        if (c.has_report) {
          apiGet<{ reports: ReportFile[] }>(`/changes/${c.id}/reports`)
            .then((res) => setReports(res.reports))
            .catch((err) => toast.push("error", `Load report list failed: ${err.message}`));
        }
      })
      .catch((err) => setError(err.message));
  }, [id, toast]);

  // The HTML report is fetched with the bearer header and shown via a blob
  // URL, because an <iframe src> pointed straight at the API cannot carry
  // Authorization. reportUrl is intentionally not a dependency: listing it
  // re-ran this effect after setReportUrl and the cleanup revoked the live URL.
  // `id` is in the dependency list so route transitions soft-cancel the old
  // load before a stale fetch can create/adopt a URL.
  useEffect(() => {
    if (tab !== "report" || !change?.has_report || preview.current.current()) {
      return;
    }
    return preview.current.load({
      routeId: id,
      changeId: change.id,
      onAdopt: setReportUrl,
      onError: (message) => toast.push("error", `Load report failed: ${message}`),
    });
  }, [id, tab, change, toast]);

  // Reset preview state when navigating between changes; cancel + revoke on leave/unmount.
  useEffect(() => {
    setReportUrl(null);
    setTab("findings");
    setReports([]);
    return () => {
      preview.current.dispose();
    };
  }, [id]);

  const findings: MergedFinding[] = useMemo(() => {
    if (!change) {
      return [];
    }
    // The analysis document's risk_findings carry details + evidence; the
    // stored findings rows are the canonical list. Merge by finding id.
    const byId = new Map<string, AnalysisRiskFinding>();
    for (const rf of change.analysis?.risk_findings ?? []) {
      byId.set(rf.id, rf);
    }
    const merged = change.findings.map((f) => {
      const rf = byId.get(f.finding_id);
      return {
        findingId: f.finding_id,
        severity: f.severity,
        category: f.category,
        title: f.title,
        recommendation: f.recommendation,
        details: rf?.details ?? [],
        evidence: rf?.evidence ?? [],
      };
    });
    merged.sort(
      (a, b) =>
        (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0) ||
        a.findingId.localeCompare(b.findingId),
    );
    return merged;
  }, [change]);

  const download = (name: string) => {
    if (!change) {
      return;
    }
    fetchReportBlob(change.id, name)
      .then((blob) => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `change-${change.id}-${name}`;
        a.click();
        URL.revokeObjectURL(url);
      })
      .catch((err) => toast.push("error", `Download ${name} failed: ${err.message}`));
  };

  if (error) {
    return (
      <div className="empty-state">
        <h2>Change not available</h2>
        <p>{error}</p>
        <p>
          <Link to="/">Back to timeline</Link>
        </p>
      </div>
    );
  }
  if (!change) {
    return <div className="loading">Loading change...</div>;
  }

  return (
    <>
      <div className="detail-header">
        <SeverityBadge severity={change.max_severity} />
        <h1>{device?.name ?? change.device_id}</h1>
        <span className="spacer" />
        <Link to="/" className="btn">
          Back to timeline
        </Link>
      </div>
      <div className="detail-meta">
        <span title={change.detected_at}>
          {formatTimestamp(change.detected_at)} ({timeAgo(change.detected_at)})
        </span>
        <span>{change.summary}</span>
        {change.changed_by && (
          <span className="changed-by" title="attributed from syslog audit event">
            by {change.changed_by}
          </span>
        )}
        <span className="mono" title="snapshot commit">
          {change.commit_hash.slice(0, 8)}
          {change.prev_commit_hash && ` ← ${change.prev_commit_hash.slice(0, 8)}`}
        </span>
      </div>

      <div className="tab-bar">
        <button className={tab === "findings" ? "active" : ""} onClick={() => setTab("findings")}>
          Findings ({findings.length})
        </button>
        {change.has_report && (
          <>
            <button className={tab === "report" ? "active" : ""} onClick={() => setTab("report")}>
              Full report
            </button>
            <button className={tab === "files" ? "active" : ""} onClick={() => setTab("files")}>
              Files ({reports.length})
            </button>
          </>
        )}
      </div>

      {tab === "findings" &&
        (findings.length === 0 ? (
          <div className="empty-state">
            <h2>No risk findings</h2>
            <p>
              {change.summary === "initial snapshot"
                ? "This is the device's first snapshot; monitoring starts here."
                : "The analyzer recorded this change without flagging any risks."}
            </p>
          </div>
        ) : (
          findings.map((f) => (
            <div key={f.findingId} className={`finding-card sev-border-${f.severity}`}>
              <div className="finding-head">
                <SeverityBadge severity={f.severity} />
                <span className="finding-title">{f.title}</span>
                <span className="finding-category">{f.category}</span>
                <span className="spacer" />
                <span className="finding-id">{f.findingId}</span>
              </div>
              {f.details.length > 0 && (
                <div className="finding-section">
                  {f.details.map((line, i) => (
                    <div key={i}>{line}</div>
                  ))}
                </div>
              )}
              {f.evidence.length > 0 && (
                <div className="finding-section">
                  <div className="label">Evidence</div>
                  <pre className="evidence">{f.evidence.join("\n")}</pre>
                </div>
              )}
              {f.recommendation && (
                <div className="finding-section">
                  <div className="label">Recommendation</div>
                  <div className="recommendation">{f.recommendation}</div>
                </div>
              )}
            </div>
          ))
        ))}

      {tab === "report" &&
        (reportUrl ? (
          <iframe className="report-frame" title="Change report" src={reportUrl} />
        ) : (
          <div className="loading">Loading report...</div>
        ))}

      {tab === "files" && (
        <div className="panel">
          <h2>Report bundle</h2>
          {reports.length === 0 ? (
            <div className="loading">No files in the report bundle.</div>
          ) : (
            <ul className="report-files">
              {reports.map((r) => (
                <li key={r.name}>
                  <a
                    href={`/api/v1/changes/${change.id}/reports/${r.name}`}
                    onClick={(e) => {
                      e.preventDefault();
                      download(r.name);
                    }}
                  >
                    {r.name}
                  </a>
                  <span className="size">{formatBytes(r.size)}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </>
  );
}
