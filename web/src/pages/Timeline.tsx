import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { apiGet, type Change, type Device, type Severity } from "../api";
import { SeverityBadge } from "../components/SeverityBadge";
import { useToast } from "../toast";
import { timeAgo } from "../util";

const REFRESH_MS = 30_000;

// findingsCount extracts the leading "N findings" from the recorded summary
// line ("3 findings (1 high) - 5 blocks changed"). The list endpoint does not
// carry findings, so the summary is the source.
function findingsCount(summary: string): number | null {
  const m = /^(\d+) findings?\b/.exec(summary);
  if (m) {
    return parseInt(m[1], 10);
  }
  if (summary.startsWith("no findings")) {
    return 0;
  }
  return null;
}

export default function Timeline() {
  const [changes, setChanges] = useState<Change[] | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [deviceFilter, setDeviceFilter] = useState("");
  const [minSeverity, setMinSeverity] = useState<Severity | "">("");
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const navigate = useNavigate();
  const toast = useToast();
  const failedOnce = useRef(false);

  const load = useCallback(
    (quiet: boolean) => {
      const params = new URLSearchParams({ limit: "100" });
      if (deviceFilter) {
        params.set("device_id", deviceFilter);
      }
      if (minSeverity) {
        params.set("min_severity", minSeverity);
      }
      apiGet<{ changes: Change[] }>(`/changes?${params}`)
        .then((res) => {
          setChanges(res.changes);
          setLastRefresh(new Date());
          failedOnce.current = false;
        })
        .catch((err) => {
          // One toast per failure streak, not one per 30s tick.
          if (!quiet || !failedOnce.current) {
            toast.push("error", `Load changes failed: ${err.message}`);
          }
          failedOnce.current = true;
        });
    },
    [deviceFilter, minSeverity, toast],
  );

  useEffect(() => {
    load(false);
    const id = setInterval(() => {
      if (!document.hidden) {
        load(true);
      }
    }, REFRESH_MS);
    return () => clearInterval(id);
  }, [load]);

  useEffect(() => {
    apiGet<{ devices: Device[] }>("/devices")
      .then((res) => setDevices(res.devices))
      .catch(() => {
        // Device names degrade to ids; the changes fetch surfaces real errors.
      });
  }, []);

  const deviceName = (id: string) => devices.find((d) => d.id === id)?.name || id;

  return (
    <>
      <div className="page-head">
        <h1>Timeline</h1>
        <span className="sub">all device config changes, newest first</span>
        <span className="spacer" />
        {lastRefresh && (
          <span className="refresh-note">
            auto-refresh 30s · updated {lastRefresh.toLocaleTimeString()}
          </span>
        )}
      </div>

      <div className="filter-bar">
        <label>
          Device
          <select value={deviceFilter} onChange={(e) => setDeviceFilter(e.target.value)}>
            <option value="">all</option>
            {devices.map((d) => (
              <option key={d.id} value={d.id}>
                {d.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Min severity
          <select
            value={minSeverity}
            onChange={(e) => setMinSeverity(e.target.value as Severity | "")}
          >
            <option value="">any</option>
            <option value="low">low</option>
            <option value="medium">medium</option>
            <option value="high">high</option>
          </select>
        </label>
        <button onClick={() => load(false)}>Refresh</button>
      </div>

      {changes === null ? (
        <div className="loading">Loading changes...</div>
      ) : changes.length === 0 ? (
        <div className="empty-state">
          <h2>No changes recorded yet</h2>
          {devices.length === 0 ? (
            <p>
              Cutsheet is not watching anything. Head to{" "}
              <Link to="/devices">Devices</Link> and add your first device; its initial
              snapshot will land here.
            </p>
          ) : (
            <p>
              {deviceFilter || minSeverity
                ? "No changes match the current filters."
                : "Devices are registered; changes will appear here as snapshots detect them."}
            </p>
          )}
        </div>
      ) : (
        <div>
          {changes.map((c) => {
            const fc = findingsCount(c.summary);
            return (
              <div
                key={c.id}
                className="timeline-row"
                onClick={() => navigate(`/changes/${c.id}`)}
              >
                <SeverityBadge severity={c.max_severity} />
                <span className="timeline-device">{deviceName(c.device_id)}</span>
                <span className="timeline-summary">{c.summary}</span>
                <span className="timeline-meta">
                  {c.changed_by && (
                    <span className="changed-by" title="attributed from syslog audit event">
                      by {c.changed_by}
                    </span>
                  )}
                  {fc !== null && fc > 0 && (
                    <span className="findings-count">
                      {fc} finding{fc === 1 ? "" : "s"}
                    </span>
                  )}
                  <span title={c.detected_at}>{timeAgo(c.detected_at)}</span>
                </span>
              </div>
            );
          })}
        </div>
      )}
    </>
  );
}
