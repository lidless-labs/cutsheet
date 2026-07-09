import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import {
  apiDelete,
  apiGet,
  apiPatch,
  apiPost,
  type Change,
  type ChangeDetail,
  type Device,
} from "../api";
import { SeverityBadge } from "../components/SeverityBadge";
import { useToast } from "../toast";
import { timeAgo } from "../util";

// Known configdiff parser modes, offered as datalist suggestions; the field
// stays free-text because the parser list can grow ahead of the UI.
const VENDOR_MODES = ["auto", "cisco-ios", "edgeos", "vyos", "junos", "fortios", "unifi-json"];

const SSH_PRESETS = ["", "edgeos", "vyos", "cisco-ios", "junos", "fortios"];

interface FormState {
  editingId: string | null; // null = add mode
  id: string;
  name: string;
  vendor: string;
  address: string;
  collectorType: string;
  intervalSeconds: string;
  enabled: boolean;
  // file
  filePath: string;
  // ssh
  sshHost: string;
  sshPort: string;
  sshUsername: string;
  sshPassword: string;
  sshPrivateKey: string;
  sshPreset: string;
  sshCommand: string;
  sshHostKey: string;
  sshInsecureIgnoreHostKey: boolean;
  // unifi
  unifiUrl: string;
  unifiSite: string;
  unifiUsername: string;
  unifiPassword: string;
  unifiInsecureTls: boolean;
  // eero
  eeroSessionToken: string;
  eeroNetworkId: string;
}

const EMPTY_FORM: FormState = {
  editingId: null,
  id: "",
  name: "",
  vendor: "",
  address: "",
  collectorType: "file",
  intervalSeconds: "300",
  enabled: true,
  filePath: "",
  sshHost: "",
  sshPort: "",
  sshUsername: "",
  sshPassword: "",
  sshPrivateKey: "",
  sshPreset: "",
  sshCommand: "",
  sshHostKey: "",
  sshInsecureIgnoreHostKey: false,
  unifiUrl: "",
  unifiSite: "",
  unifiUsername: "",
  unifiPassword: "",
  unifiInsecureTls: false,
  eeroSessionToken: "",
  eeroNetworkId: "",
};

function str(cfg: Record<string, unknown>, key: string): string {
  const v = cfg[key];
  return typeof v === "string" ? v : "";
}

function formFromDevice(d: Device): FormState {
  const cfg = d.collector_config ?? {};
  return {
    ...EMPTY_FORM,
    editingId: d.id,
    id: d.id,
    name: d.name,
    vendor: d.vendor,
    address: d.address,
    collectorType: d.collector_type,
    intervalSeconds: String(d.poll_interval_seconds),
    enabled: d.enabled,
    filePath: str(cfg, "path"),
    sshHost: str(cfg, "host"),
    sshPort: typeof cfg.port === "number" && cfg.port !== 0 ? String(cfg.port) : "",
    sshUsername: str(cfg, "username"),
    sshPassword: str(cfg, "password"), // arrives as *** when a secret is stored
    sshPrivateKey: str(cfg, "private_key"),
    sshPreset: str(cfg, "preset"),
    sshCommand: str(cfg, "command"),
    sshHostKey: str(cfg, "host_key"),
    sshInsecureIgnoreHostKey: cfg.insecure_ignore_host_key === true,
    unifiUrl: str(cfg, "url"),
    unifiSite: str(cfg, "site"),
    unifiUsername: str(cfg, "username"),
    unifiPassword: str(cfg, "password"),
    unifiInsecureTls: cfg.insecure_tls === true,
    eeroSessionToken: str(cfg, "session_token"),
    eeroNetworkId: str(cfg, "network_id"),
  };
}

// collectorConfig builds the collector_config object for the API. Empty
// optional fields are omitted; a password left as "***" is sent as-is, which
// the server treats as "keep the stored credential".
function collectorConfig(f: FormState): Record<string, unknown> {
  switch (f.collectorType) {
    case "file":
      return { path: f.filePath };
    case "ssh": {
      const cfg: Record<string, unknown> = { host: f.sshHost, username: f.sshUsername };
      if (f.sshPort) cfg.port = parseInt(f.sshPort, 10);
      if (f.sshPassword) cfg.password = f.sshPassword;
      if (f.sshPrivateKey) cfg.private_key = f.sshPrivateKey;
      if (f.sshPreset) cfg.preset = f.sshPreset;
      if (f.sshCommand) cfg.command = f.sshCommand;
      if (f.sshHostKey) cfg.host_key = f.sshHostKey;
      if (f.sshInsecureIgnoreHostKey) cfg.insecure_ignore_host_key = true;
      return cfg;
    }
    case "unifi": {
      const cfg: Record<string, unknown> = {
        url: f.unifiUrl,
        username: f.unifiUsername,
      };
      if (f.unifiSite) cfg.site = f.unifiSite;
      if (f.unifiPassword) cfg.password = f.unifiPassword;
      if (f.unifiInsecureTls) cfg.insecure_tls = true;
      return cfg;
    }
    case "eero": {
      const cfg: Record<string, unknown> = {};
      if (f.eeroSessionToken) cfg.session_token = f.eeroSessionToken;
      if (f.eeroNetworkId) cfg.network_id = f.eeroNetworkId;
      return cfg;
    }
    default:
      return {};
  }
}

export default function Devices() {
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [lastChange, setLastChange] = useState<Record<string, Change>>({});
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [showForm, setShowForm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [snapshotting, setSnapshotting] = useState<string | null>(null);
  const toast = useToast();

  const set = <K extends keyof FormState>(key: K, value: FormState[K]) =>
    setForm((f) => ({ ...f, [key]: value }));

  const load = useCallback(() => {
    apiGet<{ devices: Device[] }>("/devices")
      .then((res) => setDevices(res.devices))
      .catch((err) => toast.push("error", `Load devices failed: ${err.message}`));
    apiGet<{ changes: Change[] }>("/changes?limit=500")
      .then((res) => {
        const latest: Record<string, Change> = {};
        for (const c of res.changes) {
          // List is newest-first; keep the first seen per device.
          if (!latest[c.device_id]) {
            latest[c.device_id] = c;
          }
        }
        setLastChange(latest);
      })
      .catch(() => {
        // Last-change column degrades to "-"; the devices fetch reports errors.
      });
  }, [toast]);

  useEffect(load, [load]);

  const openAdd = () => {
    setForm(EMPTY_FORM);
    setShowForm(true);
  };

  const openEdit = (d: Device) => {
    setForm(formFromDevice(d));
    setShowForm(true);
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const interval = parseInt(form.intervalSeconds || "300", 10);
    if (Number.isNaN(interval) || interval < 0) {
      toast.push("error", "Poll interval must be a non-negative number of seconds");
      return;
    }
    const body = {
      name: form.name || undefined,
      vendor: form.vendor || undefined,
      address: form.address || undefined,
      collector_type: form.collectorType,
      collector_config: collectorConfig(form),
      poll_interval_seconds: interval,
      enabled: form.enabled,
    };
    setBusy(true);
    const req = form.editingId
      ? apiPatch<Device>(`/devices/${form.editingId}`, {
          ...body,
          name: form.name,
          vendor: form.vendor,
          address: form.address,
        })
      : apiPost<Device>("/devices", { ...body, id: form.id });
    req
      .then((d) => {
        toast.push("success", `${form.editingId ? "Updated" : "Added"} device ${d.id}`);
        setShowForm(false);
        setForm(EMPTY_FORM);
        load();
      })
      .catch((err) => toast.push("error", `Save failed: ${err.message}`))
      .finally(() => setBusy(false));
  };

  const toggleEnabled = (d: Device) => {
    apiPatch<Device>(`/devices/${d.id}`, { enabled: !d.enabled })
      .then((upd) => {
        toast.push("success", `${upd.name}: polling ${upd.enabled ? "enabled" : "disabled"}`);
        load();
      })
      .catch((err) => toast.push("error", `Update failed: ${err.message}`));
  };

  const remove = (d: Device) => {
    if (!window.confirm(`Delete device "${d.name}" (${d.id})? Its change history stays in the database.`)) {
      return;
    }
    apiDelete(`/devices/${d.id}`)
      .then(() => {
        toast.push("success", `Deleted device ${d.id}`);
        load();
      })
      .catch((err) => toast.push("error", `Delete failed: ${err.message}`));
  };

  const snapshotNow = (d: Device) => {
    setSnapshotting(d.id);
    apiPost<{ changed: boolean; change?: ChangeDetail }>(`/devices/${d.id}/snapshot`)
      .then((res) => {
        if (res.changed && res.change) {
          toast.push(
            "success",
            `${d.name}: change recorded (${res.change.max_severity}) - ${res.change.summary}`,
          );
          load();
        } else {
          toast.push("info", `${d.name}: no change since last snapshot`);
        }
      })
      .catch((err) => toast.push("error", `${d.name}: snapshot failed: ${err.message}`))
      .finally(() => setSnapshotting(null));
  };

  return (
    <>
      <div className="page-head">
        <h1>Devices</h1>
        <span className="sub">watched device inventory</span>
        <span className="spacer" />
        <button className="btn-primary" onClick={showForm ? () => setShowForm(false) : openAdd}>
          {showForm ? "Close form" : "Add device"}
        </button>
      </div>

      {showForm && (
        <div className="panel">
          <h2>{form.editingId ? `Edit device: ${form.editingId}` : "Add device"}</h2>
          <form className="device-form" onSubmit={submit}>
            <label className="field">
              Device ID
              <input
                className="mono"
                value={form.id}
                onChange={(e) => set("id", e.target.value)}
                placeholder="edge-gw1"
                required
                disabled={form.editingId !== null}
              />
            </label>
            <label className="field">
              Display name
              <input
                value={form.name}
                onChange={(e) => set("name", e.target.value)}
                placeholder="defaults to ID"
              />
            </label>
            <label className="field">
              Vendor (parser mode)
              <input
                list="vendor-modes"
                value={form.vendor}
                onChange={(e) => set("vendor", e.target.value)}
                placeholder="auto-suggested"
              />
              <datalist id="vendor-modes">
                {VENDOR_MODES.map((v) => (
                  <option key={v} value={v} />
                ))}
              </datalist>
            </label>
            <label className="field">
              Address
              <input
                value={form.address}
                onChange={(e) => set("address", e.target.value)}
                placeholder="198.18.0.1"
              />
            </label>
            <label className="field">
              Collector
              <select
                value={form.collectorType}
                onChange={(e) => set("collectorType", e.target.value)}
              >
                <option value="file">file</option>
                <option value="ssh">ssh</option>
                <option value="unifi">unifi</option>
                <option value="eero">eero</option>
              </select>
            </label>
            <label className="field">
              Poll interval (seconds, 0 = manual)
              <input
                type="number"
                min={0}
                value={form.intervalSeconds}
                onChange={(e) => set("intervalSeconds", e.target.value)}
              />
            </label>
            <label className="field-inline">
              <input
                type="checkbox"
                checked={form.enabled}
                onChange={(e) => set("enabled", e.target.checked)}
              />
              Polling enabled
            </label>

            {form.collectorType === "file" && (
              <label className="field full">
                Config file path (absolute, on the server)
                <input
                  className="mono"
                  value={form.filePath}
                  onChange={(e) => set("filePath", e.target.value)}
                  placeholder="/var/lib/cutsheet/fixtures/gw1.cfg"
                  required
                />
              </label>
            )}

            {form.collectorType === "ssh" && (
              <>
                <label className="field">
                  SSH host
                  <input
                    className="mono"
                    value={form.sshHost}
                    onChange={(e) => set("sshHost", e.target.value)}
                    placeholder="198.18.0.1"
                    required
                  />
                </label>
                <label className="field">
                  Port
                  <input
                    type="number"
                    value={form.sshPort}
                    onChange={(e) => set("sshPort", e.target.value)}
                    placeholder="22"
                  />
                </label>
                <label className="field">
                  Username
                  <input
                    value={form.sshUsername}
                    onChange={(e) => set("sshUsername", e.target.value)}
                    required
                  />
                </label>
                <label className="field">
                  Password
                  <input
                    type="password"
                    value={form.sshPassword}
                    onChange={(e) => set("sshPassword", e.target.value)}
                    placeholder="or use a private key"
                  />
                </label>
                <label className="field">
                  Vendor preset
                  <select
                    value={form.sshPreset}
                    onChange={(e) => set("sshPreset", e.target.value)}
                  >
                    {SSH_PRESETS.map((p) => (
                      <option key={p} value={p}>
                        {p || "(none - custom command)"}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="field">
                  Custom command (overrides preset)
                  <input
                    className="mono"
                    value={form.sshCommand}
                    onChange={(e) => set("sshCommand", e.target.value)}
                    placeholder="show configuration"
                  />
                </label>
                <label className="field full">
                  Private key (PEM, optional)
                  <textarea
                    rows={3}
                    value={form.sshPrivateKey}
                    onChange={(e) => set("sshPrivateKey", e.target.value)}
                  />
                </label>
                <label className="field full">
                  Host key (openssh format)
                  <input
                    className="mono"
                    value={form.sshHostKey}
                    onChange={(e) => set("sshHostKey", e.target.value)}
                    placeholder="ssh-ed25519 AAAA..."
                  />
                </label>
                <label className="field-inline">
                  <input
                    type="checkbox"
                    checked={form.sshInsecureIgnoreHostKey}
                    onChange={(e) => set("sshInsecureIgnoreHostKey", e.target.checked)}
                  />
                  Skip host key verification (insecure)
                </label>
              </>
            )}

            {form.collectorType === "unifi" && (
              <>
                <label className="field">
                  Controller URL
                  <input
                    className="mono"
                    value={form.unifiUrl}
                    onChange={(e) => set("unifiUrl", e.target.value)}
                    placeholder="https://198.18.0.10:8443"
                    required
                  />
                </label>
                <label className="field">
                  Site
                  <input
                    value={form.unifiSite}
                    onChange={(e) => set("unifiSite", e.target.value)}
                    placeholder="default"
                  />
                </label>
                <label className="field">
                  Username
                  <input
                    value={form.unifiUsername}
                    onChange={(e) => set("unifiUsername", e.target.value)}
                    required
                  />
                </label>
                <label className="field">
                  Password
                  <input
                    type="password"
                    value={form.unifiPassword}
                    onChange={(e) => set("unifiPassword", e.target.value)}
                    required={form.editingId === null}
                  />
                </label>
                <label className="field-inline">
                  <input
                    type="checkbox"
                    checked={form.unifiInsecureTls}
                    onChange={(e) => set("unifiInsecureTls", e.target.checked)}
                  />
                  Skip TLS verification (self-signed controller)
                </label>
              </>
            )}

            {form.collectorType === "eero" && (
              <>
                <label className="field full">
                  Session token
                  <input
                    type="password"
                    className="mono"
                    value={form.eeroSessionToken}
                    onChange={(e) => set("eeroSessionToken", e.target.value)}
                    required={form.editingId === null}
                  />
                  <span className="form-hint">
                    Obtain a session token out of band, for example with eero-cli (eero auth),
                    and paste it here. Cutsheet does not run eero's OTP login flow.
                  </span>
                </label>
                <label className="field">
                  Network ID
                  <input
                    className="mono"
                    value={form.eeroNetworkId}
                    onChange={(e) => set("eeroNetworkId", e.target.value)}
                    placeholder="optional for a single-network account"
                  />
                </label>
              </>
            )}

            <div className="form-actions">
              <button className="btn-primary" type="submit" disabled={busy}>
                {busy ? "Saving..." : form.editingId ? "Save changes" : "Add device"}
              </button>
              <button type="button" onClick={() => setShowForm(false)}>
                Cancel
              </button>
              <span className="form-hint">
                Stored secrets display as *** and are kept unless you type a new value.
              </span>
            </div>
          </form>
        </div>
      )}

      {devices === null ? (
        <div className="loading">Loading devices...</div>
      ) : devices.length === 0 ? (
        <div className="empty-state">
          <h2>No devices yet</h2>
          <p>
            Add your first device to start watching its configuration. The file collector
            works with any config you can drop on disk; ssh, unifi, and eero collect live.
          </p>
          {!showForm && (
            <button className="btn-primary" onClick={openAdd}>
              Add device
            </button>
          )}
        </div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Vendor</th>
              <th>Collector</th>
              <th>Address</th>
              <th>Interval</th>
              <th>Enabled</th>
              <th>Last change</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => {
              const lc = lastChange[d.id];
              return (
                <tr key={d.id}>
                  <td>
                    <span className="mono">{d.name}</span>
                    {d.name !== d.id && <span className="form-hint"> ({d.id})</span>}
                  </td>
                  <td className="mono">{d.vendor}</td>
                  <td className="mono">{d.collector_type}</td>
                  <td className="mono">{d.address || "-"}</td>
                  <td>{d.poll_interval_seconds === 0 ? "manual" : `${d.poll_interval_seconds}s`}</td>
                  <td>
                    <span className={`enabled-dot ${d.enabled ? "on" : "off"}`} />
                    {d.enabled ? "on" : "off"}
                  </td>
                  <td>
                    {lc ? (
                      <Link to={`/changes/${lc.id}`} title={lc.summary}>
                        <SeverityBadge severity={lc.max_severity} />{" "}
                        <span title={lc.detected_at}>{timeAgo(lc.detected_at)}</span>
                      </Link>
                    ) : (
                      "-"
                    )}
                  </td>
                  <td>
                    <span className="row-actions">
                      <button
                        onClick={() => snapshotNow(d)}
                        disabled={snapshotting === d.id}
                        title="Collect and analyze this device right now"
                      >
                        {snapshotting === d.id ? "Snapshotting..." : "Snapshot now"}
                      </button>
                      <button onClick={() => openEdit(d)}>Edit</button>
                      <button onClick={() => toggleEnabled(d)}>
                        {d.enabled ? "Disable" : "Enable"}
                      </button>
                      <button className="btn-danger" onClick={() => remove(d)}>
                        Delete
                      </button>
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </>
  );
}
