// Package notify pushes recorded config changes to external sinks: a generic
// JSON webhook and Discord. Notifications are best-effort by design - a dead
// webhook must never block change recording - so the Fanout logs failures and
// moves on instead of returning them to the pipeline.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/lidless-labs/cutsheet/internal/store"
)

// Event is the notification payload for one recorded change. Field names are
// the generic webhook's JSON contract. ReportDir is intentionally a public
// change reference, not store.Change.ReportDir's server-local filesystem path.
type Event struct {
	DeviceID      string    `json:"device_id"`
	DeviceName    string    `json:"device_name"`
	ChangeID      int64     `json:"change_id"`
	DetectedAt    time.Time `json:"detected_at"`
	Summary       string    `json:"summary"`
	MaxSeverity   string    `json:"max_severity"`
	FindingsCount int       `json:"findings_count"`
	ReportDir     string    `json:"report_dir"`
	// ChangedBy is the device username from a syslog audit event when known.
	ChangedBy string `json:"changed_by"`
}

// EventFromChange builds the notification event for a recorded change.
func EventFromChange(device store.Device, change store.Change) Event {
	return publicEvent(Event{
		DeviceID:      device.ID,
		DeviceName:    device.Name,
		ChangeID:      change.ID,
		DetectedAt:    change.DetectedAt,
		Summary:       change.Summary,
		MaxSeverity:   change.MaxSeverity,
		FindingsCount: len(change.Findings),
		ReportDir:     change.ReportDir,
		ChangedBy:     change.ChangedBy,
	})
}

func publicReportRef(changeID int64) string {
	if changeID <= 0 {
		return ""
	}
	return "change-" + strconv.FormatInt(changeID, 10)
}

func publicEvent(ev Event) Event {
	ev.ReportDir = publicReportRef(ev.ChangeID)
	return ev
}

// Notifier delivers one event to one sink.
type Notifier interface {
	Notify(ctx context.Context, ev Event) error
}

const (
	defaultTimeout = 10 * time.Second
	defaultBackoff = 2 * time.Second
)

var defaultClient = &http.Client{Timeout: defaultTimeout}

// Webhook POSTs the Event as JSON to a URL: the generic integration point for
// anything that speaks HTTP (n8n, ntfy bridges, custom receivers).
type Webhook struct {
	URL    string
	Client *http.Client // optional; defaults to a 10s-timeout client

	backoff time.Duration // test hook; defaults to 2s
}

// Notify implements Notifier.
func (w *Webhook) Notify(ctx context.Context, ev Event) error {
	ev = publicEvent(ev)
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}
	return postJSON(ctx, orDefault(w.Client), w.URL, body, w.backoff)
}

// Discord POSTs an embed to a Discord webhook URL.
type Discord struct {
	URL    string
	Client *http.Client // optional; defaults to a 10s-timeout client

	backoff time.Duration // test hook; defaults to 2s
}

type discordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type discordEmbed struct {
	Title       string              `json:"title"`
	Description string              `json:"description"`
	Color       int                 `json:"color"`
	Fields      []discordEmbedField `json:"fields"`
	Timestamp   string              `json:"timestamp"`
}

type discordMessage struct {
	Embeds []discordEmbed `json:"embeds"`
}

// severityColor maps a severity to the embed accent color. Unknown severities
// get the "none" gray, matching store.SeverityRank's unknown-ranks-low rule.
func severityColor(severity string) int {
	switch severity {
	case "high":
		return 0xE74C3C // red
	case "medium":
		return 0xE67E22 // orange
	case "low":
		return 0xF1C40F // yellow
	default:
		return 0x95A5A6 // gray
	}
}

// Notify implements Notifier.
func (d *Discord) Notify(ctx context.Context, ev Event) error {
	// Discord rejects embeds with empty field values, and initial snapshots
	// have no report bundle.
	changeID := "(none)"
	if ev.ChangeID > 0 {
		changeID = strconv.FormatInt(ev.ChangeID, 10)
	}
	fields := []discordEmbedField{
		{Name: "Severity", Value: ev.MaxSeverity, Inline: true},
		{Name: "Findings", Value: strconv.Itoa(ev.FindingsCount), Inline: true},
		{Name: "Change ID", Value: changeID},
	}
	// Discord rejects embeds with empty field values.
	if ev.ChangedBy != "" {
		fields = append(fields, discordEmbedField{Name: "Changed by", Value: ev.ChangedBy, Inline: true})
	}
	msg := discordMessage{Embeds: []discordEmbed{{
		Title:       "Config change: " + ev.DeviceName,
		Description: ev.Summary,
		Color:       severityColor(ev.MaxSeverity),
		Fields:      fields,
		Timestamp:   ev.DetectedAt.UTC().Format(time.RFC3339),
	}}}
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal discord payload: %w", err)
	}
	return postJSON(ctx, orDefault(d.Client), d.URL, body, d.backoff)
}

func orDefault(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return defaultClient
}

// postJSON POSTs body to url with a single retry on 5xx responses or
// transport errors (after backoff); 4xx responses fail immediately because
// retrying a rejected payload can't succeed.
func postJSON(ctx context.Context, client *http.Client, url string, body []byte, backoff time.Duration) error {
	if backoff <= 0 {
		backoff = defaultBackoff
	}
	err := doPost(ctx, client, url, body)
	if err == nil || !retryable(err) {
		return err
	}
	select {
	case <-ctx.Done():
		return fmt.Errorf("notify %s: %w (after first attempt: %v)", url, ctx.Err(), err)
	case <-time.After(backoff):
	}
	if retryErr := doPost(ctx, client, url, body); retryErr != nil {
		return fmt.Errorf("notify %s failed after retry: %w (first attempt: %v)", url, retryErr, err)
	}
	return nil
}

// httpStatusError marks a non-2xx response so retryable can tell 5xx from 4xx.
type httpStatusError struct{ status int }

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("unexpected status %d", e.status)
}

func retryable(err error) bool {
	if se, ok := err.(*httpStatusError); ok {
		return se.status >= 500
	}
	return true // transport-level error
}

func doPost(ctx context.Context, client *http.Client, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &httpStatusError{status: resp.StatusCode}
	}
	return nil
}

// Fanout delivers one event to every configured notifier, filtered by a
// minimum severity. MinSeverity "none" notifies on everything including
// initial snapshots; empty defaults to "low" (any finding-bearing change).
// Failures are logged per notifier and never propagate: one dead webhook
// must not block the others or the pipeline.
type Fanout struct {
	Notifiers   []Notifier
	MinSeverity string
	Logger      *slog.Logger
}

// Notify fans the event out. It never returns an error; delivery failures
// are logged and swallowed by design.
func (f *Fanout) Notify(ctx context.Context, ev Event) {
	min := f.MinSeverity
	if min == "" {
		min = "low"
	}
	if store.SeverityRank(ev.MaxSeverity) < store.SeverityRank(min) {
		return
	}
	logger := f.Logger
	if logger == nil {
		logger = slog.Default()
	}
	for _, n := range f.Notifiers {
		if err := n.Notify(ctx, ev); err != nil {
			logger.Error("notification failed",
				"notifier", fmt.Sprintf("%T", n),
				"device", ev.DeviceID,
				"change_id", ev.ChangeID,
				"error", err)
		}
	}
}
