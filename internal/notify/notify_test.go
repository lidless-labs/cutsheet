package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/solomonneas/cutsheet/internal/store"
)

func testEvent() Event {
	return Event{
		DeviceID:      "edge-gw1",
		DeviceName:    "Edge Gateway",
		ChangeID:      42,
		DetectedAt:    time.Date(2026, 6, 9, 12, 30, 0, 0, time.UTC),
		Summary:       "3 findings (1 high) - 5 blocks changed",
		MaxSeverity:   "high",
		FindingsCount: 3,
		ReportDir:     "/data/reports/edge-gw1/20260609-123000-abcd1234",
	}
}

func TestEventFromChange(t *testing.T) {
	device := store.Device{ID: "edge-gw1", Name: "Edge Gateway"}
	change := store.Change{
		ID:          42,
		DeviceID:    "edge-gw1",
		DetectedAt:  time.Date(2026, 6, 9, 12, 30, 0, 0, time.UTC),
		Summary:     "3 findings (1 high) - 5 blocks changed",
		MaxSeverity: "high",
		ReportDir:   "/data/reports/edge-gw1/20260609-123000-abcd1234",
		Findings:    make([]store.Finding, 3),
	}
	got := EventFromChange(device, change)
	want := testEvent()
	want.ReportDir = "change-42"
	if got != want {
		t.Fatalf("EventFromChange:\n got %+v\nwant %+v", got, want)
	}
}

func TestWebhookPayload(t *testing.T) {
	var gotContentType string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	wh := &Webhook{URL: srv.URL}
	if err := wh.Notify(context.Background(), testEvent()); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
	want := map[string]any{
		"device_id":      "edge-gw1",
		"device_name":    "Edge Gateway",
		"change_id":      float64(42),
		"detected_at":    "2026-06-09T12:30:00Z",
		"summary":        "3 findings (1 high) - 5 blocks changed",
		"max_severity":   "high",
		"findings_count": float64(3),
		"report_dir":     "change-42",
	}
	for key, wantVal := range want {
		if gotBody[key] != wantVal {
			t.Errorf("payload[%q] = %v, want %v", key, gotBody[key], wantVal)
		}
	}
	if len(gotBody) != len(want) {
		t.Errorf("payload has %d keys, want %d: %v", len(gotBody), len(want), gotBody)
	}
	assertNoReportPathDisclosure(t, gotBody)
}

func TestWebhookRetriesOn5xx(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh := &Webhook{URL: srv.URL, backoff: time.Millisecond}
	if err := wh.Notify(context.Background(), testEvent()); err != nil {
		t.Fatalf("Notify after retry: %v", err)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("server saw %d requests, want 2", n)
	}
}

func TestWebhookGivesUpAfterOneRetry(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	wh := &Webhook{URL: srv.URL, backoff: time.Millisecond}
	if err := wh.Notify(context.Background(), testEvent()); err == nil {
		t.Fatal("Notify: want error on persistent 5xx, got nil")
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("server saw %d requests, want 2", n)
	}
}

func TestWebhookNoRetryOn4xx(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	wh := &Webhook{URL: srv.URL, backoff: time.Millisecond}
	if err := wh.Notify(context.Background(), testEvent()); err == nil {
		t.Fatal("Notify: want error on 4xx, got nil")
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("server saw %d requests, want 1 (no retry on 4xx)", n)
	}
}

// countingErrTransport fails every request at the transport level.
type countingErrTransport struct{ calls atomic.Int32 }

func (c *countingErrTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.calls.Add(1)
	return nil, errors.New("connection refused")
}

func TestWebhookRetriesOnNetworkError(t *testing.T) {
	tr := &countingErrTransport{}
	wh := &Webhook{
		URL:     "http://192.0.2.10/hook",
		Client:  &http.Client{Transport: tr},
		backoff: time.Millisecond,
	}
	if err := wh.Notify(context.Background(), testEvent()); err == nil {
		t.Fatal("Notify: want error on network failure, got nil")
	}
	if n := tr.calls.Load(); n != 2 {
		t.Fatalf("transport saw %d attempts, want 2", n)
	}
}

type discordPayload struct {
	Embeds []struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Color       int    `json:"color"`
		Fields      []struct {
			Name   string `json:"name"`
			Value  string `json:"value"`
			Inline bool   `json:"inline"`
		} `json:"fields"`
		Timestamp string `json:"timestamp"`
	} `json:"embeds"`
}

func TestDiscordEmbed(t *testing.T) {
	var got discordPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	d := &Discord{URL: srv.URL}
	if err := d.Notify(context.Background(), testEvent()); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if len(got.Embeds) != 1 {
		t.Fatalf("embeds: got %d, want 1", len(got.Embeds))
	}
	em := got.Embeds[0]
	if em.Title != "Config change: Edge Gateway" {
		t.Errorf("title = %q", em.Title)
	}
	if em.Description != "3 findings (1 high) - 5 blocks changed" {
		t.Errorf("description = %q", em.Description)
	}
	if em.Color != 0xE74C3C {
		t.Errorf("color = %#x, want %#x (high = red)", em.Color, 0xE74C3C)
	}
	if em.Timestamp != "2026-06-09T12:30:00Z" {
		t.Errorf("timestamp = %q", em.Timestamp)
	}
	wantFields := map[string]string{
		"Severity":  "high",
		"Findings":  "3",
		"Change ID": "42",
	}
	if len(em.Fields) != len(wantFields) {
		t.Fatalf("fields: got %d, want %d: %+v", len(em.Fields), len(wantFields), em.Fields)
	}
	for _, f := range em.Fields {
		if want, ok := wantFields[f.Name]; !ok || f.Value != want {
			t.Errorf("field %q = %q, want %q", f.Name, f.Value, want)
		}
	}
	assertNoReportPathDisclosure(t, got)
}

func TestDiscordColorBySeverity(t *testing.T) {
	tests := []struct {
		severity string
		want     int
	}{
		{"high", 0xE74C3C},
		{"medium", 0xE67E22},
		{"low", 0xF1C40F},
		{"none", 0x95A5A6},
		{"unknown", 0x95A5A6},
	}
	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			var got discordPayload
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
					t.Errorf("decode body: %v", err)
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer srv.Close()

			ev := testEvent()
			ev.MaxSeverity = tt.severity
			d := &Discord{URL: srv.URL}
			if err := d.Notify(context.Background(), ev); err != nil {
				t.Fatalf("Notify: %v", err)
			}
			if got.Embeds[0].Color != tt.want {
				t.Errorf("color = %#x, want %#x", got.Embeds[0].Color, tt.want)
			}
		})
	}
}

func TestDiscordEmptyReportDir(t *testing.T) {
	var got discordPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	ev := testEvent()
	ev.ReportDir = "" // initial snapshots have no report bundle
	d := &Discord{URL: srv.URL}
	if err := d.Notify(context.Background(), ev); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	for _, f := range got.Embeds[0].Fields {
		if f.Value == "" {
			t.Errorf("%s field has empty value; Discord rejects empty embed field values", f.Name)
		}
	}
}

func assertNoReportPathDisclosure(t *testing.T, payload any) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	for _, forbidden := range []string{
		"/data/reports",
		"edge-gw1/20260609-123000-abcd1234",
		"20260609-123000-abcd1234",
	} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("payload disclosed report path detail %q: %s", forbidden, body)
		}
	}
}

// recordingNotifier records the events it receives and optionally fails.
type recordingNotifier struct {
	events []Event
	err    error
}

func (r *recordingNotifier) Notify(_ context.Context, ev Event) error {
	r.events = append(r.events, ev)
	return r.err
}

func TestFanoutSeverityFilter(t *testing.T) {
	tests := []struct {
		minSeverity   string
		eventSeverity string
		wantNotified  bool
	}{
		{"none", "none", true}, // none = everything, including initial snapshots
		{"none", "low", true},
		{"low", "none", false},
		{"low", "low", true},
		{"low", "medium", true},
		{"low", "high", true},
		{"medium", "low", false},
		{"medium", "medium", true},
		{"high", "medium", false},
		{"high", "high", true},
		{"", "none", false}, // empty min defaults to low
		{"", "low", true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("min=%s_event=%s", tt.minSeverity, tt.eventSeverity), func(t *testing.T) {
			rec := &recordingNotifier{}
			f := &Fanout{Notifiers: []Notifier{rec}, MinSeverity: tt.minSeverity}
			ev := testEvent()
			ev.MaxSeverity = tt.eventSeverity
			f.Notify(context.Background(), ev)
			if got := len(rec.events) == 1; got != tt.wantNotified {
				t.Fatalf("notified = %t, want %t", got, tt.wantNotified)
			}
		})
	}
}

func TestFanoutIsolation(t *testing.T) {
	failing := &recordingNotifier{err: errors.New("webhook down")}
	healthy := &recordingNotifier{}
	f := &Fanout{Notifiers: []Notifier{failing, healthy}, MinSeverity: "none"}
	f.Notify(context.Background(), testEvent())
	if len(failing.events) != 1 {
		t.Fatalf("failing notifier called %d times, want 1", len(failing.events))
	}
	if len(healthy.events) != 1 {
		t.Fatalf("healthy notifier called %d times, want 1 (must not be blocked by the failing one)", len(healthy.events))
	}
}
