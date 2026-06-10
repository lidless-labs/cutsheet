package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/solomonneas/cutsheet/internal/store"
)

const (
	defaultChangeLimit = 50
	maxChangeLimit     = 500
)

// changeJSON is the timeline (list) form of a change: no findings, no
// analysis blob.
type changeJSON struct {
	ID             int64     `json:"id"`
	DeviceID       string    `json:"device_id"`
	DetectedAt     time.Time `json:"detected_at"`
	CommitHash     string    `json:"commit_hash"`
	PrevCommitHash string    `json:"prev_commit_hash"`
	Summary        string    `json:"summary"`
	MaxSeverity    string    `json:"max_severity"`
	HasReport      bool      `json:"has_report"`
}

// changeDetailJSON adds the analysis document and findings.
type changeDetailJSON struct {
	changeJSON
	Analysis json.RawMessage `json:"analysis"`
	Findings []findingJSON   `json:"findings"`
}

type findingJSON struct {
	ID             int64  `json:"id"`
	FindingID      string `json:"finding_id"`
	Severity       string `json:"severity"`
	Category       string `json:"category"`
	Title          string `json:"title"`
	Recommendation string `json:"recommendation"`
}

func toChangeJSON(c store.Change) changeJSON {
	return changeJSON{
		ID:             c.ID,
		DeviceID:       c.DeviceID,
		DetectedAt:     c.DetectedAt.UTC(),
		CommitHash:     c.CommitHash,
		PrevCommitHash: c.PrevCommitHash,
		Summary:        c.Summary,
		MaxSeverity:    c.MaxSeverity,
		HasReport:      c.ReportDir != "",
	}
}

func toChangeDetailJSON(c store.Change) changeDetailJSON {
	detail := changeDetailJSON{
		changeJSON: toChangeJSON(c),
		Analysis:   json.RawMessage("null"),
		Findings:   make([]findingJSON, 0, len(c.Findings)),
	}
	if json.Valid([]byte(c.AnalysisJSON)) && c.AnalysisJSON != "" {
		detail.Analysis = json.RawMessage(c.AnalysisJSON)
	}
	for _, f := range c.Findings {
		detail.Findings = append(detail.Findings, findingJSON{
			ID:             f.ID,
			FindingID:      f.FindingID,
			Severity:       f.Severity,
			Category:       f.Category,
			Title:          f.Title,
			Recommendation: f.Recommendation,
		})
	}
	return detail
}

func (s *Server) handleChangeList(w http.ResponseWriter, r *http.Request) {
	limit, err := queryInt(r, "limit", defaultChangeLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if limit <= 0 {
		limit = defaultChangeLimit
	}
	if limit > maxChangeLimit {
		limit = maxChangeLimit
	}
	offset, err := queryInt(r, "offset", 0)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if offset < 0 {
		offset = 0
	}
	minSeverity := r.URL.Query().Get("min_severity")
	if minSeverity != "" && !validSeverity(minSeverity) {
		writeError(w, http.StatusBadRequest, "bad_request",
			"invalid min_severity: use none, low, medium, or high")
		return
	}

	changes, err := s.cfg.Store.ListChanges(r.Context(), store.ListChangesOptions{
		DeviceID:    r.URL.Query().Get("device_id"),
		Limit:       limit,
		Offset:      offset,
		MinSeverity: minSeverity,
	})
	if err != nil {
		s.writeStoreError(w, err, "list changes")
		return
	}
	out := make([]changeJSON, 0, len(changes))
	for _, c := range changes {
		out = append(out, toChangeJSON(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"changes": out,
		"limit":   limit,
		"offset":  offset,
	})
}

// changeFromPath loads the change addressed by the {id} path segment.
func (s *Server) changeFromPath(w http.ResponseWriter, r *http.Request) (store.Change, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid change id")
		return store.Change{}, false
	}
	c, err := s.cfg.Store.GetChange(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "get change")
		return store.Change{}, false
	}
	return c, true
}

func (s *Server) handleChangeGet(w http.ResponseWriter, r *http.Request) {
	c, ok := s.changeFromPath(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, toChangeDetailJSON(c))
}

// reportNamePattern is the allowlist for servable report files: a clean
// basename (letters, digits, . _ -, no leading dot) ending in .md, .html, or
// .json. Everything else, including any path syntax, is rejected.
var reportNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*\.(md|html|json)$`)

// validReportName reports whether name is a safe, allowlisted report file
// basename. Path traversal is impossible by construction: no separators, no
// ".." sequences, no leading dot, and the joined path is re-checked against
// the report dir by the caller anyway.
func validReportName(name string) bool {
	if strings.Contains(name, "..") || strings.ContainsAny(name, `/\`) {
		return false
	}
	if name != filepath.Base(name) {
		return false
	}
	return reportNamePattern.MatchString(name)
}

type reportFileJSON struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

func (s *Server) handleReportList(w http.ResponseWriter, r *http.Request) {
	c, ok := s.changeFromPath(w, r)
	if !ok {
		return
	}
	reports := make([]reportFileJSON, 0)
	if c.ReportDir != "" {
		entries, err := os.ReadDir(c.ReportDir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			s.cfg.Logger.Error("read report dir failed", "change", c.ID, "error", err)
			writeError(w, http.StatusInternalServerError, "internal", "read report dir failed")
			return
		}
		for _, entry := range entries {
			if entry.IsDir() || !validReportName(entry.Name()) {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			reports = append(reports, reportFileJSON{Name: entry.Name(), Size: info.Size()})
		}
		sort.Slice(reports, func(i, j int) bool { return reports[i].Name < reports[j].Name })
	}
	writeJSON(w, http.StatusOK, map[string]any{"reports": reports})
}

func (s *Server) handleReportFile(w http.ResponseWriter, r *http.Request) {
	c, ok := s.changeFromPath(w, r)
	if !ok {
		return
	}
	name := r.PathValue("name")
	if !validReportName(name) {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid report name")
		return
	}
	if c.ReportDir == "" {
		writeError(w, http.StatusNotFound, "not_found", "change has no report bundle")
		return
	}

	// Belt and suspenders: even with the strict name allowlist, verify the
	// joined path stays inside the report dir.
	dir := filepath.Clean(c.ReportDir)
	path := filepath.Join(dir, name)
	if filepath.Dir(path) != dir {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid report name")
		return
	}

	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "not_found", "report file not found")
		return
	}
	if err != nil {
		s.cfg.Logger.Error("read report file failed", "change", c.ID, "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "read report file failed")
		return
	}

	// text/html is reserved for the rendered report.html; every other file is
	// served inert (JSON as JSON, the rest as plain text) so a crafted file in
	// a report dir can never become a stored-XSS vehicle.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	switch {
	case name == "report.html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case strings.HasSuffix(name, ".json"):
		w.Header().Set("Content-Type", "application/json")
	default:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (s *Server) handleSnapshotNow(w http.ResponseWriter, r *http.Request) {
	if s.cfg.SnapshotNow == nil {
		writeError(w, http.StatusNotImplemented, "not_implemented", "snapshot-now is not wired on this server")
		return
	}
	deviceID := r.PathValue("id")
	if _, err := s.cfg.Store.GetDevice(r.Context(), deviceID); err != nil {
		s.writeStoreError(w, err, "get device")
		return
	}

	change, changed, err := s.cfg.SnapshotNow(r.Context(), deviceID)
	if err != nil {
		s.cfg.Logger.Error("snapshot now failed", "device", deviceID, "error", err)
		writeError(w, http.StatusBadGateway, "snapshot_failed", err.Error())
		return
	}
	if !changed {
		writeJSON(w, http.StatusOK, map[string]any{"changed": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"changed": true,
		"change":  toChangeDetailJSON(*change),
	})
}
