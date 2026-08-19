// Package snapshots stores device configuration snapshots in a server-managed
// git repository. Each device owns one canonical file
// (devices/<deviceID>/running-config) and every accepted change is a commit,
// which gives Cutsheet history, blame, and an offsite backup path for free.
package snapshots

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// ErrNoSnapshot is returned when no snapshot exists for the device.
var ErrNoSnapshot = errors.New("no snapshot for device")

const (
	authorName  = "cutsheet"
	authorEmail = "noreply@cutsheet.local"
)

var deviceIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// SaveResult describes the outcome of a Save call.
type SaveResult struct {
	// Changed is true when callers must run post-snapshot processing: either
	// a new commit was made, or HEAD is still ahead of the durable processing
	// cursor after a prior Save whose HandleChange (or equivalent) did not
	// finish.
	Changed bool
	// CommitHash is the commit containing this content: the new commit when
	// a commit was made, otherwise the existing latest commit for the device.
	CommitHash string
	// PrevCommitHash is the last successfully processed commit for this
	// device (the analysis baseline). Empty on the first snapshot.
	PrevCommitHash string
	// PrevContent is the snapshot content at PrevCommitHash. Nil on the first
	// snapshot.
	PrevContent []byte
}

// processingCursor is the crash-safe durable record of the last commit whose
// post-snapshot processing completed successfully. It is written before a new
// git commit so a crash after commit cannot make identical HEAD content look
// processed. File: devices/<id>/.processing-cursor (untracked, mode 0600).
type processingCursor struct {
	LastProcessedCommit string `json:"last_processed_commit"`
}

// legacyPendingProcessing is the pre-cursor sidecar format. Still recognized
// on read so in-flight installs migrate without silently skipping work.
type legacyPendingProcessing struct {
	CommitHash     string `json:"commit_hash"`
	PrevCommitHash string `json:"prev_commit_hash,omitempty"`
}

// SnapshotStore is a git-backed store of device config snapshots. It is safe
// for concurrent use.
type SnapshotStore struct {
	mu   sync.Mutex
	dir  string
	repo *git.Repository
}

// Open opens the snapshot repository at dir, initializing a plain repository
// with a filesystem worktree if none exists.
func Open(dir string) (*SnapshotStore, error) {
	repo, err := git.PlainOpen(dir)
	if errors.Is(err, git.ErrRepositoryNotExists) {
		if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
			return nil, fmt.Errorf("create snapshot dir: %w", mkErr)
		}
		repo, err = git.PlainInit(dir, false)
	}
	if err != nil {
		return nil, fmt.Errorf("open snapshot repo %s: %w", dir, err)
	}
	return &SnapshotStore{dir: dir, repo: repo}, nil
}

// Save records content as the latest snapshot for deviceID. New or changed
// content is committed only after the processed baseline cursor is persisted.
// Identical content is a no-op (Changed=false) only when HEAD equals the
// cursor's last processed commit. While HEAD is ahead of the cursor, Save
// returns Changed=true with Prev* taken from the cursor so scheduler and
// on-demand paths retry analysis from the last successful baseline (P→HEAD),
// including when intermediate unprocessed commits were superseded.
func (s *SnapshotStore) Save(deviceID string, content []byte) (SaveResult, error) {
	if err := validateDeviceID(deviceID); err != nil {
		return SaveResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	path := devicePath(deviceID)
	prev, prevExists, err := s.headFileContent(path)
	if err != nil {
		return SaveResult{}, fmt.Errorf("read previous snapshot for %s: %w", deviceID, err)
	}
	if prevExists && bytes.Equal(prev, content) {
		lastHash, err := s.lastCommitFor(path)
		if err != nil {
			return SaveResult{}, fmt.Errorf("resolve latest commit for %s: %w", deviceID, err)
		}
		return s.resultForIdentical(deviceID, lastHash)
	}

	baseline, err := s.ensureBaselineBeforeCommit(deviceID, prevExists, path)
	if err != nil {
		return SaveResult{}, err
	}

	fullPath := filepath.Join(s.dir, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		return SaveResult{}, fmt.Errorf("create device dir: %w", err)
	}
	if err := os.WriteFile(fullPath, content, 0o600); err != nil {
		return SaveResult{}, fmt.Errorf("write snapshot file: %w", err)
	}

	wt, err := s.repo.Worktree()
	if err != nil {
		return SaveResult{}, fmt.Errorf("open worktree: %w", err)
	}
	if _, err := wt.Add(path); err != nil {
		return SaveResult{}, fmt.Errorf("stage snapshot: %w", err)
	}
	hash, err := wt.Commit("snapshot: "+deviceID, &git.CommitOptions{
		Author: &object.Signature{Name: authorName, Email: authorEmail, When: time.Now()},
	})
	if err != nil {
		return SaveResult{}, fmt.Errorf("commit snapshot for %s: %w", deviceID, err)
	}

	return s.resultFromBaseline(deviceID, hash.String(), baseline)
}

// MarkProcessed advances the durable processing cursor for deviceID to
// commitHash after pipeline.HandleChange (or equivalent) succeeds. The cursor
// advances only when commitHash is the device's current HEAD commit; stale
// acks are a no-op so superseded or duplicate completions stay safe.
func (s *SnapshotStore) MarkProcessed(deviceID, commitHash string) error {
	if err := validateDeviceID(deviceID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if commitHash == "" {
		return fmt.Errorf("mark processed for %s: empty commit hash", deviceID)
	}
	lastHash, err := s.lastCommitFor(devicePath(deviceID))
	if err != nil {
		return fmt.Errorf("resolve latest commit for %s: %w", deviceID, err)
	}
	if lastHash == "" || commitHash != lastHash {
		return nil
	}
	if err := s.writeCursor(deviceID, processingCursor{LastProcessedCommit: commitHash}); err != nil {
		return err
	}
	// Drop any legacy pending sidecar once the cursor is authoritative.
	if err := os.Remove(s.pendingPath(deviceID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear legacy pending for %s: %w", deviceID, err)
	}
	return nil
}

// Get returns the current (HEAD) snapshot content for deviceID.
func (s *SnapshotStore) Get(deviceID string) ([]byte, error) {
	if err := validateDeviceID(deviceID); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	content, exists, err := s.headFileContent(devicePath(deviceID))
	if err != nil {
		return nil, fmt.Errorf("read snapshot for %s: %w", deviceID, err)
	}
	if !exists {
		return nil, fmt.Errorf("device %s: %w", deviceID, ErrNoSnapshot)
	}
	return content, nil
}

// GetAt returns the snapshot content for deviceID as of the given commit.
func (s *SnapshotStore) GetAt(deviceID, commitHash string) ([]byte, error) {
	if err := validateDeviceID(deviceID); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	commit, err := s.repo.CommitObject(plumbing.NewHash(commitHash))
	if err != nil {
		return nil, fmt.Errorf("resolve commit %s: %w", commitHash, err)
	}
	content, exists, err := fileContent(commit, devicePath(deviceID))
	if err != nil {
		return nil, fmt.Errorf("read snapshot for %s at %s: %w", deviceID, commitHash, err)
	}
	if !exists {
		return nil, fmt.Errorf("device %s at %s: %w", deviceID, commitHash, ErrNoSnapshot)
	}
	return content, nil
}

func devicePath(deviceID string) string {
	return "devices/" + deviceID + "/running-config"
}

func cursorRelPath(deviceID string) string {
	return "devices/" + deviceID + "/.processing-cursor"
}

func pendingRelPath(deviceID string) string {
	return "devices/" + deviceID + "/.pending-processing"
}

func (s *SnapshotStore) cursorPath(deviceID string) string {
	return filepath.Join(s.dir, filepath.FromSlash(cursorRelPath(deviceID)))
}

func (s *SnapshotStore) pendingPath(deviceID string) string {
	return filepath.Join(s.dir, filepath.FromSlash(pendingRelPath(deviceID)))
}

// ensureBaselineBeforeCommit persists the processing cursor before mutating
// git HEAD. For pre-feature repos with no cursor, HEAD is treated as already
// processed (safe upgrade). For a brand-new device, an empty cursor is written
// so a crash after the first commit cannot be mistaken for an upgrade skip.
func (s *SnapshotStore) ensureBaselineBeforeCommit(deviceID string, prevExists bool, path string) (processingCursor, error) {
	cur, status, err := s.loadCursor(deviceID)
	if err != nil {
		return processingCursor{}, err
	}
	switch status {
	case cursorOK:
		return *cur, nil
	case cursorMissing:
		if !prevExists {
			empty := processingCursor{LastProcessedCommit: ""}
			if err := s.writeCursor(deviceID, empty); err != nil {
				return processingCursor{}, err
			}
			return empty, nil
		}
		headHash, err := s.lastCommitFor(path)
		if err != nil {
			return processingCursor{}, fmt.Errorf("resolve previous commit for %s: %w", deviceID, err)
		}
		upgraded := processingCursor{LastProcessedCommit: headHash}
		if err := s.writeCursor(deviceID, upgraded); err != nil {
			return processingCursor{}, err
		}
		return upgraded, nil
	case cursorCorrupt, cursorStale:
		// Conservative recovery: keep last_processed behind HEAD so work is
		// retried. Prefer the git predecessor of HEAD when available.
		baseline := processingCursor{LastProcessedCommit: ""}
		if prevExists {
			headHash, err := s.lastCommitFor(path)
			if err != nil {
				return processingCursor{}, err
			}
			prevHash, err := s.previousCommitFor(path, headHash)
			if err != nil {
				return processingCursor{}, err
			}
			baseline.LastProcessedCommit = prevHash
		}
		if err := s.writeCursor(deviceID, baseline); err != nil {
			return processingCursor{}, err
		}
		return baseline, nil
	default:
		return processingCursor{}, fmt.Errorf("unknown cursor status for %s", deviceID)
	}
}

func (s *SnapshotStore) resultForIdentical(deviceID, headHash string) (SaveResult, error) {
	cur, status, err := s.loadCursor(deviceID)
	if err != nil {
		return SaveResult{}, err
	}
	switch status {
	case cursorMissing:
		// Pre-feature upgrade: identical HEAD with no cursor is already
		// durable history; seed the cursor and skip re-analysis.
		if err := s.writeCursor(deviceID, processingCursor{LastProcessedCommit: headHash}); err != nil {
			return SaveResult{}, err
		}
		_ = os.Remove(s.pendingPath(deviceID))
		return SaveResult{Changed: false, CommitHash: headHash}, nil
	case cursorCorrupt, cursorStale:
		baseline := processingCursor{LastProcessedCommit: ""}
		prevHash, err := s.previousCommitFor(devicePath(deviceID), headHash)
		if err != nil {
			return SaveResult{}, err
		}
		baseline.LastProcessedCommit = prevHash
		if err := s.writeCursor(deviceID, baseline); err != nil {
			return SaveResult{}, err
		}
		_ = os.Remove(s.pendingPath(deviceID))
		return s.resultFromBaseline(deviceID, headHash, baseline)
	case cursorOK:
		if cur.LastProcessedCommit == headHash {
			return SaveResult{Changed: false, CommitHash: headHash}, nil
		}
		return s.resultFromBaseline(deviceID, headHash, *cur)
	default:
		return SaveResult{}, fmt.Errorf("unknown cursor status for %s", deviceID)
	}
}

func (s *SnapshotStore) resultFromBaseline(deviceID, commitHash string, baseline processingCursor) (SaveResult, error) {
	var prevContent []byte
	if baseline.LastProcessedCommit != "" {
		commit, err := s.repo.CommitObject(plumbing.NewHash(baseline.LastProcessedCommit))
		if err != nil {
			return SaveResult{}, fmt.Errorf("resolve processed commit %s for %s: %w", baseline.LastProcessedCommit, deviceID, err)
		}
		content, exists, err := fileContent(commit, devicePath(deviceID))
		if err != nil {
			return SaveResult{}, fmt.Errorf("read processed content for %s: %w", deviceID, err)
		}
		if !exists {
			return SaveResult{}, fmt.Errorf("processed content for %s at %s: %w", deviceID, baseline.LastProcessedCommit, ErrNoSnapshot)
		}
		prevContent = content
	}
	return SaveResult{
		Changed:        true,
		CommitHash:     commitHash,
		PrevCommitHash: baseline.LastProcessedCommit,
		PrevContent:    prevContent,
	}, nil
}

type cursorStatus int

const (
	cursorOK cursorStatus = iota
	cursorMissing
	cursorCorrupt
	cursorStale
)

// loadCursor reads the durable cursor, migrating a legacy pending sidecar when
// present. Corrupt JSON and cursors that name an unknown commit are reported
// as recoverable statuses (never as a sticky hard error that blocks polls).
func (s *SnapshotStore) loadCursor(deviceID string) (*processingCursor, cursorStatus, error) {
	if migrated, ok, err := s.migrateLegacyPending(deviceID); err != nil {
		return nil, cursorMissing, err
	} else if ok {
		return migrated, cursorOK, nil
	}

	data, err := os.ReadFile(s.cursorPath(deviceID))
	if errors.Is(err, os.ErrNotExist) {
		return nil, cursorMissing, nil
	}
	if err != nil {
		return nil, cursorMissing, fmt.Errorf("read processing cursor for %s: %w", deviceID, err)
	}
	var cur processingCursor
	if err := json.Unmarshal(data, &cur); err != nil {
		return nil, cursorCorrupt, nil
	}
	// Missing key unmarshals to ""; that is a valid "nothing processed yet"
	// cursor written before the first commit. Distinguish corrupt empty files.
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, cursorCorrupt, nil
	}
	if cur.LastProcessedCommit != "" {
		if _, err := s.repo.CommitObject(plumbing.NewHash(cur.LastProcessedCommit)); err != nil {
			return nil, cursorStale, nil
		}
	}
	return &cur, cursorOK, nil
}

func (s *SnapshotStore) migrateLegacyPending(deviceID string) (*processingCursor, bool, error) {
	data, err := os.ReadFile(s.pendingPath(deviceID))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read legacy pending for %s: %w", deviceID, err)
	}
	var pending legacyPendingProcessing
	if err := json.Unmarshal(data, &pending); err != nil || pending.CommitHash == "" {
		_ = os.Remove(s.pendingPath(deviceID))
		return nil, false, nil
	}
	// Cursor baseline is the last successful process point (prev), not the
	// unprocessed pending commit — so retries and supersedes use P, not A.
	cur := processingCursor{LastProcessedCommit: pending.PrevCommitHash}
	if err := s.writeCursor(deviceID, cur); err != nil {
		return nil, false, err
	}
	if err := os.Remove(s.pendingPath(deviceID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, false, fmt.Errorf("remove legacy pending for %s: %w", deviceID, err)
	}
	return &cur, true, nil
}

func (s *SnapshotStore) readCursor(deviceID string) (*processingCursor, error) {
	cur, status, err := s.loadCursor(deviceID)
	if err != nil {
		return nil, err
	}
	if status != cursorOK {
		return nil, nil
	}
	return cur, nil
}

func (s *SnapshotStore) writeCursor(deviceID string, cur processingCursor) error {
	path := s.cursorPath(deviceID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create cursor dir for %s: %w", deviceID, err)
	}
	data, err := json.Marshal(cur)
	if err != nil {
		return fmt.Errorf("encode processing cursor for %s: %w", deviceID, err)
	}
	if err := writeFileAtomic(path, data, 0o600); err != nil {
		return fmt.Errorf("write processing cursor for %s: %w", deviceID, err)
	}
	return nil
}

// writeFileAtomic publishes data at path via temp+rename with the given mode.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".processing-cursor-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// previousCommitFor returns the commit before headHash that touched path, or
// "" when headHash is the first commit for that path.
func (s *SnapshotStore) previousCommitFor(path, headHash string) (string, error) {
	if headHash == "" {
		return "", nil
	}
	iter, err := s.repo.Log(&git.LogOptions{FileName: &path})
	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer iter.Close()
	seenHead := false
	for {
		commit, err := iter.Next()
		if errors.Is(err, io.EOF) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		if !seenHead {
			if commit.Hash.String() == headHash {
				seenHead = true
			}
			continue
		}
		return commit.Hash.String(), nil
	}
}

func validateDeviceID(deviceID string) error {
	if !deviceIDPattern.MatchString(deviceID) {
		return fmt.Errorf("invalid device id %q", deviceID)
	}
	return nil
}

// headFileContent returns the content of path in the HEAD commit, with exists
// reporting whether the file (or HEAD itself) is present.
func (s *SnapshotStore) headFileContent(path string) ([]byte, bool, error) {
	head, err := s.repo.Head()
	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		return nil, false, nil // empty repository
	}
	if err != nil {
		return nil, false, err
	}
	commit, err := s.repo.CommitObject(head.Hash())
	if err != nil {
		return nil, false, err
	}
	return fileContent(commit, path)
}

func fileContent(commit *object.Commit, path string) ([]byte, bool, error) {
	file, err := commit.File(path)
	if errors.Is(err, object.ErrFileNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	reader, err := file.Reader()
	if err != nil {
		return nil, false, err
	}
	defer reader.Close()
	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, false, err
	}
	return content, true, nil
}

// lastCommitFor returns the hash of the most recent commit that touched path,
// or "" if no commit has.
func (s *SnapshotStore) lastCommitFor(path string) (string, error) {
	iter, err := s.repo.Log(&git.LogOptions{FileName: &path})
	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		return "", nil // empty repository
	}
	if err != nil {
		return "", err
	}
	defer iter.Close()
	commit, err := iter.Next()
	if errors.Is(err, io.EOF) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return commit.Hash.String(), nil
}
