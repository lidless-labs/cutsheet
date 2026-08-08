package snapshots

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func openTestStore(t *testing.T) *SnapshotStore {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func TestFirstSaveCommits(t *testing.T) {
	s := openTestStore(t)

	res, err := s.Save("gw1", []byte("hostname gw1\n"))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !res.Changed {
		t.Fatal("first save: Changed = false, want true")
	}
	if res.CommitHash == "" {
		t.Fatal("first save: empty CommitHash")
	}
	if res.PrevCommitHash != "" {
		t.Fatalf("first save: PrevCommitHash = %q, want empty", res.PrevCommitHash)
	}
	if res.PrevContent != nil {
		t.Fatalf("first save: PrevContent = %q, want nil", res.PrevContent)
	}

	got, err := s.Get("gw1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "hostname gw1\n" {
		t.Fatalf("Get: got %q", got)
	}
}

func TestIdenticalSaveIsNoOp(t *testing.T) {
	s := openTestStore(t)
	content := []byte("hostname gw1\n")

	first, err := s.Save("gw1", content)
	if err != nil {
		t.Fatalf("first Save: %v", err)
	}
	if err := s.MarkProcessed("gw1", first.CommitHash); err != nil {
		t.Fatalf("MarkProcessed: %v", err)
	}
	second, err := s.Save("gw1", content)
	if err != nil {
		t.Fatalf("second Save: %v", err)
	}
	if second.Changed {
		t.Fatal("identical save: Changed = true, want false")
	}
	if second.CommitHash != first.CommitHash {
		t.Fatalf("identical save: CommitHash = %q, want %q (no new commit)", second.CommitHash, first.CommitHash)
	}
}

// TestSaveRetriesIdenticalContentWhileUnprocessed pins issue #15: committing
// observed config before pipeline.HandleChange succeeds must not make the next
// identical poll a permanent no-op. Until processing is acknowledged, Save
// keeps Changed=true and preserves prev linkage for analysis.
func TestSaveRetriesIdenticalContentWhileUnprocessed(t *testing.T) {
	s := openTestStore(t)
	before := []byte("hostname gw1\n")
	after := []byte("hostname gw1\nntp server 192.0.2.10\n")

	initial, err := s.Save("gw1", before)
	if err != nil {
		t.Fatalf("initial Save: %v", err)
	}
	if err := s.MarkProcessed("gw1", initial.CommitHash); err != nil {
		t.Fatalf("MarkProcessed initial: %v", err)
	}
	changed, err := s.Save("gw1", after)
	if err != nil {
		t.Fatalf("changed Save: %v", err)
	}
	if !changed.Changed {
		t.Fatal("changed Save: Changed = false, want true")
	}

	// Processing failed after the commit: identical content must still be
	// reported as Changed so scheduler/on-demand retry HandleChange.
	retry, err := s.Save("gw1", after)
	if err != nil {
		t.Fatalf("retry Save: %v", err)
	}
	if !retry.Changed {
		t.Fatal("unprocessed identical Save: Changed = false, want true")
	}
	if retry.CommitHash != changed.CommitHash {
		t.Fatalf("retry CommitHash = %q, want %q", retry.CommitHash, changed.CommitHash)
	}
	if retry.PrevCommitHash != changed.PrevCommitHash {
		t.Fatalf("retry PrevCommitHash = %q, want %q", retry.PrevCommitHash, changed.PrevCommitHash)
	}
	if string(retry.PrevContent) != string(before) {
		t.Fatalf("retry PrevContent = %q, want %q", retry.PrevContent, before)
	}

	if err := s.MarkProcessed("gw1", changed.CommitHash); err != nil {
		t.Fatalf("MarkProcessed: %v", err)
	}
	done, err := s.Save("gw1", after)
	if err != nil {
		t.Fatalf("post-process Save: %v", err)
	}
	if done.Changed {
		t.Fatal("after MarkProcessed: Changed = true, want false")
	}
}

func TestChangedSaveReturnsPrevContent(t *testing.T) {
	s := openTestStore(t)

	first, err := s.Save("gw1", []byte("hostname gw1\nsnmp-server community alpha\n"))
	if err != nil {
		t.Fatalf("first Save: %v", err)
	}
	if err := s.MarkProcessed("gw1", first.CommitHash); err != nil {
		t.Fatalf("MarkProcessed: %v", err)
	}
	second, err := s.Save("gw1", []byte("hostname gw1\n"))
	if err != nil {
		t.Fatalf("second Save: %v", err)
	}
	if !second.Changed {
		t.Fatal("changed save: Changed = false, want true")
	}
	if second.CommitHash == "" || second.CommitHash == first.CommitHash {
		t.Fatalf("changed save: CommitHash = %q (first %q)", second.CommitHash, first.CommitHash)
	}
	if second.PrevCommitHash != first.CommitHash {
		t.Fatalf("changed save: PrevCommitHash = %q, want %q", second.PrevCommitHash, first.CommitHash)
	}
	if string(second.PrevContent) != "hostname gw1\nsnmp-server community alpha\n" {
		t.Fatalf("changed save: PrevContent = %q", second.PrevContent)
	}

	// Historical content is retrievable by commit hash.
	old, err := s.GetAt("gw1", first.CommitHash)
	if err != nil {
		t.Fatalf("GetAt: %v", err)
	}
	if string(old) != "hostname gw1\nsnmp-server community alpha\n" {
		t.Fatalf("GetAt: got %q", old)
	}
	cur, err := s.Get("gw1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(cur) != "hostname gw1\n" {
		t.Fatalf("Get: got %q", cur)
	}
}

func TestMultipleDevicesDoNotInterfere(t *testing.T) {
	s := openTestStore(t)

	gwFirst, err := s.Save("gw1", []byte("hostname gw1\n"))
	if err != nil {
		t.Fatalf("Save gw1: %v", err)
	}
	if err := s.MarkProcessed("gw1", gwFirst.CommitHash); err != nil {
		t.Fatalf("MarkProcessed gw1: %v", err)
	}
	swRes, err := s.Save("sw1", []byte("hostname sw1\n"))
	if err != nil {
		t.Fatalf("Save sw1: %v", err)
	}
	if !swRes.Changed {
		t.Fatal("sw1 first save: Changed = false")
	}
	if swRes.PrevCommitHash != "" {
		t.Fatalf("sw1 first save: PrevCommitHash = %q, want empty (gw1 commits must not count)", swRes.PrevCommitHash)
	}
	if err := s.MarkProcessed("sw1", swRes.CommitHash); err != nil {
		t.Fatalf("MarkProcessed sw1: %v", err)
	}

	// Changing gw1 must not affect sw1's prev tracking.
	gwRes, err := s.Save("gw1", []byte("hostname gw1-renamed\n"))
	if err != nil {
		t.Fatalf("Save gw1 change: %v", err)
	}
	if !gwRes.Changed {
		t.Fatal("gw1 change: Changed = false")
	}
	if string(gwRes.PrevContent) != "hostname gw1\n" {
		t.Fatalf("gw1 change: PrevContent = %q", gwRes.PrevContent)
	}

	sw, err := s.Get("sw1")
	if err != nil {
		t.Fatalf("Get sw1: %v", err)
	}
	if string(sw) != "hostname sw1\n" {
		t.Fatalf("Get sw1: got %q", sw)
	}
}

func TestReopenExistingRepo(t *testing.T) {
	dir := t.TempDir()
	s1, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	first, err := s1.Save("gw1", []byte("hostname gw1\n"))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := s1.MarkProcessed("gw1", first.CommitHash); err != nil {
		t.Fatalf("MarkProcessed: %v", err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	res, err := s2.Save("gw1", []byte("hostname gw1\n"))
	if err != nil {
		t.Fatalf("Save after reopen: %v", err)
	}
	if res.Changed {
		t.Fatal("identical save after reopen: Changed = true, want false")
	}
	if res.CommitHash != first.CommitHash {
		t.Fatalf("after reopen: CommitHash = %q, want %q", res.CommitHash, first.CommitHash)
	}
}

func TestGetUnknownDevice(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.Get("ghost"); !errors.Is(err, ErrNoSnapshot) {
		t.Fatalf("Get ghost: got %v, want ErrNoSnapshot", err)
	}
}

func TestInvalidDeviceID(t *testing.T) {
	s := openTestStore(t)
	for _, id := range []string{"", "../escape", "a/b", "a\\b", "."} {
		if _, err := s.Save(id, []byte("x")); err == nil {
			t.Errorf("Save(%q): want error, got nil", id)
		}
		if err := s.MarkProcessed(id, "deadbeef"); err == nil {
			t.Errorf("MarkProcessed(%q): want error, got nil", id)
		}
	}
}

// TestSaveCrashAfterCommitRetainsProcessedBaseline proves issue #15 crash
// safety: the durable cursor records the last processed commit before a new
// git commit, so losing any post-commit sidecar cannot make identical HEAD
// content look already processed.
func TestSaveCrashAfterCommitRetainsProcessedBaseline(t *testing.T) {
	s := openTestStore(t)
	before := []byte("hostname gw1\n")
	after := []byte("hostname gw1\nntp server 192.0.2.10\n")

	initial, err := s.Save("gw1", before)
	if err != nil {
		t.Fatalf("initial Save: %v", err)
	}
	if err := s.MarkProcessed("gw1", initial.CommitHash); err != nil {
		t.Fatalf("MarkProcessed: %v", err)
	}

	changed, err := s.Save("gw1", after)
	if err != nil {
		t.Fatalf("changed Save: %v", err)
	}
	if !changed.Changed {
		t.Fatal("changed Save: Changed = false, want true")
	}
	if changed.PrevCommitHash != initial.CommitHash {
		t.Fatalf("changed PrevCommitHash = %q, want %q", changed.PrevCommitHash, initial.CommitHash)
	}

	// Crash/failure window: destroy legacy/post-commit pending sidecars only.
	// The processing cursor must still identify initial as last processed.
	_ = os.Remove(s.pendingPath("gw1"))
	cur, err := s.readCursor("gw1")
	if err != nil {
		t.Fatalf("readCursor: %v", err)
	}
	if cur == nil || cur.LastProcessedCommit != initial.CommitHash {
		t.Fatalf("cursor after commit = %+v, want last_processed=%q", cur, initial.CommitHash)
	}

	retry, err := s.Save("gw1", after)
	if err != nil {
		t.Fatalf("retry Save: %v", err)
	}
	if !retry.Changed {
		t.Fatal("after crash window: Changed = false, want true (baseline must not skip work)")
	}
	if retry.CommitHash != changed.CommitHash {
		t.Fatalf("retry CommitHash = %q, want %q", retry.CommitHash, changed.CommitHash)
	}
	if retry.PrevCommitHash != initial.CommitHash {
		t.Fatalf("retry PrevCommitHash = %q, want last processed %q", retry.PrevCommitHash, initial.CommitHash)
	}
	if string(retry.PrevContent) != string(before) {
		t.Fatalf("retry PrevContent = %q, want %q", retry.PrevContent, before)
	}
}

// TestSaveSupersedeUsesLastProcessedNotIntermediateHEAD: if A is still
// unprocessed and B arrives, analysis must cover P→B, not A→B.
func TestSaveSupersedeUsesLastProcessedNotIntermediateHEAD(t *testing.T) {
	s := openTestStore(t)
	pContent := []byte("hostname gw1\n")
	aContent := []byte("hostname gw1\nntp server 192.0.2.10\n")
	bContent := []byte("hostname gw1\nntp server 192.0.2.10\nntp server 192.0.2.11\n")

	p, err := s.Save("gw1", pContent)
	if err != nil {
		t.Fatalf("Save P: %v", err)
	}
	if err := s.MarkProcessed("gw1", p.CommitHash); err != nil {
		t.Fatalf("MarkProcessed P: %v", err)
	}
	a, err := s.Save("gw1", aContent)
	if err != nil {
		t.Fatalf("Save A: %v", err)
	}
	if !a.Changed || a.PrevCommitHash != p.CommitHash {
		t.Fatalf("Save A: %+v, want Changed with Prev=%q", a, p.CommitHash)
	}

	b, err := s.Save("gw1", bContent)
	if err != nil {
		t.Fatalf("Save B: %v", err)
	}
	if !b.Changed {
		t.Fatal("Save B: Changed = false, want true")
	}
	if b.PrevCommitHash != p.CommitHash {
		t.Fatalf("Save B PrevCommitHash = %q, want last processed P %q (not intermediate A %q)",
			b.PrevCommitHash, p.CommitHash, a.CommitHash)
	}
	if string(b.PrevContent) != string(pContent) {
		t.Fatalf("Save B PrevContent = %q, want P content %q", b.PrevContent, pContent)
	}
}

func TestProcessingCursorModeAndAtomicReplace(t *testing.T) {
	s := openTestStore(t)
	first, err := s.Save("gw1", []byte("hostname gw1\n"))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	path := s.cursorPath("gw1")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat cursor: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cursor mode = %o, want 0600", info.Mode().Perm())
	}

	// Replace with known bytes, then MarkProcessed must atomically publish a
	// full valid cursor (no truncated leftover) at mode 0600.
	if err := os.WriteFile(path, []byte(`{"last_processed_commit":"stale"}`), 0o644); err != nil {
		t.Fatalf("seed stale cursor: %v", err)
	}
	if err := s.MarkProcessed("gw1", first.CommitHash); err != nil {
		t.Fatalf("MarkProcessed: %v", err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatalf("stat cursor after MarkProcessed: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cursor mode after replace = %o, want 0600", info.Mode().Perm())
	}
	var cur processingCursor
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cursor: %v", err)
	}
	if err := json.Unmarshal(data, &cur); err != nil {
		t.Fatalf("cursor JSON: %v\n%s", err, data)
	}
	if cur.LastProcessedCommit != first.CommitHash {
		t.Fatalf("cursor = %+v, want last_processed=%q", cur, first.CommitHash)
	}
}

func TestCorruptCursorRecoversWithoutSkipping(t *testing.T) {
	s := openTestStore(t)
	content := []byte("hostname gw1\n")
	first, err := s.Save("gw1", content)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := s.MarkProcessed("gw1", first.CommitHash); err != nil {
		t.Fatalf("MarkProcessed: %v", err)
	}
	if err := os.WriteFile(s.cursorPath("gw1"), []byte("not-json{"), 0o600); err != nil {
		t.Fatalf("corrupt cursor: %v", err)
	}

	retry, err := s.Save("gw1", content)
	if err != nil {
		t.Fatalf("Save with corrupt cursor: %v (want recovery, not sticky failure)", err)
	}
	if !retry.Changed {
		t.Fatal("corrupt cursor recovery: Changed = false (silently skipped work)")
	}
	if retry.CommitHash != first.CommitHash {
		t.Fatalf("retry CommitHash = %q, want %q", retry.CommitHash, first.CommitHash)
	}
}

func TestStaleCursorRemovedOnMismatch(t *testing.T) {
	s := openTestStore(t)
	content := []byte("hostname gw1\n")
	first, err := s.Save("gw1", content)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := s.MarkProcessed("gw1", first.CommitHash); err != nil {
		t.Fatalf("MarkProcessed: %v", err)
	}
	// Stale cursor naming a commit that is not last-processed-compatible:
	// point at a fake hash while HEAD content is already processed. Recovery
	// must not leave the stale file ignored forever.
	if err := s.writeCursor("gw1", processingCursor{LastProcessedCommit: "0" + first.CommitHash[1:]}); err != nil {
		// If hash tweak collided, force a clearly unknown hash.
		if err := s.writeCursor("gw1", processingCursor{LastProcessedCommit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}); err != nil {
			t.Fatalf("write stale cursor: %v", err)
		}
	}

	retry, err := s.Save("gw1", content)
	if err != nil {
		t.Fatalf("Save with stale cursor: %v", err)
	}
	if !retry.Changed {
		t.Fatal("stale cursor: Changed = false, want reprocess (no silent skip)")
	}
}

func TestUpgradeWithoutCursorSkipsIdenticalHEAD(t *testing.T) {
	dir := t.TempDir()
	s1, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	first, err := s1.Save("gw1", []byte("hostname gw1\n"))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := s1.MarkProcessed("gw1", first.CommitHash); err != nil {
		t.Fatalf("MarkProcessed: %v", err)
	}
	// Simulate a pre-feature repo: processed content in git, no cursor file.
	if err := os.Remove(s1.cursorPath("gw1")); err != nil {
		t.Fatalf("remove cursor: %v", err)
	}
	_ = os.Remove(s1.pendingPath("gw1"))

	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	res, err := s2.Save("gw1", []byte("hostname gw1\n"))
	if err != nil {
		t.Fatalf("upgrade Save: %v", err)
	}
	if res.Changed {
		t.Fatal("pre-feature upgrade: identical HEAD Changed = true, want false")
	}
}

func TestLegacyPendingMigratesToCursor(t *testing.T) {
	s := openTestStore(t)
	before := []byte("hostname gw1\n")
	after := []byte("hostname gw1\nntp server 192.0.2.10\n")
	initial, err := s.Save("gw1", before)
	if err != nil {
		t.Fatalf("initial Save: %v", err)
	}
	if err := s.MarkProcessed("gw1", initial.CommitHash); err != nil {
		t.Fatalf("MarkProcessed: %v", err)
	}
	changed, err := s.Save("gw1", after)
	if err != nil {
		t.Fatalf("changed Save: %v", err)
	}

	// Replace cursor with legacy pending-only state (crash-era layout).
	if err := os.Remove(s.cursorPath("gw1")); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remove cursor: %v", err)
	}
	legacy := legacyPendingProcessing{CommitHash: changed.CommitHash, PrevCommitHash: initial.CommitHash}
	data, _ := json.Marshal(legacy)
	if err := os.MkdirAll(filepath.Dir(s.pendingPath("gw1")), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(s.pendingPath("gw1"), data, 0o600); err != nil {
		t.Fatalf("write legacy pending: %v", err)
	}

	retry, err := s.Save("gw1", after)
	if err != nil {
		t.Fatalf("migrate Save: %v", err)
	}
	if !retry.Changed {
		t.Fatal("legacy pending migrate: Changed = false, want true")
	}
	if retry.PrevCommitHash != initial.CommitHash {
		t.Fatalf("migrate PrevCommitHash = %q, want %q", retry.PrevCommitHash, initial.CommitHash)
	}
	if _, err := os.Stat(s.pendingPath("gw1")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy pending still present: %v", err)
	}
}
