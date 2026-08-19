package delivery

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// recordingWALIO wraps the real filesystem and records the order of the calls
// whose ordering is the safety property: the replacement's contents must be
// fsynced before the rename unlinks the original.
type recordingWALIO struct {
	trace []string
	inner walIO
	// writeErr, if set, makes the first Write on the temporary fail, standing
	// in for a full disk part-way through the replacement.
	writeErr error
}

func newRecordingWALIO() *recordingWALIO {
	return &recordingWALIO{inner: defaultWALIO()}
}

func (r *recordingWALIO) io() walIO {
	return walIO{
		create: func(name string, perm os.FileMode) (syncWriteCloser, error) {
			file, err := r.inner.create(name, perm)
			if err != nil {
				return nil, err
			}
			r.trace = append(r.trace, "create "+filepath.Base(name))
			return &recordingFile{owner: r, name: filepath.Base(name), inner: file}, nil
		},
		rename: func(oldPath, newPath string) error {
			r.trace = append(r.trace, "rename "+filepath.Base(oldPath)+" -> "+filepath.Base(newPath))
			return r.inner.rename(oldPath, newPath)
		},
		remove: func(name string) error {
			err := r.inner.remove(name)
			if err == nil {
				r.trace = append(r.trace, "remove "+filepath.Base(name))
			}
			return err
		},
		syncDir: func(directory string) error {
			r.trace = append(r.trace, "syncdir")
			return r.inner.syncDir(directory)
		},
	}
}

// indexOfPrefix returns the position of the first traced call with the given
// prefix, or -1.
func (r *recordingWALIO) indexOfPrefix(prefix string) int {
	for i, entry := range r.trace {
		if strings.HasPrefix(entry, prefix) {
			return i
		}
	}
	return -1
}

type recordingFile struct {
	owner *recordingWALIO
	name  string
	inner syncWriteCloser
}

func (f *recordingFile) Write(p []byte) (int, error) {
	if err := f.owner.writeErr; err != nil {
		f.owner.writeErr = nil
		f.owner.trace = append(f.owner.trace, "write-failed "+f.name)
		return 0, err
	}
	f.owner.trace = append(f.owner.trace, "write "+f.name)
	return f.inner.Write(p)
}

func (f *recordingFile) Sync() error {
	f.owner.trace = append(f.owner.trace, "sync "+f.name)
	return f.inner.Sync()
}

func (f *recordingFile) Close() error {
	f.owner.trace = append(f.owner.trace, "close "+f.name)
	return f.inner.Close()
}

// TestCompactSyncsContentsBeforeRename is the assertion the reviewer asked for.
//
// os.Rename unlinks the original — the only copy of the sequence state that has
// ever been fsynced — so the replacement's CONTENTS must reach stable storage
// first. Nothing about the filesystem afterwards distinguishes a synced
// replacement from one whose bytes are still in the page cache, which is why
// this asserts the call ORDER rather than the file. Syncing only the directory
// (the previous behaviour) makes the rename durable while the contents are
// not, so a crash in that window leaves a truncated or empty WAL with the
// original gone; that replays every session to seq == 0 and the sink's
// first-write-wins dedup then discards real post-restart delivery.
func TestCompactSyncsContentsBeforeRename(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delivery.wal")
	recorder := newRecordingWALIO()

	// openWAL compacts unconditionally, so this exercises the production path
	// rather than compactWAL in isolation.
	wal, err := openWAL(path, recorder.io())
	if err != nil {
		t.Fatalf("openWAL: %v", err)
	}
	defer wal.Close()

	sync := recorder.indexOfPrefix("sync delivery.wal.compact")
	rename := recorder.indexOfPrefix("rename delivery.wal.compact")
	if sync < 0 {
		t.Fatalf("compaction never fsynced the replacement's contents; trace = %v", recorder.trace)
	}
	if rename < 0 {
		t.Fatalf("compaction never renamed the replacement into place; trace = %v", recorder.trace)
	}
	if sync > rename {
		t.Fatalf("fsync of the replacement happened AFTER the rename unlinked the original; trace = %v", recorder.trace)
	}

	write := recorder.indexOfPrefix("write delivery.wal.compact")
	if write >= 0 && write > sync {
		t.Fatalf("contents were written after the fsync that was supposed to make them durable; trace = %v", recorder.trace)
	}
	if closed := recorder.indexOfPrefix("close delivery.wal.compact"); closed >= 0 && closed > rename {
		t.Fatalf("replacement was renamed into place while still open; trace = %v", recorder.trace)
	}
}

// TestCompactSyncsBeforeRenameWithLiveSessions repeats the ordering assertion
// for a compaction that actually has bytes to write, since an empty file is
// the one case where a missing fsync could not corrupt anything.
func TestCompactSyncsBeforeRenameWithLiveSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delivery.wal")
	if err := os.WriteFile(path, []byte("session-a 7\nsession-b 3\n"), walFileMode); err != nil {
		t.Fatalf("seed WAL: %v", err)
	}

	recorder := newRecordingWALIO()
	wal, err := openWAL(path, recorder.io())
	if err != nil {
		t.Fatalf("openWAL: %v", err)
	}
	defer wal.Close()

	write := recorder.indexOfPrefix("write delivery.wal.compact")
	sync := recorder.indexOfPrefix("sync delivery.wal.compact")
	rename := recorder.indexOfPrefix("rename delivery.wal.compact")
	if write < 0 || sync < 0 || rename < 0 {
		t.Fatalf("incomplete durable-replace sequence; trace = %v", recorder.trace)
	}
	if !(write < sync && sync < rename) {
		t.Fatalf("want write < sync < rename, got %d/%d/%d; trace = %v", write, sync, rename, recorder.trace)
	}

	seq, err := wal.NextSeq("session-a")
	if err != nil {
		t.Fatalf("NextSeq: %v", err)
	}
	if seq != 8 {
		t.Fatalf("compaction lost the high-water mark: got %d, want 8", seq)
	}
}

// TestCompactCleansUpAfterAPartialWrite pins the other half of a durable
// replace: a replacement that could not be written must not survive, or the
// next compaction's O_EXCL create adopts it as a hard error, and the original
// must be left exactly as it was.
func TestCompactCleansUpAfterAPartialWrite(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "delivery.wal")
	original := "session-a 7\n"
	if err := os.WriteFile(path, []byte(original), walFileMode); err != nil {
		t.Fatalf("seed WAL: %v", err)
	}

	recorder := newRecordingWALIO()
	recorder.writeErr = errors.New("no space left on device")
	if _, err := openWAL(path, recorder.io()); err == nil {
		t.Fatal("openWAL succeeded despite a failed write of the replacement")
	}

	if _, err := os.Stat(path + ".compact"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a failed compaction left its temporary behind: stat err = %v", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read WAL: %v", err)
	}
	if string(contents) != original {
		t.Fatalf("a failed compaction damaged the original: %q, want %q", contents, original)
	}
}

// TestCompactDoesNotInheritStaleTemporaryMode pins that a temporary left by a
// crashed compaction is replaced rather than reused. os.WriteFile only applies
// its mode when it creates the file, so reusing one would publish the WAL —
// which names subscriber sessions — under whatever mode the debris carried.
func TestCompactDoesNotInheritStaleTemporaryMode(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "delivery.wal")
	if err := os.WriteFile(path+".compact", []byte("debris\n"), 0o666); err != nil {
		t.Fatalf("seed stale temporary: %v", err)
	}
	if err := os.Chmod(path+".compact", 0o666); err != nil {
		t.Fatalf("chmod stale temporary: %v", err)
	}

	wal, err := OpenWAL(path)
	if err != nil {
		t.Fatalf("OpenWAL with a stale temporary: %v", err)
	}
	defer wal.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat WAL: %v", err)
	}
	if mode := info.Mode().Perm(); mode != walFileMode {
		t.Fatalf("WAL mode = %04o, want %04o; the stale temporary's mode was inherited", mode, walFileMode)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read WAL: %v", err)
	}
	if string(contents) != "" {
		t.Fatalf("stale temporary's contents were published as the WAL: %q", contents)
	}
}

// TestWALRetireIsTerminal pins that releasing a session's state does not rewind
// its sequence to zero. The doc on the old Forget claimed this; the code did
// the opposite.
func TestWALRetireIsTerminal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delivery.wal")
	wal, err := OpenWAL(path)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer wal.Close()

	for i := 0; i < 3; i++ {
		if _, err := wal.NextSeq("session-a"); err != nil {
			t.Fatalf("NextSeq: %v", err)
		}
	}
	wal.Retire("session-a")

	seq, err := wal.NextSeq("session-a")
	if err == nil {
		t.Fatalf("NextSeq reissued %d for a retired session; the sink would discard everything from there", seq)
	}

	// Retiring one session must not disturb another.
	if seq, err := wal.NextSeq("session-b"); err != nil || seq != 1 {
		t.Fatalf("NextSeq(session-b) = %d, %v; want 1, nil", seq, err)
	}
}

// TestWALRetireCompactsWithinARun pins that retirement actually bounds the
// file. Before, compaction ran only at OpenWAL and was fed by a fresh replay of
// the file, so a retired session was read straight back off disk and written
// straight back out again — for the lifetime of the process and every process
// after it.
func TestWALRetireCompactsWithinARun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delivery.wal")
	wal, err := OpenWAL(path)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer wal.Close()
	wal.compactAfter = 4

	if _, err := wal.NextSeq("session-live"); err != nil {
		t.Fatalf("NextSeq: %v", err)
	}
	for i := 0; i < wal.compactAfter; i++ {
		sessionID := fmt.Sprintf("session-%d", i)
		if _, err := wal.NextSeq(sessionID); err != nil {
			t.Fatalf("NextSeq: %v", err)
		}
		wal.Retire(sessionID)
	}

	// The next reservation is what reclaims the retired state.
	if _, err := wal.NextSeq("session-live"); err != nil {
		t.Fatalf("NextSeq after retirements: %v", err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read WAL: %v", err)
	}
	for i := 0; i < wal.compactAfter; i++ {
		if strings.Contains(string(contents), fmt.Sprintf("session-%d ", i)) {
			t.Fatalf("retired session-%d is still on disk after compaction:\n%s", i, contents)
		}
	}
	if !strings.Contains(string(contents), "session-live ") {
		t.Fatalf("compaction dropped a live session:\n%s", contents)
	}

	// Appends after a compaction must land in the file that replaced the old
	// one, not in the inode the rename unlinked.
	if _, err := wal.NextSeq("session-live"); err != nil {
		t.Fatalf("NextSeq after compaction: %v", err)
	}
	reread, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("re-read WAL: %v", err)
	}
	if len(reread) <= len(contents) {
		t.Fatalf("append after compaction did not reach the live file: %q then %q", contents, reread)
	}
}

// TestWALRetiredSessionDoesNotSurviveCleanShutdown pins that a clean shutdown
// leaves only sessions that were still open, so the file does not grow by one
// permanent record per session ever seen.
func TestWALRetiredSessionDoesNotSurviveCleanShutdown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delivery.wal")
	wal, err := OpenWAL(path)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	for _, sessionID := range []string{"session-open", "session-closed"} {
		if _, err := wal.NextSeq(sessionID); err != nil {
			t.Fatalf("NextSeq: %v", err)
		}
	}
	wal.Retire("session-closed")
	if err := wal.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read WAL: %v", err)
	}
	if strings.Contains(string(contents), "session-closed") {
		t.Fatalf("a retired session survived a clean shutdown:\n%s", contents)
	}
	if !strings.Contains(string(contents), "session-open 1\n") {
		t.Fatalf("a session that was still open was dropped:\n%s", contents)
	}

	// And the survivor's high-water mark is intact across the restart.
	reopened, err := OpenWAL(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if seq, err := reopened.NextSeq("session-open"); err != nil || seq != 2 {
		t.Fatalf("NextSeq after restart = %d, %v; want 2, nil", seq, err)
	}
}

// TestSeqMonotonicAcrossRestart is the acceptance criterion that motivates the
// WAL at all: a sender restart must not rewind the emit sequence, because the
// sink deduplicates by (session_id, seq) under first-write-wins and would
// silently discard the post-restart delivery.
func TestSeqMonotonicAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delivery.wal")

	wal, err := OpenWAL(path)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	var before uint64
	for i := 0; i < 5; i++ {
		if before, err = wal.NextSeq("session-a"); err != nil {
			t.Fatalf("NextSeq: %v", err)
		}
	}
	if before != 5 {
		t.Fatalf("sequence before restart = %d, want 5", before)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Restart the sender against the same WAL.
	reopened, err := OpenWAL(path)
	if err != nil {
		t.Fatalf("reopen WAL: %v", err)
	}
	defer reopened.Close()

	after, err := reopened.NextSeq("session-a")
	if err != nil {
		t.Fatalf("NextSeq after restart: %v", err)
	}
	if after <= before {
		t.Fatalf("sequence rewound across restart: %d then %d", before, after)
	}
	if after != 6 {
		t.Fatalf("sequence after restart = %d, want 6", after)
	}
}

// TestTrackerSeqSurvivesRestart wires the WAL through the Tracker, which is
// how the sender actually uses it.
func TestTrackerSeqSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delivery.wal")
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0).UTC()}

	wal, err := OpenWAL(path)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	tracker, err := NewTracker(wal, WithClock(clock.Now))
	if err != nil {
		t.Fatalf("NewTracker: %v", err)
	}
	sessionID, err := tracker.Open("subscriber-a")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	clock.Add(10 * time.Second)
	first, err := tracker.Emit("subscriber-a")
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("Close WAL: %v", err)
	}

	// The process restarts and re-adopts the same session ID from the broker.
	restartedWAL, err := OpenWAL(path)
	if err != nil {
		t.Fatalf("reopen WAL: %v", err)
	}
	defer restartedWAL.Close()

	restarted, err := NewTracker(restartedWAL, WithClock(clock.Now),
		WithIDFunc(func() (string, error) { return sessionID, nil }))
	if err != nil {
		t.Fatalf("NewTracker after restart: %v", err)
	}
	if _, err := restarted.Open("subscriber-a"); err != nil {
		t.Fatalf("Open after restart: %v", err)
	}
	clock.Add(10 * time.Second)
	second, err := restarted.Emit("subscriber-a")
	if err != nil {
		t.Fatalf("Emit after restart: %v", err)
	}

	if second.SessionID != first.SessionID {
		t.Fatalf("session ID changed: %s then %s", first.SessionID, second.SessionID)
	}
	if second.Seq <= first.Seq {
		t.Fatalf("emit sequence rewound across restart: %d then %d", first.Seq, second.Seq)
	}
}

func TestWALIsPerSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delivery.wal")
	wal, err := OpenWAL(path)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer wal.Close()

	for i := 0; i < 3; i++ {
		if _, err := wal.NextSeq("session-a"); err != nil {
			t.Fatalf("NextSeq: %v", err)
		}
	}
	seq, err := wal.NextSeq("session-b")
	if err != nil {
		t.Fatalf("NextSeq: %v", err)
	}
	if seq != 1 {
		t.Fatalf("a second session started at %d, want 1", seq)
	}
}

// TestWALCompactsOnOpen keeps the file bounded by open sessions rather than by
// lifetime emit count, without losing the high-water mark.
func TestWALCompactsOnOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delivery.wal")
	wal, err := OpenWAL(path)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	for i := 0; i < 50; i++ {
		if _, err := wal.NextSeq("session-a"); err != nil {
			t.Fatalf("NextSeq: %v", err)
		}
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := OpenWAL(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read WAL: %v", err)
	}
	lines := strings.Count(string(contents), "\n")
	if lines != 1 {
		t.Fatalf("compacted WAL has %d records, want 1", lines)
	}

	seq, err := reopened.NextSeq("session-a")
	if err != nil {
		t.Fatalf("NextSeq: %v", err)
	}
	if seq != 51 {
		t.Fatalf("compaction lost the high-water mark: got %d, want 51", seq)
	}
}

// TestWALToleratesTornTrailingRecord models an unclean shutdown mid-append.
// The half-written sequence is skipped, never reused.
func TestWALToleratesTornTrailingRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delivery.wal")
	if err := os.WriteFile(path, []byte("session-a 1\nsession-a 2\nsession-a 3"), walFileMode); err != nil {
		t.Fatalf("seed WAL: %v", err)
	}

	wal, err := OpenWAL(path)
	if err != nil {
		t.Fatalf("OpenWAL with a torn record: %v", err)
	}
	defer wal.Close()

	seq, err := wal.NextSeq("session-a")
	if err != nil {
		t.Fatalf("NextSeq: %v", err)
	}
	if seq != 3 {
		t.Fatalf("next sequence = %d, want 3 (the torn record is skipped, not reused)", seq)
	}
}

// TestWALRejectsMidFileCorruption draws the line at the other kind of damage:
// a malformed record that is not the last one is real corruption, and a
// billing WAL must refuse to guess.
func TestWALRejectsMidFileCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delivery.wal")
	if err := os.WriteFile(path, []byte("session-a 1\ngarbage\nsession-a 3\n"), walFileMode); err != nil {
		t.Fatalf("seed WAL: %v", err)
	}
	if _, err := OpenWAL(path); err == nil {
		t.Fatal("OpenWAL accepted a corrupt WAL; it must refuse rather than guess a sequence")
	}
}

func TestWALRejectsDelimiterInSessionID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delivery.wal")
	wal, err := OpenWAL(path)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer wal.Close()

	for _, sessionID := range []string{"bad id", "bad\nid", ""} {
		if _, err := wal.NextSeq(sessionID); err == nil {
			t.Fatalf("NextSeq accepted session ID %q", sessionID)
		}
	}
}

func TestWALNextSeqAfterCloseFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delivery.wal")
	wal, err := OpenWAL(path)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := wal.NextSeq("session-a"); err == nil {
		t.Fatal("NextSeq succeeded on a closed WAL")
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("second Close should be a no-op, got %v", err)
	}
}

func TestWALCreatesParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "state", "delivery.wal")
	wal, err := OpenWAL(path)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer wal.Close()
	if _, err := wal.NextSeq("session-a"); err != nil {
		t.Fatalf("NextSeq: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("WAL was not created: %v", err)
	}
}

func TestWALConcurrentSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delivery.wal")
	wal, err := OpenWAL(path)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer wal.Close()

	const sessions, emits = 8, 16
	errs := make(chan error, sessions)
	for s := 0; s < sessions; s++ {
		go func(s int) {
			sessionID := fmt.Sprintf("session-%d", s)
			for i := 0; i < emits; i++ {
				seq, err := wal.NextSeq(sessionID)
				if err != nil {
					errs <- err
					return
				}
				if seq != uint64(i+1) {
					errs <- fmt.Errorf("%s emit %d got seq %d", sessionID, i, seq)
					return
				}
			}
			errs <- nil
		}(s)
	}
	for s := 0; s < sessions; s++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent NextSeq: %v", err)
		}
	}
}
