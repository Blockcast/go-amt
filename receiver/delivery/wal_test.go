package delivery

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
