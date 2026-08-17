package delivery

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// walFileMode is deliberately owner-only: the WAL names subscriber sessions.
const walFileMode = 0o600

// walRetiredCompactThreshold is how many retired sessions may accumulate before
// the next NextSeq rewrites the file. Compaction is O(open sessions), so this
// trades a bounded amount of dead state for not rewriting on every close.
const walRetiredCompactThreshold = 64

// WAL is a durable per-session emit-sequence store.
//
// It exists because an emit sequence held only in memory resets to 1 after a
// sender restart, and the downstream sink deduplicates by (session_id, seq)
// under first-write-wins. A reset sequence therefore does not merely duplicate
// a record — it causes the sink to silently DISCARD real post-restart
// delivery, under-billing the subscriber. Sequence numbers must survive the
// process that issued them.
//
// NextSeq fsyncs before returning, so a crash can only skip a sequence number,
// never reissue one. Gaps are safe; reuse is not.
type WAL struct {
	mu      sync.Mutex
	file    *os.File
	path    string
	seq     map[string]uint64
	retired map[string]struct{}
	fsio    walIO
	// compactAfter is walRetiredCompactThreshold; it is a field only so tests
	// can drive compaction without retiring a hundred sessions first.
	compactAfter int
}

// OpenWAL opens or creates the sequence WAL at path, replaying any existing
// records so sequences continue from where the previous process stopped.
//
// Replay is strict about mid-file corruption and forgiving about exactly one
// torn trailing record, which is the only damage an unclean shutdown can do to
// an append-only file.
func OpenWAL(path string) (*WAL, error) {
	return openWAL(path, defaultWALIO())
}

func openWAL(path string, fsio walIO) (*WAL, error) {
	if path == "" {
		return nil, errors.New("delivery: WAL path is empty")
	}
	if directory := filepath.Dir(path); directory != "" {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, fmt.Errorf("delivery: create WAL directory: %w", err)
		}
	}

	seq, err := replayWAL(path)
	if err != nil {
		return nil, err
	}

	// Compact on open. Only the high-water mark per session is meaningful, so
	// rewriting bounds the file at O(open sessions) instead of O(all emits).
	if err := compactWAL(path, seq, fsio); err != nil {
		return nil, err
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, walFileMode)
	if err != nil {
		return nil, fmt.Errorf("delivery: open WAL: %w", err)
	}
	return &WAL{
		file:         file,
		path:         path,
		seq:          seq,
		retired:      make(map[string]struct{}),
		fsio:         fsio,
		compactAfter: walRetiredCompactThreshold,
	}, nil
}

// NextSeq reserves and durably records the next sequence number for sessionID.
func (w *WAL) NextSeq(sessionID string) (uint64, error) {
	if sessionID == "" {
		return 0, errors.New("delivery: session ID is empty")
	}
	if strings.ContainsAny(sessionID, " \n") {
		return 0, fmt.Errorf("delivery: session ID %q contains a WAL delimiter", sessionID)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return 0, errors.New("delivery: WAL is closed")
	}
	if _, retired := w.retired[sessionID]; retired {
		return 0, fmt.Errorf("delivery: session %s was retired; its sequence must not restart", sessionID)
	}
	// Reclaim retired state before issuing, not after, so the failure mode of a
	// full disk is a refused sequence number rather than a reissued one.
	if len(w.retired) >= w.compactAfter {
		if err := w.compactLocked(); err != nil {
			return 0, err
		}
	}

	next := w.seq[sessionID] + 1
	if _, err := fmt.Fprintf(w.file, "%s %d\n", sessionID, next); err != nil {
		return 0, fmt.Errorf("delivery: append WAL record: %w", err)
	}
	// Durability before the caller can act on the sequence number. Emits are
	// periodic, not per-packet, so an fsync here is not on the hot path.
	if err := w.file.Sync(); err != nil {
		return 0, fmt.Errorf("delivery: sync WAL: %w", err)
	}

	w.seq[sessionID] = next
	return next, nil
}

// Retire releases the sequence state for a session that has closed and will
// never emit again. It is the hook that bounds this WAL: without it both the
// in-memory map and the file grow for the lifetime of the process, because a
// session's high-water record is otherwise replayed and rewritten by every
// subsequent compaction forever.
//
// Retirement is terminal. For as long as this WAL still remembers the
// retirement, NextSeq for that session ID returns an error rather than
// restarting its sequence at 1 — restarting would reissue numbers the sink has
// already accepted, and first-write-wins would then discard the new records,
// which is the exact under-billing this WAL exists to prevent. That memory is
// reclaimed at the next compaction, after which the ID is indistinguishable
// from one never seen. Session IDs are single-use UUIDs (see NewSessionID), so
// presenting one twice is a caller bug either way; the error catches that bug
// quickly, it does not make reuse safe.
//
// Retire only mutates memory and therefore cannot fail. The retired session's
// record leaves the file at the next compaction, which NextSeq triggers once
// enough sessions have retired and which Close performs on the way out.
func (w *WAL) Retire(sessionID string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, known := w.seq[sessionID]; !known {
		return // nothing to reclaim
	}
	w.retired[sessionID] = struct{}{}
}

// Close compacts away any retired sessions and closes the WAL, so a clean
// shutdown leaves on disk only the sessions that were still open.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return nil
	}
	var compactErr error
	if len(w.retired) > 0 {
		compactErr = w.compactLocked()
	}
	if w.file == nil {
		// compactLocked failed to reopen and already surrendered the handle.
		return compactErr
	}
	err := w.file.Close()
	w.file = nil
	return errors.Join(compactErr, err)
}

// compactLocked rewrites the file with one high-water record per live session,
// dropping retired ones, and re-points the append handle at the replacement.
// The caller must hold w.mu.
//
// The old handle is closed only after the rename succeeds: an O_APPEND fd
// survives the rename pointing at the now-unlinked inode, so appends made
// through it would be written to a file nothing will ever read again. On any
// failure before that point nothing is mutated and the old handle stays valid.
func (w *WAL) compactLocked() error {
	if w.file == nil {
		return errors.New("delivery: WAL is closed")
	}

	live := make(map[string]uint64, len(w.seq))
	for sessionID, seq := range w.seq {
		if _, retired := w.retired[sessionID]; !retired {
			live[sessionID] = seq
		}
	}
	if err := compactWAL(w.path, live, w.fsio); err != nil {
		return err
	}

	if err := w.file.Close(); err != nil {
		w.file = nil
		return fmt.Errorf("delivery: close superseded WAL handle: %w", err)
	}
	file, err := os.OpenFile(w.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, walFileMode)
	if err != nil {
		w.file = nil
		return fmt.Errorf("delivery: reopen compacted WAL: %w", err)
	}
	w.file = file
	w.seq = live
	w.retired = make(map[string]struct{})
	return nil
}

func replayWAL(path string) (map[string]uint64, error) {
	seq := make(map[string]uint64)

	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return seq, nil
	}
	if err != nil {
		return nil, fmt.Errorf("delivery: open WAL for replay: %w", err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	for lineNumber := 1; ; lineNumber++ {
		line, err := reader.ReadString('\n')
		if errors.Is(err, io.EOF) {
			// A record with no trailing newline is a torn write from an
			// unclean shutdown. It is only ever the last record, and the
			// sequence it would have carried is skipped, not reused.
			break
		}
		if err != nil {
			return nil, fmt.Errorf("delivery: read WAL: %w", err)
		}

		sessionID, value, ok := parseWALRecord(line)
		if !ok {
			return nil, fmt.Errorf("delivery: WAL %s is corrupt at line %d", path, lineNumber)
		}
		if value > seq[sessionID] {
			seq[sessionID] = value
		}
	}
	return seq, nil
}

func parseWALRecord(line string) (string, uint64, bool) {
	trimmed := strings.TrimSuffix(line, "\n")
	sessionID, rawSeq, found := strings.Cut(trimmed, " ")
	if !found || sessionID == "" {
		return "", 0, false
	}
	value, err := strconv.ParseUint(rawSeq, 10, 64)
	if err != nil || value == 0 {
		return "", 0, false
	}
	return sessionID, value, true
}

// syncWriteCloser is the subset of *os.File that a durable replace needs.
type syncWriteCloser interface {
	io.Writer
	Sync() error
	Close() error
}

// walIO is the seam that makes the ORDER of compaction's filesystem calls
// testable. The bug it exists to pin is invisible on a healthy filesystem: no
// inspection after the fact can distinguish a replacement whose contents were
// fsynced from one whose bytes are still only in the page cache, so the
// ordering is asserted through this interface instead of through the file.
type walIO struct {
	create  func(name string, perm os.FileMode) (syncWriteCloser, error)
	rename  func(oldPath, newPath string) error
	remove  func(name string) error
	syncDir func(directory string) error
}

func defaultWALIO() walIO {
	return walIO{
		create: func(name string, perm os.FileMode) (syncWriteCloser, error) {
			return os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		},
		rename:  os.Rename,
		remove:  os.Remove,
		syncDir: syncDir,
	}
}

// compactWAL atomically and durably rewrites path with one high-water record
// per session.
//
// The ordering below is the whole point of the function. os.Rename unlinks the
// original — the only copy of the sequence state that has ever been fsynced —
// so the replacement's CONTENTS must reach stable storage before the rename,
// not after. Writing without fsync and then fsyncing only the directory (which
// is what this used to do) is the worst of the two orderings: it makes the
// rename durable while the bytes it published are not, so a crash in that
// window can leave a truncated or zero-length WAL with the original already
// gone. An emptied WAL replays every session to seq == 0, NextSeq reissues
// 1, 2, 3..., and the sink's first-write-wins dedup on (session_id, seq) then
// silently discards real post-restart delivery.
//
// The temporary deliberately lives in the same directory as path: rename is
// only atomic within a filesystem.
func compactWAL(path string, seq map[string]uint64, fsio walIO) error {
	sessionIDs := make([]string, 0, len(seq))
	for sessionID := range seq {
		sessionIDs = append(sessionIDs, sessionID)
	}
	sort.Strings(sessionIDs)

	var builder strings.Builder
	for _, sessionID := range sessionIDs {
		fmt.Fprintf(&builder, "%s %d\n", sessionID, seq[sessionID])
	}

	temporary := path + ".compact"
	// Clear debris from a crashed compaction so the replacement is created
	// fresh under walFileMode rather than inheriting a stale file's mode, and
	// so O_EXCL below means what it says.
	if err := fsio.remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delivery: remove stale compacted WAL: %w", err)
	}

	file, err := fsio.create(temporary, walFileMode)
	if err != nil {
		return fmt.Errorf("delivery: create compacted WAL: %w", err)
	}
	// Every failure past this point must take the temporary with it; leaving a
	// half-written one behind would be adopted by the next compaction's O_EXCL
	// as a hard error.
	if _, err := io.WriteString(file, builder.String()); err != nil {
		file.Close()
		_ = fsio.remove(temporary)
		return fmt.Errorf("delivery: write compacted WAL: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = fsio.remove(temporary)
		return fmt.Errorf("delivery: sync compacted WAL: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = fsio.remove(temporary)
		return fmt.Errorf("delivery: close compacted WAL: %w", err)
	}
	if err := fsio.rename(temporary, path); err != nil {
		_ = fsio.remove(temporary)
		return fmt.Errorf("delivery: replace WAL: %w", err)
	}
	return fsio.syncDir(filepath.Dir(path))
}

// syncDir fsyncs a directory so a rename is durable. Not every platform
// permits opening a directory for sync, and a failure to do so is not fatal.
func syncDir(directory string) error {
	handle, err := os.Open(directory)
	if err != nil {
		return nil
	}
	defer handle.Close()
	_ = handle.Sync()
	return nil
}

// MemorySeqStore is a non-durable SeqStore for tests and dry runs. It must not
// be used by a sender that bills, because it reissues sequence numbers after a
// restart.
type MemorySeqStore struct {
	mu  sync.Mutex
	seq map[string]uint64
}

// NewMemorySeqStore returns an empty in-memory sequence store.
func NewMemorySeqStore() *MemorySeqStore {
	return &MemorySeqStore{seq: make(map[string]uint64)}
}

// NextSeq returns the next in-memory sequence number for sessionID.
func (m *MemorySeqStore) NextSeq(sessionID string) (uint64, error) {
	if sessionID == "" {
		return 0, errors.New("delivery: session ID is empty")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq[sessionID]++
	return m.seq[sessionID], nil
}

// Retire drops the sequence state for a closed session.
//
// Unlike WAL.Retire this does not refuse a later NextSeq for the same session
// ID; it would restart that sequence at 1. Nothing is lost by the omission,
// because a store that reissues sequence numbers across a restart already
// cannot be used by a sender that bills.
func (m *MemorySeqStore) Retire(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.seq, sessionID)
}
