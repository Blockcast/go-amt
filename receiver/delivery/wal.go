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
	mu   sync.Mutex
	file *os.File
	path string
	seq  map[string]uint64
}

// OpenWAL opens or creates the sequence WAL at path, replaying any existing
// records so sequences continue from where the previous process stopped.
//
// Replay is strict about mid-file corruption and forgiving about exactly one
// torn trailing record, which is the only damage an unclean shutdown can do to
// an append-only file.
func OpenWAL(path string) (*WAL, error) {
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
	if err := compactWAL(path, seq); err != nil {
		return nil, err
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, walFileMode)
	if err != nil {
		return nil, fmt.Errorf("delivery: open WAL: %w", err)
	}
	return &WAL{file: file, path: path, seq: seq}, nil
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

// Forget drops in-memory state for a retired session. The next compaction
// removes it from disk. Retiring a session never rewinds its sequence while it
// is still on disk, so a late replayed record cannot collide.
func (w *WAL) Forget(sessionID string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.seq, sessionID)
}

// Close flushes and closes the WAL.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
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

// compactWAL atomically rewrites path with one high-water record per session.
func compactWAL(path string, seq map[string]uint64) error {
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
	if err := os.WriteFile(temporary, []byte(builder.String()), walFileMode); err != nil {
		return fmt.Errorf("delivery: write compacted WAL: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("delivery: replace WAL: %w", err)
	}
	return syncDir(filepath.Dir(path))
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
