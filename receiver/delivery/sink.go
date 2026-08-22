package delivery

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// recordFileMode matches the WAL's: billing records name subscribers and their
// traffic volumes, so they are not world-readable.
const recordFileMode = 0o600

// WriterSink ships records as JSON lines to an io.Writer.
//
// One record per line, flushed and (where the writer supports it) fsynced
// before Ship returns, because Reporter treats a nil error as "durably
// accepted" and will not retransmit afterwards. A buffered writer that
// returned nil on a write still sitting in memory would turn a crash into
// silently unbilled traffic.
type WriterSink struct {
	mu     sync.Mutex
	writer io.Writer
}

// NewWriterSink returns a sink writing JSON lines to writer.
func NewWriterSink(writer io.Writer) (*WriterSink, error) {
	if writer == nil {
		return nil, errors.New("delivery: record writer is nil")
	}
	return &WriterSink{writer: writer}, nil
}

// OpenRecordFile opens or creates an append-only JSON-lines record file.
func OpenRecordFile(path string) (*os.File, error) {
	if path == "" {
		return nil, errors.New("delivery: record path is empty")
	}
	if directory := filepath.Dir(path); directory != "" {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, fmt.Errorf("delivery: create record directory: %w", err)
		}
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, recordFileMode)
	if err != nil {
		return nil, fmt.Errorf("delivery: open record file: %w", err)
	}
	return file, nil
}

// Ship appends record as a JSON line.
func (s *WriterSink) Ship(record Record) error {
	line, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("delivery: marshal record seq %d: %w", record.Seq, err)
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.writer.Write(line); err != nil {
		return fmt.Errorf("delivery: write record seq %d: %w", record.Seq, err)
	}
	// Only a real file can promise durability; an in-memory writer in a test
	// has nothing to sync and correctly reports success without one.
	if syncer, ok := s.writer.(interface{ Sync() error }); ok {
		if err := syncer.Sync(); err != nil {
			return fmt.Errorf("delivery: sync record seq %d: %w", record.Seq, err)
		}
	}
	return nil
}
