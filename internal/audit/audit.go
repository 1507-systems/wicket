// Package audit provides an append-only JSON audit log for tracking every
// token request handled by the wicket daemon. Each entry records the
// timestamp, provider, scope, caller identity, and outcome.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry represents a single audit log entry. Failed requests are also
// logged (with Success=false and an Error field).
type Entry struct {
	Timestamp    time.Time  `json:"timestamp"`
	Action       string     `json:"action"`
	Provider     string     `json:"provider,omitempty"`
	Scope        string     `json:"scope,omitempty"`
	CallerPID    int32      `json:"caller_pid"`
	CallerUID    uint32     `json:"caller_uid"`
	CallerBinary string     `json:"caller_binary,omitempty"`
	TokenType    string     `json:"token_type,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	Success      bool       `json:"success"`
	Error        string     `json:"error,omitempty"`
}

// Logger writes audit entries as newline-delimited JSON to an append-only file.
// It is safe for concurrent use.
type Logger struct {
	mu   sync.Mutex
	file *os.File
	path string
}

// NewLogger creates an audit logger that writes to the given file path.
// The file is opened in append-only mode (O_APPEND). Parent directories
// are created if they don't exist.
func NewLogger(path string) (*Logger, error) {
	if path == "" {
		return nil, fmt.Errorf("audit: log path is required")
	}

	// Ensure the parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("audit: failed to create log directory %s: %w", dir, err)
	}

	// Open in append-only mode with restrictive permissions
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("audit: failed to open log file %s: %w", path, err)
	}

	return &Logger{
		file: f,
		path: path,
	}, nil
}

// Log writes a single audit entry as a JSON line to the log file.
func (l *Logger) Log(entry Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file == nil {
		return fmt.Errorf("audit: logger is closed")
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("audit: failed to marshal entry: %w", err)
	}

	// Write JSON line (entry + newline)
	data = append(data, '\n')
	if _, err := l.file.Write(data); err != nil {
		return fmt.Errorf("audit: failed to write entry: %w", err)
	}

	return nil
}

// ReadLast reads the last N entries from the audit log file by scanning the
// entire file. For large logs this is intentionally simple -- external log
// rotation keeps the file manageable.
func (l *Logger) ReadLast(n int) ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if n <= 0 {
		n = 20
	}

	data, err := os.ReadFile(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: failed to read log file: %w", err)
	}

	// Parse all entries (newline-delimited JSON)
	var entries []Entry
	decoder := json.NewDecoder(
		// Use a bytes reader from the data
		newBytesReader(data),
	)

	for decoder.More() {
		var entry Entry
		if err := decoder.Decode(&entry); err != nil {
			// Skip malformed lines rather than failing entirely
			continue
		}
		entries = append(entries, entry)
	}

	// Return the last N entries
	if len(entries) > n {
		entries = entries[len(entries)-n:]
	}

	return entries, nil
}

// Close flushes and closes the audit log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file == nil {
		return nil
	}

	err := l.file.Close()
	l.file = nil
	return err
}

// bytesReader wraps a byte slice for use with json.NewDecoder.
type bytesReader struct {
	data []byte
	pos  int
}

func newBytesReader(data []byte) *bytesReader {
	return &bytesReader{data: data}
}

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
