package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLogAndReadBack(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	logger, err := NewLogger(logPath)
	if err != nil {
		t.Fatalf("NewLogger() error: %v", err)
	}
	defer logger.Close()

	now := time.Now().UTC()
	entry := Entry{
		Timestamp: now,
		Action:    "get",
		Provider:  "cloudflare",
		Scope:     "dns",
		CallerPID: 12345,
		CallerUID: 501,
		TokenType: "short-lived",
		Success:   true,
	}

	if err := logger.Log(entry); err != nil {
		t.Fatalf("Log() error: %v", err)
	}

	// Read back
	entries, err := logger.ReadLast(10)
	if err != nil {
		t.Fatalf("ReadLast() error: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("ReadLast() returned %d entries, want 1", len(entries))
	}

	if entries[0].Provider != "cloudflare" {
		t.Errorf("entry.Provider = %q, want cloudflare", entries[0].Provider)
	}
	if entries[0].Scope != "dns" {
		t.Errorf("entry.Scope = %q, want dns", entries[0].Scope)
	}
	if !entries[0].Success {
		t.Error("entry.Success = false, want true")
	}
}

func TestLogMultipleEntries(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	logger, err := NewLogger(logPath)
	if err != nil {
		t.Fatalf("NewLogger() error: %v", err)
	}
	defer logger.Close()

	// Write 5 entries
	for i := 0; i < 5; i++ {
		logger.Log(Entry{
			Timestamp: time.Now().UTC(),
			Action:    "get",
			Provider:  "test",
			Scope:     "scope",
			CallerPID: int32(i),
			CallerUID: 501,
			Success:   true,
		})
	}

	// ReadLast(3) should return only the last 3
	entries, err := logger.ReadLast(3)
	if err != nil {
		t.Fatalf("ReadLast(3) error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("ReadLast(3) returned %d entries, want 3", len(entries))
	}

	// The first returned entry should have PID 2 (entries 0,1 were truncated)
	if entries[0].CallerPID != 2 {
		t.Errorf("first entry PID = %d, want 2", entries[0].CallerPID)
	}
}

func TestLogFailedRequest(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	logger, err := NewLogger(logPath)
	if err != nil {
		t.Fatalf("NewLogger() error: %v", err)
	}
	defer logger.Close()

	entry := Entry{
		Timestamp: time.Now().UTC(),
		Action:    "get",
		Provider:  "badprovider",
		Scope:     "missing",
		CallerPID: 999,
		CallerUID: 501,
		Success:   false,
		Error:     "provider not found",
	}

	if err := logger.Log(entry); err != nil {
		t.Fatalf("Log() error: %v", err)
	}

	entries, err := logger.ReadLast(10)
	if err != nil {
		t.Fatalf("ReadLast() error: %v", err)
	}

	if entries[0].Success {
		t.Error("expected Success=false for failed entry")
	}
	if entries[0].Error != "provider not found" {
		t.Errorf("entry.Error = %q, want 'provider not found'", entries[0].Error)
	}
}

func TestLogJSONFormat(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	logger, err := NewLogger(logPath)
	if err != nil {
		t.Fatalf("NewLogger() error: %v", err)
	}

	logger.Log(Entry{
		Timestamp: time.Date(2026, 4, 7, 12, 0, 0, 0, time.UTC),
		Action:    "get",
		Provider:  "cloudflare",
		Scope:     "dns",
		CallerPID: 12345,
		CallerUID: 501,
		Success:   true,
	})
	logger.Close()

	// Read raw file and verify it's valid JSON
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("log line is not valid JSON: %v\nraw: %s", err, string(data))
	}

	if parsed["provider"] != "cloudflare" {
		t.Errorf("JSON provider = %v, want cloudflare", parsed["provider"])
	}
}

func TestNewLoggerCreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "subdir", "nested", "audit.log")

	logger, err := NewLogger(logPath)
	if err != nil {
		t.Fatalf("NewLogger() should create parent dirs, got error: %v", err)
	}
	logger.Close()

	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Error("expected log file to exist after NewLogger()")
	}
}

func TestNewLoggerEmptyPath(t *testing.T) {
	_, err := NewLogger("")
	if err == nil {
		t.Fatal("expected error for empty path, got nil")
	}
}
