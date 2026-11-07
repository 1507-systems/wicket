package notify

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// PauseFileEnv names the environment variable that overrides the path of the
// alert pause file. Unset means DefaultPauseFile().
//
// The pause is a no-deploy kill switch for outbound alerts (operator docs:
// README.md "Pausing alerts (no deploy)"). The file is read on every Send, so
// creating or removing it takes effect immediately, with no restart.
const PauseFileEnv = "WICKET_PAUSE_FILE"

// pauseIndefinite is the explicit "paused until removed" value. An empty file
// means the same thing.
const pauseIndefinite = "indefinite"

// pauseDatePrefix requires a full YYYY-MM-DD date before a value is treated
// as a time. Without it a bare number such as "12345" could be read as a year
// and silence alerts for millennia.
var pauseDatePrefix = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}`)

// pauseLayouts are the accepted ISO-8601 shapes. Layouts without a zone parse
// as UTC (time.Parse's default), matching the provisioning notify-pause lib.
var pauseLayouts = []string{
	time.RFC3339Nano,                // 2026-11-08T10:00:00Z, ...+02:00, fractional
	"2006-01-02T15:04Z07:00",        // 2026-11-08T10:00Z
	"2006-01-02T15:04:05.999999999", // 2026-11-08T10:00:00 (UTC)
	"2006-01-02T15:04",              // 2026-11-08T10:00 (UTC)
	"2006-01-02",                    // 2026-11-08 = midnight UTC that day
}

// DefaultPauseFile returns ~/.local/state/wicket/notify-paused.
func DefaultPauseFile() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".local", "state", "wicket", "notify-paused")
}

// pauseFilePath resolves the pause file path: WICKET_PAUSE_FILE, else the
// default. Resolved on every call so the override needs no restart either.
func pauseFilePath() string {
	if p := strings.TrimSpace(os.Getenv(PauseFileEnv)); p != "" {
		return p
	}
	return DefaultPauseFile()
}

// pauseInForce reports whether the pause file at path mutes alerts at now.
//
// In force: the file is empty, says "indefinite", or holds an ISO-8601 time
// later than now (no zone means UTC). Everything else fails open (NOT paused):
// a missing file, a read error, a past time, or an unparseable value, so a
// typo can never silence an alert.
func pauseInForce(path string, now time.Time) bool {
	if path == "" {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	// Strip all whitespace, as the shell lib does with tr -d '[:space:]'.
	v := strings.Join(strings.Fields(string(data)), "")
	if v == "" || v == pauseIndefinite {
		return true
	}
	if !pauseDatePrefix.MatchString(v) {
		return false
	}
	for _, layout := range pauseLayouts {
		if t, err := time.Parse(layout, v); err == nil {
			return t.After(now)
		}
	}
	return false
}
