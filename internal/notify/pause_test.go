package notify

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writePause(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "notify-paused")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPauseInForce(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"empty", "", true},
		{"whitespace only", " \n\t", true},
		{"indefinite", "indefinite\n", true},
		{"future RFC3339 Z", "2026-11-07T13:00:00Z", true},
		{"future no zone is UTC", "2026-11-07T12:30:00", true},
		{"future minutes no zone", "2026-11-07T12:01", true},
		{"future date only", "2026-11-08", true},
		{"past RFC3339", "2026-11-07T11:59:59Z", false},
		{"past no zone is UTC", "2026-11-07T11:00:00", false},
		{"past date only", "2026-11-07", false},
		{"garbage", "tomorrow please", false},
		{"bare number is not a year", "12345", false},
		{"short year", "99999-01-01", false},
		{"date prefix then junk", "2027-01-01junk", false},
		{"indefinite typo", "indefinte", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := pauseInForce(writePause(t, c.content), now); got != c.want {
				t.Errorf("pauseInForce(%q) = %v, want %v", c.content, got, c.want)
			}
		})
	}
}

func TestPauseOffsetIsHonored(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	// 10:00-03:00 is 13:00Z: future. 08:00-03:00 is 11:00Z: past.
	if !pauseInForce(writePause(t, "2026-11-07T10:00:00-03:00"), now) {
		t.Error("13:00Z via offset should be in force")
	}
	if pauseInForce(writePause(t, "2026-11-07T08:00:00-03:00"), now) {
		t.Error("11:00Z via offset should not be in force")
	}
}

func TestPauseMissingFileFailsOpen(t *testing.T) {
	if pauseInForce(filepath.Join(t.TempDir(), "absent"), time.Now()) {
		t.Error("missing file must not pause")
	}
	if pauseInForce("", time.Now()) {
		t.Error("empty path must not pause")
	}
}

func TestPauseUnreadableFailsOpen(t *testing.T) {
	// A directory at the path is a read error on every platform and user.
	if pauseInForce(t.TempDir(), time.Now()) {
		t.Error("directory at pause path must not pause")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can read mode-000 files")
	}
	p := writePause(t, "indefinite")
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
	if pauseInForce(p, time.Now()) {
		t.Error("unreadable file must not pause")
	}
}

func TestPauseFilePathOverrideAndDefault(t *testing.T) {
	t.Setenv(PauseFileEnv, "/tmp/custom-pause")
	if got := pauseFilePath(); got != "/tmp/custom-pause" {
		t.Errorf("override: got %q", got)
	}
	t.Setenv(PauseFileEnv, "")
	t.Setenv("HOME", "/home/x")
	if got, want := pauseFilePath(), "/home/x/.local/state/wicket/notify-paused"; got != want {
		t.Errorf("default: got %q, want %q", got, want)
	}
}

// A suppressed send must not make the POST and must not consume the
// rate-limit slot: the first send after the pause ends goes out.
func TestPausedSendDoesNotConsumeRateLimit(t *testing.T) {
	t.Setenv(EndpointEnv, "")
	t.Setenv("WICKET_NTFY_TOKEN", "")

	got := make(chan struct{}, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- struct{}{}
	}))
	defer srv.Close()

	pause := writePause(t, "indefinite")
	t.Setenv(PauseFileEnv, pause)

	n := NewNotifier(srv.URL + "/topic")
	n.Send("event", "Wicket Error", "while paused")

	select {
	case <-got:
		t.Fatal("paused send reached the ntfy server")
	case <-time.After(300 * time.Millisecond):
	}
	n.mu.Lock()
	_, recorded := n.lastSent["event"]
	n.mu.Unlock()
	if recorded {
		t.Fatal("paused send recorded lastSent (consumed the rate-limit slot)")
	}

	// Resume: no restart, just remove the file.
	if err := os.Remove(pause); err != nil {
		t.Fatal(err)
	}
	n.Send("event", "Wicket Error", "after resume")
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("first send after resume did not reach the ntfy server")
	}
}
