// Package notify sends urgent push notifications via ntfy.sh for critical
// daemon events. Notifications are best-effort (fire-and-forget) and
// rate-limited to avoid spam during sustained outages.
package notify

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// ntfyEndpoint is the ntfy topic URL for wicket alerts.
	ntfyEndpoint = "https://ntfy.sh/roguenode-watchdog-6ffbaa666ec3"

	// rateLimitWindow is the minimum interval between notifications of the
	// same event type. Prevents flooding during sustained outages.
	rateLimitWindow = 5 * time.Minute
)

// Notifier sends urgent notifications via ntfy.sh. It rate-limits by event
// type to avoid spam.
type Notifier struct {
	mu       sync.Mutex
	lastSent map[string]time.Time
	client   *http.Client
}

// NewNotifier creates a new ntfy notifier.
func NewNotifier() *Notifier {
	return &Notifier{
		lastSent: make(map[string]time.Time),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Send sends an urgent notification via ntfy. The eventType is used for
// rate limiting (only one notification per event type per 5 minutes).
// This is fire-and-forget: a notification failure never blocks daemon
// operation.
func (n *Notifier) Send(eventType, title, message string) {
	n.mu.Lock()
	if last, ok := n.lastSent[eventType]; ok {
		if time.Since(last) < rateLimitWindow {
			n.mu.Unlock()
			slog.Debug("ntfy notification rate-limited", "event_type", eventType)
			return
		}
	}
	n.lastSent[eventType] = time.Now()
	n.mu.Unlock()

	// Fire-and-forget in a goroutine so we never block the caller
	go func() {
		if err := n.sendHTTP(title, message); err != nil {
			// Log but never propagate -- notification failure must not affect daemon
			slog.Warn("ntfy notification failed", "error", err, "event_type", eventType)
		}
	}()
}

// sendHTTP performs the actual HTTP POST to ntfy.
func (n *Notifier) sendHTTP(title, message string) error {
	req, err := http.NewRequest("POST", ntfyEndpoint, strings.NewReader(message))
	if err != nil {
		return fmt.Errorf("failed to create ntfy request: %w", err)
	}

	req.Header.Set("Priority", "urgent")
	req.Header.Set("Title", title)
	req.Header.Set("Tags", "key,warning")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("ntfy HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("ntfy returned status %d", resp.StatusCode)
	}

	return nil
}
