package notify

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A notifier with no configured topic must never make a network call. This is
// the guard on the reason the topic left the source tree: an unconfigured
// build must be inert, not fall back to a baked-in endpoint.
func TestNotifierDisabledWithoutTopic(t *testing.T) {
	t.Setenv(EndpointEnv, "")

	n := NewNotifier("")
	if n.Enabled() {
		t.Fatal("Enabled() = true with no topic configured")
	}
	if err := n.sendHTTP("title", "body"); err == nil {
		t.Fatal("sendHTTP() with empty endpoint returned nil error")
	}
}

func TestEnvOverridesConfiguredTopic(t *testing.T) {
	t.Setenv(EndpointEnv, "https://ntfy.example.invalid/from-env")

	n := NewNotifier("https://ntfy.example.invalid/from-config")
	if n.endpoint != "https://ntfy.example.invalid/from-env" {
		t.Errorf("endpoint = %q, want the env value", n.endpoint)
	}
}

func TestSendPostsToConfiguredTopic(t *testing.T) {
	t.Setenv(EndpointEnv, "")
	t.Setenv("WICKET_NTFY_TOKEN", "test-token")

	got := make(chan *http.Request, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r
	}))
	defer srv.Close()

	n := NewNotifier(srv.URL + "/topic")
	n.Send("event", "Wicket Error", "something broke")

	select {
	case r := <-got:
		if r.URL.Path != "/topic" {
			t.Errorf("path = %q, want /topic", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Authorization = %q, want the bearer token", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Priority") != "urgent" {
			t.Errorf("Priority = %q, want urgent", r.Header.Get("Priority"))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no request reached the ntfy server within 5s")
	}
}
