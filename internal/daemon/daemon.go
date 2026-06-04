// Package daemon implements the wicket Unix socket server.
//
// The daemon listens on a Unix socket, authenticates connecting processes
// via kernel credentials (getpeereid), dispatches requests to the appropriate
// provider, and logs every operation to the audit log.
package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/1507-systems/wicket/internal/audit"
	"github.com/1507-systems/wicket/internal/config"
	"github.com/1507-systems/wicket/internal/coffer"
	"github.com/1507-systems/wicket/internal/notify"
	"github.com/1507-systems/wicket/internal/protocol"
	"github.com/1507-systems/wicket/internal/provider"
)

// Daemon is the main wicket daemon process. It manages the Unix socket
// listener, provider registry, audit logging, and lifecycle (lock/unlock/stop).
type Daemon struct {
	cfg       *config.Config
	listener  net.Listener
	providers map[string]provider.TokenProvider
	coffer   *coffer.Reader
	auditor   *audit.Logger
	notifier  *notify.Notifier

	// State tracking
	startTime   time.Time
	lastRequest atomic.Value // *time.Time
	tokensIssued atomic.Int64
	locked       atomic.Bool

	// Idle timeout
	idleTimer *time.Timer

	// Shutdown coordination
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a new daemon from the given config. It does NOT start
// listening; call Run() for that.
func New(cfg *config.Config) (*Daemon, error) {
	auditor, err := audit.NewLogger(cfg.AuditLog)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit logger: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	d := &Daemon{
		cfg:       cfg,
		providers: make(map[string]provider.TokenProvider),
		coffer:   coffer.NewReader(cfg.CofferPath),
		auditor:   auditor,
		notifier:  notify.NewNotifier(),
		startTime: time.Now(),
		ctx:       ctx,
		cancel:    cancel,
	}

	return d, nil
}

// LoadProviders reads root credentials from coffer and initializes all
// configured providers. This is called on startup and after unlock.
func (d *Daemon) LoadProviders() error {
	for name, pcfg := range d.cfg.Providers {
		p, err := d.initProvider(name, pcfg)
		if err != nil {
			return fmt.Errorf("failed to initialize provider %q: %w", name, err)
		}
		d.providers[name] = p
		slog.Info("loaded provider", "name", name, "type", pcfg.Type, "scopes", p.Scopes())
	}
	return nil
}

// initProvider creates a single provider instance by reading its credentials
// from coffer and constructing the appropriate provider type.
func (d *Daemon) initProvider(name string, pcfg config.ProviderConfig) (provider.TokenProvider, error) {
	switch pcfg.Type {
	case "cloudflare":
		metaToken, err := d.coffer.Get(pcfg.RootCredential)
		if err != nil {
			return nil, fmt.Errorf("failed to read root credential: %w", err)
		}
		cfConfig := provider.CloudflareConfig{Scopes: make(map[string]provider.CloudflareScope)}
		for scopeName, scopeCfg := range pcfg.Scopes {
			cfConfig.Scopes[scopeName] = provider.CloudflareScope{
				Permissions: scopeCfg.Permissions,
				ZoneIDs:     scopeCfg.ZoneIDs,
				AccountIDs:  scopeCfg.AccountIDs,
			}
		}
		return provider.NewCloudflare(name, metaToken, pcfg.DefaultTTL.Duration, cfConfig), nil

	case "github":
		privateKey, err := d.coffer.Get(pcfg.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key: %w", err)
		}
		ghConfig := provider.GitHubConfig{Scopes: make(map[string]provider.GitHubScope)}
		for scopeName, scopeCfg := range pcfg.Scopes {
			ghConfig.Scopes[scopeName] = provider.GitHubScope{
				Permissions:  scopeCfg.GHPermissions,
				Repositories: scopeCfg.Repositories,
			}
		}
		return provider.NewGitHub(name, pcfg.AppID, pcfg.InstallationID, []byte(privateKey), ghConfig)

	case "tailscale_oauth":
		clientID, err := d.coffer.Get(pcfg.ClientID)
		if err != nil {
			return nil, fmt.Errorf("failed to read client_id: %w", err)
		}
		clientSecret, err := d.coffer.Get(pcfg.ClientSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to read client_secret: %w", err)
		}
		tsConfig := provider.TailscaleConfig{Scopes: make(map[string]provider.TailscaleScope)}
		for scopeName, scopeCfg := range pcfg.Scopes {
			tsConfig.Scopes[scopeName] = provider.TailscaleScope{
				TailscaleScopes: scopeCfg.TailscaleScopes,
			}
		}
		return provider.NewTailscale(name, clientID, clientSecret, tsConfig), nil

	case "zoho_oauth":
		clientID, err := d.coffer.Get(pcfg.ClientID)
		if err != nil {
			return nil, fmt.Errorf("failed to read client_id: %w", err)
		}
		clientSecret, err := d.coffer.Get(pcfg.ClientSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to read client_secret: %w", err)
		}
		refreshToken, err := d.coffer.Get(pcfg.RefreshToken)
		if err != nil {
			return nil, fmt.Errorf("failed to read refresh_token: %w", err)
		}
		zohoConfig := provider.ZohoConfig{Scopes: make(map[string]provider.ZohoScope)}
		for scopeName, scopeCfg := range pcfg.Scopes {
			zohoConfig.Scopes[scopeName] = provider.ZohoScope{
				ZohoScopes: scopeCfg.ZohoScopes,
			}
		}
		return provider.NewZoho(name, clientID, clientSecret, refreshToken, pcfg.RefreshToken, pcfg.Domain, zohoConfig, d.coffer, d.notifier), nil

	case "passthrough":
		credential, err := d.coffer.Get(pcfg.Credential)
		if err != nil {
			return nil, fmt.Errorf("failed to read credential: %w", err)
		}
		scopes := make([]string, 0, len(pcfg.Scopes))
		for s := range pcfg.Scopes {
			scopes = append(scopes, s)
		}
		// If no scopes are configured, use "token" as default
		if len(scopes) == 0 {
			scopes = []string{"token"}
		}
		return provider.NewPassthrough(name, credential, scopes), nil

	default:
		return nil, fmt.Errorf("unknown provider type: %q", pcfg.Type)
	}
}

// Run starts the daemon: creates the socket, writes the PID file, and
// begins accepting connections. It blocks until the context is cancelled
// or a shutdown signal is received.
func (d *Daemon) Run() error {
	// Check for stale socket/PID (indicates previous unclean exit)
	d.detectStaleState()

	// Remove any existing socket file
	if err := os.Remove(d.cfg.SocketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing socket: %w", err)
	}

	// Ensure socket directory exists
	socketDir := filepath.Dir(d.cfg.SocketPath)
	if err := os.MkdirAll(socketDir, 0700); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Create the Unix socket listener
	listener, err := net.Listen("unix", d.cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on socket %s: %w", d.cfg.SocketPath, err)
	}
	d.listener = listener

	// Set socket permissions to 0700 (owner only)
	if err := os.Chmod(d.cfg.SocketPath, 0700); err != nil {
		listener.Close()
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	// Write PID file
	if err := d.writePIDFile(); err != nil {
		listener.Close()
		return fmt.Errorf("failed to write PID file: %w", err)
	}

	// Set up idle timeout if configured
	if d.cfg.IdleTimeout.Duration > 0 {
		d.idleTimer = time.AfterFunc(d.cfg.IdleTimeout.Duration, func() {
			slog.Info("idle timeout reached, locking daemon")
			d.Lock()
		})
	}

	// Set up signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		select {
		case sig := <-sigCh:
			slog.Info("received signal, shutting down", "signal", sig)
			d.cancel()
		case <-d.ctx.Done():
		}
	}()

	slog.Info("wicket daemon started",
		"socket", d.cfg.SocketPath,
		"pid", os.Getpid(),
		"providers", len(d.providers),
	)

	// Accept loop
	go func() {
		for {
			conn, err := d.listener.Accept()
			if err != nil {
				select {
				case <-d.ctx.Done():
					return // Shutting down
				default:
					slog.Error("failed to accept connection", "error", err)
					continue
				}
			}

			d.wg.Add(1)
			go func() {
				defer d.wg.Done()
				d.handleConnection(conn)
			}()
		}
	}()

	// Wait for shutdown signal
	<-d.ctx.Done()
	return d.shutdown()
}

// handleConnection processes a single client connection: authenticate,
// parse request, dispatch to handler, write response, close.
func (d *Daemon) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Set a reasonable deadline for the entire request-response cycle
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Authenticate the peer (UID match) and, when allowed_binaries is
	// configured, enforce the executable allowlist. An empty allowlist keeps
	// the historical behavior of accepting any same-UID caller.
	peer, err := AuthenticatePeerWithBinaries(conn, d.cfg.AllowedBinaries)
	if err != nil {
		slog.Warn("peer authentication failed", "error", err)
		d.notifier.Send("unauthorized", "Wicket: Unauthorized Connection", fmt.Sprintf("Peer authentication failed: %v", err))

		writeJSON(conn, protocol.ErrorResponse{
			Error: "peer authentication failed",
			Code:  protocol.ErrUnauthorized,
		})
		return
	}

	// Parse the request
	var req protocol.Request
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&req); err != nil {
		slog.Warn("failed to decode request", "error", err, "peer_uid", peer.UID, "peer_pid", peer.PID)
		writeJSON(conn, protocol.ErrorResponse{
			Error: fmt.Sprintf("invalid request: %v", err),
			Code:  protocol.ErrInvalidRequest,
		})
		return
	}

	// Reset idle timer on every request
	d.resetIdleTimer()

	// Update last request time
	now := time.Now()
	d.lastRequest.Store(&now)

	// Dispatch based on action
	switch req.Action {
	case "get":
		d.handleGet(conn, &req, peer)
	case "status":
		d.handleStatus(conn)
	case "providers":
		d.handleProviders(conn)
	case "audit":
		d.handleAudit(conn, &req)
	case "lock":
		d.handleLock(conn)
	default:
		writeJSON(conn, protocol.ErrorResponse{
			Error: fmt.Sprintf("unknown action: %q", req.Action),
			Code:  protocol.ErrInvalidRequest,
		})
	}
}

// handleGet processes a token request.
func (d *Daemon) handleGet(conn net.Conn, req *protocol.Request, peer *PeerInfo) {
	// Check if daemon is locked
	if d.locked.Load() {
		d.auditor.Log(audit.Entry{
			Timestamp: time.Now().UTC(),
			Action:    "get",
			Provider:  req.Provider,
			Scope:     req.Scope,
			CallerPID:    peer.PID,
			CallerUID:    peer.UID,
			CallerBinary: peer.Binary,
			Success:   false,
			Error:     "daemon locked",
		})
		writeJSON(conn, protocol.ErrorResponse{
			Error: "daemon locked",
			Code:  protocol.ErrLocked,
		})
		return
	}

	if req.Provider == "" || req.Scope == "" {
		writeJSON(conn, protocol.ErrorResponse{
			Error: "provider and scope are required for 'get' action",
			Code:  protocol.ErrInvalidRequest,
		})
		return
	}

	// Find the provider
	p, ok := d.providers[req.Provider]
	if !ok {
		d.auditor.Log(audit.Entry{
			Timestamp: time.Now().UTC(),
			Action:    "get",
			Provider:  req.Provider,
			Scope:     req.Scope,
			CallerPID:    peer.PID,
			CallerUID:    peer.UID,
			CallerBinary: peer.Binary,
			Success:   false,
			Error:     "provider not found",
		})
		writeJSON(conn, protocol.ErrorResponse{
			Error: fmt.Sprintf("provider %q not configured", req.Provider),
			Code:  protocol.ErrProviderNotFound,
		})
		return
	}

	// Validate scope
	validScope := false
	for _, s := range p.Scopes() {
		if s == req.Scope {
			validScope = true
			break
		}
	}
	if !validScope {
		d.auditor.Log(audit.Entry{
			Timestamp: time.Now().UTC(),
			Action:    "get",
			Provider:  req.Provider,
			Scope:     req.Scope,
			CallerPID:    peer.PID,
			CallerUID:    peer.UID,
			CallerBinary: peer.Binary,
			Success:   false,
			Error:     "scope not found",
		})
		writeJSON(conn, protocol.ErrorResponse{
			Error: fmt.Sprintf("scope %q not available for provider %q", req.Scope, req.Provider),
			Code:  protocol.ErrScopeNotFound,
		})
		return
	}

	// Request the token
	token, err := p.GetToken(d.ctx, req.Scope, req.Options)
	if err != nil {
		slog.Error("token exchange failed", "provider", req.Provider, "scope", req.Scope, "error", err)

		d.auditor.Log(audit.Entry{
			Timestamp: time.Now().UTC(),
			Action:    "get",
			Provider:  req.Provider,
			Scope:     req.Scope,
			CallerPID:    peer.PID,
			CallerUID:    peer.UID,
			CallerBinary: peer.Binary,
			Success:   false,
			Error:     err.Error(),
		})

		writeJSON(conn, protocol.ErrorResponse{
			Error: fmt.Sprintf("token exchange failed: %v", err),
			Code:  protocol.ErrTokenExchangeFailed,
		})
		return
	}

	// Log the successful issuance
	d.tokensIssued.Add(1)
	d.auditor.Log(audit.Entry{
		Timestamp: time.Now().UTC(),
		Action:    "get",
		Provider:  req.Provider,
		Scope:     req.Scope,
		CallerPID: peer.PID,
		CallerUID: peer.UID,
		TokenType: token.Type,
		ExpiresAt: token.ExpiresAt,
		Success:   true,
	})

	writeJSON(conn, protocol.Response{
		Token:     token.Value,
		ExpiresAt: token.ExpiresAt,
		Provider:  token.Provider,
		Scope:     token.Scope,
		Type:      token.Type,
	})
}

// handleStatus returns the current daemon status.
func (d *Daemon) handleStatus(conn net.Conn) {
	var lastReq *time.Time
	if v := d.lastRequest.Load(); v != nil {
		lastReq = v.(*time.Time)
	}

	writeJSON(conn, protocol.StatusResponse{
		Status:          statusString(d.locked.Load()),
		Locked:          d.locked.Load(),
		UptimeSeconds:   int64(time.Since(d.startTime).Seconds()),
		ProvidersLoaded: len(d.providers),
		TokensIssued:    d.tokensIssued.Load(),
		LastRequest:     lastReq,
	})
}

// handleProviders returns information about all loaded providers.
func (d *Daemon) handleProviders(conn net.Conn) {
	infos := make([]protocol.ProviderInfo, 0, len(d.providers))
	for _, p := range d.providers {
		infos = append(infos, protocol.ProviderInfo{
			Name:    p.Name(),
			Type:    p.Type(),
			Scopes:  p.Scopes(),
			Healthy: p.Healthy(),
		})
	}
	writeJSON(conn, protocol.ProvidersResponse{Providers: infos})
}

// handleAudit returns recent audit log entries.
func (d *Daemon) handleAudit(conn net.Conn, req *protocol.Request) {
	limit := 20
	if req.Options != nil {
		if l, ok := req.Options["limit"]; ok {
			switch v := l.(type) {
			case float64:
				limit = int(v)
			case int:
				limit = v
			}
		}
	}

	entries, err := d.auditor.ReadLast(limit)
	if err != nil {
		writeJSON(conn, protocol.ErrorResponse{
			Error: fmt.Sprintf("failed to read audit log: %v", err),
			Code:  protocol.ErrInternalError,
		})
		return
	}

	// Convert audit.Entry to protocol.AuditEntry
	protoEntries := make([]protocol.AuditEntry, len(entries))
	for i, e := range entries {
		protoEntries[i] = protocol.AuditEntry{
			Timestamp:    e.Timestamp,
			Action:       e.Action,
			Provider:     e.Provider,
			Scope:        e.Scope,
			CallerPID:    e.CallerPID,
			CallerUID:    e.CallerUID,
			CallerBinary: e.CallerBinary,
			TokenType:    e.TokenType,
			ExpiresAt:    e.ExpiresAt,
			Success:      e.Success,
			Error:        e.Error,
		}
	}

	writeJSON(conn, protocol.AuditResponse{Entries: protoEntries})
}

// handleLock immediately locks the daemon, clearing all credentials from memory.
func (d *Daemon) handleLock(conn net.Conn) {
	d.Lock()
	writeJSON(conn, protocol.LockResponse{Status: "locked"})
}

// Lock clears all provider credentials from memory and sets the daemon
// to locked state. The socket remains open but returns LOCKED errors.
func (d *Daemon) Lock() {
	if d.locked.Load() {
		return // Already locked
	}

	slog.Info("locking daemon, clearing credentials from memory")

	for _, p := range d.providers {
		if err := p.Close(); err != nil {
			slog.Error("failed to close provider during lock", "provider", p.Name(), "error", err)
		}
	}

	d.locked.Store(true)
}

// shutdown performs graceful shutdown: zero credentials, remove socket, remove PID.
func (d *Daemon) shutdown() error {
	slog.Info("shutting down wicket daemon")

	// Close the listener to stop accepting new connections
	if d.listener != nil {
		d.listener.Close()
	}

	// Wait for in-flight connections to complete (with timeout)
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		slog.Warn("timed out waiting for connections to close")
	}

	// Zero all credential memory
	for _, p := range d.providers {
		if err := p.Close(); err != nil {
			slog.Error("failed to close provider during shutdown", "provider", p.Name(), "error", err)
		}
	}

	// Stop idle timer
	if d.idleTimer != nil {
		d.idleTimer.Stop()
	}

	// Flush and close audit log
	if d.auditor != nil {
		d.auditor.Close()
	}

	// Remove socket file
	os.Remove(d.cfg.SocketPath)

	// Remove PID file
	os.Remove(d.cfg.PIDFile)

	slog.Info("wicket daemon stopped")
	return nil
}

// detectStaleState checks for leftover socket/PID files from a previous
// unclean exit and sends an ntfy notification if found.
func (d *Daemon) detectStaleState() {
	stale := false

	if _, err := os.Stat(d.cfg.SocketPath); err == nil {
		slog.Warn("stale socket detected, removing", "path", d.cfg.SocketPath)
		os.Remove(d.cfg.SocketPath)
		stale = true
	}

	if _, err := os.Stat(d.cfg.PIDFile); err == nil {
		slog.Warn("stale PID file detected", "path", d.cfg.PIDFile)
		stale = true
	}

	if stale {
		d.notifier.Send("stale_state", "Wicket: Unclean Restart",
			"Detected stale socket or PID file from previous unclean exit")
	}
}

// writePIDFile writes the current process PID to the configured PID file path.
func (d *Daemon) writePIDFile() error {
	dir := filepath.Dir(d.cfg.PIDFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create PID file directory: %w", err)
	}
	return os.WriteFile(d.cfg.PIDFile, []byte(strconv.Itoa(os.Getpid())), 0600)
}

// resetIdleTimer resets the idle timeout timer. Called on every request.
func (d *Daemon) resetIdleTimer() {
	if d.idleTimer != nil {
		d.idleTimer.Reset(d.cfg.IdleTimeout.Duration)
	}
}

// writeJSON encodes a value as JSON and writes it to the connection.
func writeJSON(conn net.Conn, v any) {
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(v); err != nil {
		slog.Error("failed to write JSON response", "error", err)
	}
}

func statusString(locked bool) string {
	if locked {
		return "locked"
	}
	return "running"
}
