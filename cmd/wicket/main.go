// Package main is the CLI entry point for wicket, a credential broker daemon.
// The wicket binary acts as both the daemon and the client. The first argument
// determines the subcommand: start, stop, status, get, lock, unlock, audit,
// providers, version.
package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/1507-systems/wicket/internal/config"
	"github.com/1507-systems/wicket/internal/daemon"
	"github.com/1507-systems/wicket/internal/protocol"
)

// Version is set at build time via -ldflags.
var Version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcmd := os.Args[1]

	switch subcmd {
	case "start":
		cmdStart()
	case "stop":
		cmdStop()
	case "status":
		cmdStatus()
	case "get":
		cmdGet()
	case "lock":
		cmdLock()
	case "unlock":
		cmdUnlock()
	case "audit":
		cmdAudit()
	case "providers":
		cmdProviders()
	case "version":
		fmt.Fprintf(os.Stdout, "wicket %s\n", Version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "wicket: unknown command %q\n", subcmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `wicket -- local credential broker daemon

Usage:
  wicket start [-d] [-c config]     Start the daemon (foreground or -d for background)
  wicket stop                       Stop the running daemon
  wicket status                     Show daemon status
  wicket get <provider>/<scope>     Request a scoped token (token printed to stdout)
  wicket lock                       Immediately lock the daemon
  wicket unlock                     Unlock the daemon (re-reads coffer)
  wicket audit [--limit N]          Show recent audit log entries
  wicket providers                  List configured providers
  wicket version                    Print version info
  wicket help                       Show this help

Exit codes:
  0  success
  1  error
  2  daemon locked
`)
}

// cmdStart runs the daemon. With -d it daemonizes; otherwise runs in foreground.
func cmdStart() {
	configPath := ""
	daemonize := false

	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-d":
			daemonize = true
		case "-c", "--config":
			if i+1 < len(os.Args) {
				configPath = os.Args[i+1]
				i++
			} else {
				fatal("--config requires a path argument")
			}
		default:
			fatal("unknown flag: %s", os.Args[i])
		}
	}

	if daemonize {
		// Re-exec ourselves without -d, running in the background
		args := []string{"start"}
		if configPath != "" {
			args = append(args, "-c", configPath)
		}
		cmd := exec.Command(os.Args[0], args...)
		cmd.Stdout = nil
		cmd.Stderr = nil
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true,
		}
		if err := cmd.Start(); err != nil {
			fatal("failed to daemonize: %v", err)
		}
		fmt.Fprintf(os.Stderr, "wicket daemon started (PID %d)\n", cmd.Process.Pid)
		return
	}

	// Set up structured logging to stderr
	handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	slog.SetDefault(slog.New(handler))

	cfg, err := config.Load(configPath)
	if err != nil {
		fatal("failed to load config: %v", err)
	}

	d, err := daemon.New(cfg)
	if err != nil {
		fatal("failed to create daemon: %v", err)
	}

	// Load providers (reads credentials from coffer)
	if err := d.LoadProviders(); err != nil {
		fatal("failed to load providers: %v", err)
	}

	// Run blocks until shutdown
	if err := d.Run(); err != nil {
		fatal("daemon error: %v", err)
	}
}

// cmdStop sends SIGTERM to the running daemon.
func cmdStop() {
	pidFile := config.DefaultPIDPath()
	data, err := os.ReadFile(pidFile)
	if err != nil {
		fatal("no running daemon found (cannot read PID file %s): %v", pidFile, err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		fatal("invalid PID in %s: %v", pidFile, err)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		fatal("cannot find process %d: %v", pid, err)
	}

	if err := process.Signal(syscall.SIGTERM); err != nil {
		fatal("failed to send SIGTERM to PID %d: %v", pid, err)
	}

	fmt.Fprintf(os.Stderr, "wicket: sent SIGTERM to PID %d\n", pid)
}

// cmdGet requests a token from the daemon and prints it to stdout.
func cmdGet() {
	if len(os.Args) < 3 {
		fatal("usage: wicket get <provider>/<scope>")
	}

	parts := strings.SplitN(os.Args[2], "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		fatal("invalid format: expected <provider>/<scope>, got %q", os.Args[2])
	}

	providerName := parts[0]
	scope := parts[1]

	client := protocol.NewClient(config.DefaultSocketPath())
	raw, err := client.SendAndCheck(&protocol.Request{
		Action:   "get",
		Provider: providerName,
		Scope:    scope,
	})
	if err != nil {
		// Check if it's a LOCKED error for exit code 2
		if strings.Contains(err.Error(), protocol.ErrLocked) {
			fmt.Fprintf(os.Stderr, "wicket: daemon is locked\n")
			os.Exit(2)
		}
		fatal("failed to get token: %v", err)
	}

	var resp protocol.Response
	if err := json.Unmarshal(raw, &resp); err != nil {
		fatal("failed to parse response: %v", err)
	}

	// Print ONLY the token to stdout (for $() capture)
	fmt.Print(resp.Token)
}

// cmdStatus shows the daemon's current status.
func cmdStatus() {
	client := protocol.NewClient(config.DefaultSocketPath())
	raw, err := client.SendAndCheck(&protocol.Request{Action: "status"})
	if err != nil {
		fatal("failed to get status: %v", err)
	}

	var resp protocol.StatusResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		fatal("failed to parse status response: %v", err)
	}

	// Pretty-print status to stderr (status is informational, not for capture)
	fmt.Fprintf(os.Stderr, "Status:           %s\n", resp.Status)
	fmt.Fprintf(os.Stderr, "Locked:           %v\n", resp.Locked)
	fmt.Fprintf(os.Stderr, "Uptime:           %ds\n", resp.UptimeSeconds)
	fmt.Fprintf(os.Stderr, "Providers loaded: %d\n", resp.ProvidersLoaded)
	fmt.Fprintf(os.Stderr, "Tokens issued:    %d\n", resp.TokensIssued)
	if resp.LastRequest != nil {
		fmt.Fprintf(os.Stderr, "Last request:     %s\n", resp.LastRequest.Format("2006-01-02 15:04:05"))
	} else {
		fmt.Fprintf(os.Stderr, "Last request:     none\n")
	}
}

// cmdLock sends a lock command to the daemon.
func cmdLock() {
	client := protocol.NewClient(config.DefaultSocketPath())
	_, err := client.SendAndCheck(&protocol.Request{Action: "lock"})
	if err != nil {
		fatal("failed to lock daemon: %v", err)
	}
	fmt.Fprintf(os.Stderr, "wicket: daemon locked\n")
}

// cmdUnlock is a placeholder for the unlock flow. Full implementation
// requires coffer passphrase input or keychain-stored age identity.
func cmdUnlock() {
	// TODO: implement unlock flow
	// 1. Connect to daemon socket
	// 2. Re-read coffer credentials (may prompt for passphrase)
	// 3. Reinitialize providers
	fmt.Fprintf(os.Stderr, "wicket: unlock not yet implemented\n")
	os.Exit(1)
}

// cmdAudit shows recent audit log entries.
func cmdAudit() {
	limit := 20

	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--limit":
			if i+1 < len(os.Args) {
				n, err := strconv.Atoi(os.Args[i+1])
				if err != nil {
					fatal("invalid --limit value: %v", err)
				}
				limit = n
				i++
			} else {
				fatal("--limit requires a number")
			}
		}
	}

	client := protocol.NewClient(config.DefaultSocketPath())
	raw, err := client.SendAndCheck(&protocol.Request{
		Action:  "audit",
		Options: map[string]any{"limit": float64(limit)},
	})
	if err != nil {
		fatal("failed to get audit log: %v", err)
	}

	var resp protocol.AuditResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		fatal("failed to parse audit response: %v", err)
	}

	// Pretty-print audit entries
	for _, entry := range resp.Entries {
		status := "OK"
		if !entry.Success {
			status = "FAIL"
		}
		fmt.Fprintf(os.Stderr, "[%s] %s %s/%s pid=%d uid=%d %s",
			entry.Timestamp.Format("2006-01-02 15:04:05"),
			status,
			entry.Provider,
			entry.Scope,
			entry.CallerPID,
			entry.CallerUID,
			entry.TokenType,
		)
		if entry.Error != "" {
			fmt.Fprintf(os.Stderr, " error=%s", entry.Error)
		}
		fmt.Fprintln(os.Stderr)
	}
}

// cmdProviders lists all configured providers and their health.
func cmdProviders() {
	client := protocol.NewClient(config.DefaultSocketPath())
	raw, err := client.SendAndCheck(&protocol.Request{Action: "providers"})
	if err != nil {
		fatal("failed to get providers: %v", err)
	}

	var resp protocol.ProvidersResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		fatal("failed to parse providers response: %v", err)
	}

	for _, p := range resp.Providers {
		health := "healthy"
		if !p.Healthy {
			health = "UNHEALTHY"
		}
		fmt.Fprintf(os.Stderr, "%-20s %-16s %s  scopes: %s\n",
			p.Name, p.Type, health, strings.Join(p.Scopes, ", "))
	}
}

// fatal prints an error message to stderr and exits with code 1.
func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "wicket: "+format+"\n", args...)
	os.Exit(1)
}
