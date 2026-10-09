# wicket build + deploy
#
# WHY THIS EXISTS
# ---------------
# There was no deploy step at all: the daemon ran a hand-copied binary from
# ~/.local/bin/wicket, so merged fixes never reached production. On 2026-07-25
# the deployed binary turned out to be from 2026-04-09 — old enough that PR #3's
# token caching had never shipped (which is why token minting was hammering the
# Cloudflare token cap) and PR #1's allowed_binaries enforcement was being
# silently ignored. Nobody noticed for four months because nothing compared the
# running binary to the repo.
#
# So `make install` is deliberately verify-or-fail: it refuses to leave the
# daemon down, and it proves the credential path works before declaring success.
# `make check-deployed` answers "is what's running actually current?" — run it
# whenever wicket behaves in a way the source says it shouldn't.

BINARY       := wicket
DAEMON_LABEL := com.1507.wicket

# DEPLOY TARGET (corrected 2026-09-03)
# -----------------------------------
# INSTALL_DIR used to be $(HOME)/.local/bin, which is NOT what runs. The
# LaunchDaemon /Library/LaunchDaemons/com.1507.wicket.plist executes
# /usr/local/bin/wicket, so installing to ~/.local/bin updated a binary nothing
# started. On 2026-09-03 the two paths held DIFFERENT builds (~/.local/bin from
# Aug 15, /usr/local/bin from Aug 16) and, because ~/.local/bin comes FIRST on
# the interactive PATH, `wicket` in a login shell was a different binary from
# the one the daemon was running. That is how six merged PRs (#4-#9, including a
# security fix and two Cloudflare token-cap fixes) sat undeployed for weeks.
#
# HOST CLASSES (2026-10-08)
# -------------------------
# Wicket runs two ways, on purpose, and `make install` detects which from what
# launchd has loaded, so there is one install command for every machine:
#
#   server       headless box (Wiles). Must start at boot with nobody logged in,
#                so it is the system LaunchDaemon system/$(DAEMON_LABEL) running
#                /usr/local/bin/wicket. /usr/local/bin is rogue:staff and
#                group-writable there, so no sudo is needed. ~/.local/bin/wicket
#                is kept as a SYMLINK to it so the two PATH entries never diverge.
#   workstation  machine a person logs into (Verve). Runs as the user
#                LaunchAgent gui/<uid>/$(DAEMON_LABEL) executing
#                ~/.local/bin/wicket (a real file). /usr/local/bin is root-owned
#                there, and putting wicket in it would make every upgrade need
#                an admin password, which agents cannot supply.
#
# The split is recorded in provisioning ai/EXCEPTIONS.md. Neither loaded means
# a fresh or broken machine: install refuses rather than guess; force a class
# with `make install HOST_CLASS=server|workstation` after loading the plist.
GUI_TARGET    := gui/$(shell id -u)/$(DAEMON_LABEL)
SYSTEM_TARGET := system/$(DAEMON_LABEL)
HOST_CLASS ?= $(shell if launchctl print $(SYSTEM_TARGET) >/dev/null 2>&1; then echo server; \
	elif launchctl print $(GUI_TARGET) >/dev/null 2>&1; then echo workstation; else echo unknown; fi)
ifeq ($(HOST_CLASS),server)
INSTALL_DIR    := /usr/local/bin
LEGACY_LINK    := $(HOME)/.local/bin/$(BINARY)
LAUNCHD_TARGET := $(SYSTEM_TARGET)
else
INSTALL_DIR    := $(HOME)/.local/bin
LEGACY_LINK    :=
LAUNCHD_TARGET := $(GUI_TARGET)
endif
INSTALLED   := $(INSTALL_DIR)/$(BINARY)
BUILD_OUT   := ./$(BINARY)
# Any scope is fine here; this only has to prove the daemon answers and can mint.
VERIFY_SCOPE := cloudflare/d1-read

.PHONY: build test vet fmt install check-deployed restart uninstall-check host-class

# Print what install would do on this machine, without doing it.
host-class:
	@echo "$(HOST_CLASS): $(LAUNCHD_TARGET) -> $(INSTALLED)$(if $(LEGACY_LINK), (+ symlink $(LEGACY_LINK)),)"

build:
	go build -o $(BUILD_OUT) ./cmd/wicket

test:
	go test ./...

vet:
	go vet ./...

fmt:
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi; \
	echo "gofmt clean"

# Full gate. Never install something that does not build, test, vet and format.
install: fmt vet test build
	@set -e; \
	case "$(HOST_CLASS)" in server|workstation) ;; \
	*) echo "REFUSED: host class is $(HOST_CLASS): neither $(SYSTEM_TARGET) nor $(GUI_TARGET) is loaded."; \
	   echo "  Load the host's plist from provisioning first, or pass HOST_CLASS=server|workstation."; exit 1 ;; esac; \
	echo "==> host class: $(HOST_CLASS) ($(LAUNCHD_TARGET) -> $(INSTALLED))"; \
	if [ -L "$(INSTALLED)" ]; then echo "REFUSED: $(INSTALLED) is a symlink; this host's layout is not what $(HOST_CLASS) expects"; exit 1; fi; \
	echo "==> backing up the current binary (rollback path)"; \
	if [ -f "$(INSTALLED)" ]; then \
		cp "$(INSTALLED)" "/tmp/wicket-rollback-$$(date +%s)"; \
		echo "    saved /tmp/wicket-rollback-*"; \
	else \
		echo "    none installed yet"; \
	fi; \
	echo "==> installing $(BUILD_OUT) -> $(INSTALLED)"; \
	mkdir -p "$(INSTALL_DIR)"; \
	cp "$(BUILD_OUT)" "$(INSTALLED).new"; \
	chmod +x "$(INSTALLED).new"; \
	mv -f "$(INSTALLED).new" "$(INSTALLED)"; \
	if [ -n "$(LEGACY_LINK)" ]; then \
		echo "==> pointing $(LEGACY_LINK) at the installed binary"; \
		mkdir -p "$(dir $(LEGACY_LINK))"; \
		ln -sfn "$(INSTALLED)" "$(LEGACY_LINK)"; \
	fi; \
	echo "==> restarting daemon"; \
	$(MAKE) --no-print-directory restart; \
	echo "==> verifying"; \
	if ! "$(INSTALLED)" status >/dev/null 2>&1; then \
		echo "FAILED: daemon does not answer status. Rolling back."; \
		latest=$$(ls -t /tmp/wicket-rollback-* 2>/dev/null | head -1); \
		if [ -n "$$latest" ]; then \
			cp "$$latest" "$(INSTALLED).new" && mv -f "$(INSTALLED).new" "$(INSTALLED)"; \
			$(MAKE) --no-print-directory restart; \
			echo "rolled back to $$latest"; \
		fi; \
		exit 1; \
	fi; \
	if ! "$(INSTALLED)" get $(VERIFY_SCOPE) >/dev/null 2>&1; then \
		echo "FAILED: daemon answers but cannot mint ($(VERIFY_SCOPE)). Rolling back."; \
		latest=$$(ls -t /tmp/wicket-rollback-* 2>/dev/null | head -1); \
		if [ -n "$$latest" ]; then \
			cp "$$latest" "$(INSTALLED).new" && mv -f "$(INSTALLED).new" "$(INSTALLED)"; \
			$(MAKE) --no-print-directory restart; \
			echo "rolled back to $$latest"; \
		fi; \
		exit 1; \
	fi; \
	echo "OK: installed, daemon healthy, credential path verified"

# Is the running binary built from current HEAD? Compares the installed binary
# against a fresh build of the working tree.
check-deployed: build
	@installed_hash=$$(shasum -a 256 "$(INSTALLED)" 2>/dev/null | cut -d' ' -f1); \
	fresh_hash=$$(shasum -a 256 "$(BUILD_OUT)" | cut -d' ' -f1); \
	echo "installed: $${installed_hash:-<none>}"; \
	echo "fresh    : $$fresh_hash"; \
	if [ "$$installed_hash" = "$$fresh_hash" ]; then \
		echo "MATCH — the running binary is current"; \
	else \
		echo "DRIFT — the installed binary differs from a build of this tree."; \
		echo "        Run 'make install'. (A four-month drift went unnoticed once.)"; \
		exit 1; \
	fi

# Restart the daemon the way it is actually supervised.
#
# wicket runs as launchd job $(LAUNCHD_TARGET) with KeepAlive=1, so `stop` is
# enough: launchd notices the exit and restarts it within seconds, loading
# providers from the vault afresh. The old `stop; start -d` raced launchd's
# managed instance, which could leave a second, unsupervised daemon holding the
# socket. Poll for readiness rather than sleeping a fixed 2s.
#
# `wicket status` writes to STDERR, not stdout, so the grep needs 2>&1. A check
# written with 2>/dev/null silently sees nothing and reports a healthy daemon as
# locked.
restart:
	@set -e; \
	pid=$$(pgrep -x -f '$(INSTALLED) start' 2>/dev/null | head -1); \
	"$(INSTALLED)" stop 2>/dev/null || true; \
	if launchctl print $(LAUNCHD_TARGET) >/dev/null 2>&1; then \
		echo "    (launchd-supervised: $(LAUNCHD_TARGET))"; \
		for i in 1 2 3 4 5; do \
			if [ -z "$$pid" ] || ! kill -0 "$$pid" 2>/dev/null; then break; fi; \
			sleep 1; \
		done; \
		if [ -n "$$pid" ] && kill -0 "$$pid" 2>/dev/null; then \
			echo "    'stop' left pid $$pid alive (socket closed, process lingering)"; \
			echo "    -> killing it so KeepAlive restarts the daemon"; \
			kill "$$pid" 2>/dev/null || true; \
		fi; \
	else \
		echo "    (not launchd-supervised: starting manually)"; \
		"$(INSTALLED)" start -d; \
	fi; \
	for i in $$(seq 1 30); do \
		if "$(INSTALLED)" status 2>&1 | grep -q '^Locked:'; then break; fi; \
		sleep 1; \
	done; \
	if ! "$(INSTALLED)" status 2>&1 | grep -q '^Locked:'; then \
		echo "FAILED: daemon did not come back within 30s"; exit 1; \
	fi; \
	"$(INSTALLED)" status 2>&1 | head -4
