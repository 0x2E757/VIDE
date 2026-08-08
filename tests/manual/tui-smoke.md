# Manual TUI smoke — the standing gate before the wizard is called done

Rendering, real keyboards and real terminals cannot be pinned hermetically
(a pty-scripted arbiter run would couple the frozen tier to screen layout —
the exact anti-pattern it exists to prevent). This checklist replaces that
coverage; run it in a REAL ssh terminal on a disposable VM/container, and record
the result wherever the change that declares the TUI slice done is reviewed.

Every line has an expected observation. A deviation is a finding against the
implementation — never a reason to soften this list.

## 1. Happy path (fresh box)

Walk this section at least once as BARE ROOT on a minimal image where
`dpkg -s sudo` fails (fresh debian:13 / minimal cloud image), so the target
defaults to the dedicated `vide` fallback and the ensure-sudo step actually
executes. Lesson pinned here: minimal images ship the sudo GROUP (gid 27,
base-passwd) without the PACKAGE, so `useradd -G sudo` succeeds and the
pre-fix failure only surfaced at the sudoers step — every hermetic tier and
the arbiter pre-create the target user and never walk this branch.

- [ ] `sudo ./install.sh` on an interactive terminal → the curses wizard
      opens (header, step status, bottom log pane).
- [ ] Walk it with Enter-only (defaults): exposure ack → target user
      (detected default preselected) → password (generate) → fqdn (empty ok)
      → live log scrolls during apt/node/code-server steps; spinner and
      status change; the screen never shows a password anywhere.
- [ ] The log pane is live on QUESTION screens too: INFO/WARN lines emitted
      between steps appear in the pane while a menu or field is up, not only
      during exec (`target instance user: ...` fires on EVERY run and must be
      visible by the time the next screen is up).
- [ ] apt/dpkg-heavy steps COMPLETE and the wizard advances (the status line
      moves past each step; the spinner never sits on one step forever).
      Lesson pinned here: a background child touching the controlling tty is
      STOPPED by the kernel (SIGTTIN/SIGTTOU) — it manifests ONLY on a real
      interactive terminal; every hermetic tier missed this live hang. From
      a second shell mid-apt, `ps -o pid,sid,tty,stat -p <apt pid>` shows
      `TTY ?` and STAT never `T`.
- [ ] Summary screen shows user/port/version/config/toolchain + the
      equivalent `--no-gui` command.
- [ ] After Enter: wizard closes; scrollback holds (in order) the full
      replayed log, the summary, the SHOWN-ONCE password (LAST lines before
      the prompt), and the Caddy snippet; `echo $?` → 0.
- [ ] On the vide-fallback walk: scrollback holds TWO SHOWN-ONCE secrets
      (login/sudo first, code-server second) and they differ; afterwards
      `su - vide`, then a PLAIN `sudo true` (no -k — `sudo -k cmd` never
      records a timestamp and would pass vacuously) authenticates with the
      recorded password, and the immediately following `sudo -n true` in the
      same shell FAILS (`-n` never prompts; timestamp_timeout=0 means no warm
      timestamp survives even a real sudo).
- [ ] Terminal is sane afterwards: typing echoes, `stty -a` sensible, no
      `reset` needed.

## 2. Interrupts and failure

- [ ] Ctrl-C on a question screen → "Abort install?" modal; `n` continues,
      `y` exits through endwin → full replay → a "resume with: …" note →
      non-zero exit (130 family). NO error panel on a confirmed abort.
- [ ] Ctrl-C during the apt/download step → same modal; on `y` the child
      process group gets SIGTERM (then KILL after ~5s grace) and the wizard
      exits through the same funnel — within the grace even if the child was
      stopped (`kill -STOP` it from a second shell first to check: the pane
      shows the "stopped (state T)" WARN, and abort still exits promptly).
- [ ] `q` on any menu → the same quit-confirm modal.
- [ ] Ctrl-C AT the destroy confirm modal → abort `y` → the resume note
      shows `sudo vide destroy <user> && ...` WITHOUT `--yes` (selected but
      unratified: the pasted command re-asks its own destroy prompt).
- [ ] root → Continue → Ctrl-C at the typed-ROOT challenge → abort `y` →
      the resume note carries NO `VIDE_CONFIRM_ROOT` (the typed challenge
      must be re-answered on paste; only the finish summary's command is
      fully scripted).
- [ ] Second Ctrl-C while the abort modal is open → immediate exit, replay
      still printed, terminal still sane.
- [ ] Kill the network mid-download → error panel appears with the real
      error; Retry after restoring network converges to success.
- [ ] `l` opens the full-screen log view; arrows/PgUp/PgDn scroll; `q`
      returns; nothing is lost from the pane.

## 3. The gate

- [ ] `sudo ./install.sh < /dev/null` → plain flow, byte-familiar output,
      one INFO line about the missing terminal.
- [ ] `sudo vide install > /tmp/snippet.conf` → plain flow; the file holds
      ONLY the snippet.
- [ ] `sudo vide install --no-gui` → plain flow, zero interaction.
- [ ] `TERM=dumb sudo ./install.sh` → refusal naming TERM + a paste-ready
      `--no-gui` command; exit 69; pasting the command runs plain.
- [ ] `echo 'sixteen-chars-pw' | sudo vide install --no-gui --password-stdin`
      → plain install using the supplied password; no SHOWN-ONCE line;
      logging in with that password works.

## 4. Terminal edge cases

- [ ] Resize the window during a question and during an exec step → relayout,
      no crash; shrink below 80x24 → freeze frame until enlarged.
- [ ] Run inside tmux → wizard renders; detach/attach mid-install → intact.
- [ ] Ctrl-Z then `fg` → screen redraws on the next keypress/tick.
- [ ] `ssh -t` from a terminal whose TERM the server lacks (e.g. kitty
      without ncurses-term) → the decision-6 refusal, not a crash.

## 5. Existing-instance journeys

- [ ] Re-run the wizard for the same user → "already exists" screen;
      Converge keeps version+password (MainPID stable if it was running).
- [ ] Bare-root re-run after a vide-fallback install → the same "already
      exists" journey for the `vide` instance; NO second login-password
      SHOWN-ONCE line (the pwset marker guard).
- [ ] Upgrade → only that instance restarts; summary says upgrade.
- [ ] Rotate → NEW password printed after endwin; old session cookie dead.
- [ ] Reinstall → destructive modal (the verb's exact wording); after it,
      fresh install; `vide ls` sane.
- [ ] Wizard as root picking `root` target → first the ROOT-consequence
      screen (Back returns to the user menu), then the typed-ROOT modal (the
      Confirmer challenge, in-wizard); a mistyped challenge returns to the
      user menu — never an error panel.
- [ ] Reinstall → destroy modal answered `N` → back on the existing-instance
      menu, previous selection preserved.
- [ ] Reinstall → destroy modal answered `N` → back on the menu → `q` → `y`
      → the post-exit "resume with:" note is the plain `--no-gui` converge
      command carrying the confirmed `--user <u>`, and contains NO
      `vide destroy` — the twin reflects only CONFIRMED answers, never the
      destruction that was just refused.
- [ ] `./install.sh` WITHOUT sudo on a tty → plain one-liner "must run as
      root — re-run with: sudo …"; the wizard never opens.
- [ ] `LC_ALL=C sudo ./install.sh` → wizard renders (ASCII/folded), no
      UnicodeEncodeError anywhere, including the log pane during apt.

## 6. Dry-run wizard

- [ ] `sudo vide --dry-run install` on a tty → wizard opens with the
      persistent DRY-RUN badge; exec steps stream `[dry-run]` narration;
      summary is titled as a preview; nothing on the box changed
      (`vide ls`, `/etc/vide`, `systemctl` all unchanged).
- [ ] The `[dry-run]` narration fills the log pane WHILE question screens are
      up (a dry-run spawns nothing, so the pane's only feed is the repaint).
- [ ] After Enter: the replay header reports a nonzero line count that is
      plausible against the replayed body (never "0" over a full log), and
      the post-exit summary block contains NO "Enter closes the wizard"
      sentence — that copy is screen-only.
