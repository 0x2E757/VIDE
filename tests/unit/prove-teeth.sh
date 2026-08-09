#!/usr/bin/env bash
# Mutation teeth-proofs — the red-before-green substitute for a greenfield port.
#
# A ported test NAME does not prove ported TEETH: an assertion rewritten to
# pass trivially is the failure mode the parity tier's non-empty-trace guard
# existed for. For each historical bug, this applies the one-line re-introduction to a
# SCRATCH copy of the package and requires the named test to go RED there.
# The suite is not "done" until all reds are demonstrated. Rows 7-13 guard the
# TUI slice's load-bearing behaviors; rows 10-13 ARE historical bugs from the
# first live smoke walks: the dead pane (dry-run never ticks), the SIGTTOU
# stop (a ticking child inheriting the tty stdin hung apt in state T), the
# sudo package assumed present (minimal images ship the GROUP only), and the
# stale destroy twin (a declined reinstall leaked --yes into the resume note).
#
# Usage: tests/unit/prove-teeth.sh          (runs every row, ~30s)
set -uo pipefail
REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT

pass=0 fail=0

# The shared verdict, used by BOTH prove and prove_unit.
#
# A non-zero exit is NOT sufficient evidence that the named test went red: a
# test id that rotted (module/class/method renamed) also exits non-zero, so a
# stale row reported `ok`. This file's whole authority is "a test that cannot
# fail is not coverage", and its own red-detection was the half it did not guard.
#
# Reading the MUTATED run's output cannot close it, and this is the trap worth
# recording: unittest SYNTHESIZES a _FailedTest placeholder both for an id it
# cannot resolve AND for a mutation that breaks the module's import — so a stale
# id prints an ordinary "Ran 1 test" + "FAILED (errors=1)" that is byte-wise
# indistinguishable from a legitimate red. Measured, not assumed: 20 of the 51
# rows here fail at collection time on purpose, so grepping the placeholder
# fails all twenty.
#
# The id is therefore resolved against the PRISTINE tree, where no mutation can
# confuse it. loader.errors is the exact signal — loadTestsFromName has returned
# a placeholder instead of raising since 3.5.
resolves() { # <test-id> -> 0 iff the id names something real
  (cd "$REPO" && PYTHONPATH="$REPO/tests/unit:$REPO/src" python3 -c '
import sys, unittest
loader = unittest.defaultTestLoader
loader.loadTestsFromName(sys.argv[1])
sys.exit(1 if loader.errors else 0)
' "$1" >/dev/null 2>&1)
}

red_or_fail() { # <bug-name> <test-id>
  local name=$1 test_id=$2
  if ! resolves "$test_id"; then
    printf '  FAIL %s (the named test does not exist — id "%s" is stale)\n' "$name" "$test_id"
    fail=$((fail+1)); return
  fi
  # …and it must be GREEN on the PRISTINE tree. A row whose named test is
  # already red — for an environmental reason, a host-coupled assertion, a
  # broken fixture — reports `ok` against the mutant while proving nothing at
  # all. That is the same defect as the twenty import-error rows this file's
  # header records, one layer up: the check was silent in a way that read as
  # health. One extra invocation per row, and it is the cheapest thing here.
  if ! (cd "$REPO" && PYTHONPATH="$REPO/tests/unit:$REPO/src" \
        python3 -m unittest "$test_id" >/dev/null 2>&1); then
    printf '  FAIL %s (the named test is ALREADY RED on the pristine tree — this\n' "$name"
    printf '       row proves nothing; fix the test or the box first)\n'
    fail=$((fail+1)); return
  fi
  # PYTHONPATH mirrors run.py's two sys.path inserts. Without it this file was
  # not running the tests it names: test_sso_{foundations,render,verbs} do a
  # bare `from fakes import …` and rely on the runner for the path, so a direct
  # `python3 -m unittest` could not import them at all — and the resulting
  # ModuleNotFoundError is a non-zero exit, which this file read as "the
  # mutation went red". Every row pointing into those three modules was a
  # vacuous proof that would have passed against a no-op mutation.
  if (cd "$SCRATCH" && PYTHONPATH="$SCRATCH/tests/unit:$SCRATCH/src" \
      python3 -m unittest "$test_id" >/dev/null 2>&1); then
    printf '  FAIL %s (test stayed GREEN on the re-introduced bug — no teeth)\n' "$name"
    fail=$((fail+1)); return
  fi
  printf '  ok   %s (mutation went red, as it must)\n' "$name"
  pass=$((pass+1))
}

# prove <bug-name> <test-id> <sed-expr> <file>
prove() {
  local name=$1 test_id=$2 sed_expr=$3 file=$4
  # units/ is re-copied too, though this mutation only touches src/: prove_unit
  # leaves a MUTATED units/ behind, and every prove row that ran after one was
  # executing against it. No current row reads units/, so nothing was wrong —
  # but a proof going red for the wrong reason is exactly what this file exists
  # to make impossible.
  rm -rf "$SCRATCH/src" "$SCRATCH/units"
  cp -r "$REPO/units" "$SCRATCH/units"
  cp -r "$REPO/src" "$SCRATCH/src"
  sed -i "$sed_expr" "$SCRATCH/src/vide/$file"
  if cmp -s "$SCRATCH/src/vide/$file" "$REPO/src/vide/$file"; then
    printf '  FAIL %s (the mutation did not apply — sed expression rotted)\n' "$name"
    fail=$((fail+1)); return
  fi
  # Run the one named test against the MUTATED package.
  red_or_fail "$name" "$test_id"
}

rm -rf "$SCRATCH/tests"; cp -r "$REPO/tests" "$SCRATCH/tests"

echo "mutation teeth-proofs (each historical bug re-introduced on a scratch copy)"

prove "pnpm \$0-shim: wrapper loses the absolute anchor" \
  "tests.unit.test_node.TestPnpmLauncher" \
  's|exec "{abs_pnpm}" "\$@"|exec pnpm "$@"|' \
  "node.py"

prove "empty-200 body trusted as success" \
  "tests.unit.test_net.TestDownloadClassifier.test_empty_200_body_is_transient_and_never_success" \
  's|if tmp.stat().st_size == 0:|if False:|' \
  "net.py"

prove "libatomic probe dropped" \
  "tests.unit.test_misc.TestEnsurePrereqs.test_missing_libatomic_adds_the_package" \
  's|if not system.ldconfig_has("libatomic.so.1"):|if False:|' \
  "install_flow.py"

# BRE note: `(\.+)` = literal '(', literal '.', literal '+', literal ')' —
# exactly the `(.+)` in the source regex; the replacement relaxes it to `(.*)`.
prove "template unit counted as an instance" \
  "tests.unit.test_registry.TestListInstances" \
  's|(\.+)|(.*)|' \
  "registry.py"

prove "/dev/tty guard weakened to a stat-style always-true probe" \
  "tests.unit.test_users_confirm.TestConfirmer.test_no_controlling_tty_fails_closed_with_usage_64" \
  's|w, r = self._open()|w, r = __import__("io").StringIO(), __import__("io").StringIO("n")|' \
  "confirm.py"

prove "pnpm profile loses the PATH wiring" \
  "tests.unit.test_node.TestPnpmProfile" \
  's|PATH="\$PNPM_HOME/{binsub}:\${{PATH:-}}"; export PATH|:|' \
  "node.py"

prove "tty gate collapsed to always-wizard" \
  "tests.unit.test_tui_gate.TestGateMatrix" \
  's|return stdin_tty and stdout_tty and not no_gui|return True|' \
  "tui/__init__.py"

prove "wizard password ask-point silently dropped" \
  "tests.unit.test_flow_prompter.TestSecretDelivery.test_scripted_password_reaches_ensure_config_and_is_never_echoed" \
  's|password = pr.password_choice(target) if mint_password else None|password = None|' \
  "install_flow.py"

prove "secret routed onto the notes/pane channel" \
  "tests.unit.test_tui_session.TestSessionTeardown.test_deliver_secret_goes_to_the_deferred_list_never_the_pane" \
  's|self.s.defer_secret(line)|self.s.defer_note(line)|' \
  "tui/screens.py"

# Range-addressed: only _draw_chrome's pump (the first statement before the
# assert) — the pumps in log_view/modal_input must survive the mutation.
prove "pane pump dropped from the repaint path" \
  "tests.unit.test_tui_session.TestChromePump" \
  '/def _draw_chrome/,/assert self.scr/s|self._pump()|pass|' \
  "tui/session.py"

# The smoke §1 apt hang: stdin inheritance restored → the child holds the
# operator's tty again (fd0 probe asserts the exact string /dev/null).
prove "ticking child inherits the tty stdin (SIGTTOU hang)" \
  "tests.unit.test_misc.TestTickingSpawn.test_ticking_child_without_input_gets_devnull_stdin_and_detaches" \
  's|else subprocess.DEVNULL|else None|' \
  "executor.py"

# The smoke §1 visudo death: probe collapsed to always-present → the vide
# branch stops installing the sudo package on minimal images.
prove "sudo package assumed present (vide branch dies at visudo)" \
  "tests.unit.test_misc.TestEnsureSudo.test_missing_sudo_adds_the_package" \
  's|if system.have_cmd("sudo") and system.visudo_cmd():|if True:|' \
  "install_flow.py"

# The smoke §5 stale twin: the ENTRY reset removed (range-addressed — the
# window closes at `sel = menu`, so the reset in acknowledge_exposure and
# any post-selection copy survive the mutation).
prove "declined reinstall's destroy twin survives a quit (stale resume note)" \
  "tests.unit.test_tui_session.TestExistingInstanceTwin" \
  '/def existing_instance_action/,/sel = menu/s|self._reinstall_user = ""|pass|' \
  "tui/screens.py"

# --- SSO slice teeth (T1-T6) ------------------------------------------------

# T1: an empty whitelist rendering a bare allowed_emails= is FAIL-OPEN upstream
# (an empty set allows every authenticated user) — the deny sentinel is the fix.
prove "empty whitelist renders bare allowed_emails= (fail-open)" \
  "tests.unit.test_sso_render.TestCaddyBody.test_empty_set_is_deny_sentinel_never_bare" \
  's|return contract.SSO_DENY_SENTINEL|return ""|' \
  "caddy.py"

# T2: revoke that stops re-rendering the union authn file — revocation
# immediacy dies silently (the stale union keeps authenticating the removed
# email). Range-addressed to the revoke() body so allow()'s render survives.
prove "revoke stops re-rendering the union authn file" \
  "tests.unit.test_sso_verbs.TestAllowRevoke.test_revoke_removes_and_reloads" \
  '/def revoke/,/def would_empty/s|_render_all(cfg, ex)|pass|' \
  "sso.py"

# T3: the graceful caddy reload dropped from allow/revoke — a cross-instance
# revocation then silently lags human action (fail-open, the exact direction
# the per-instance model exists to close).
prove "caddy reload dropped from allow/revoke" \
  "tests.unit.test_sso_verbs.TestAllowRevoke.test_allow_adds_renders_and_reloads_caddy" \
  's|        reload_caddy(ex, rep)|        pass|' \
  "sso.py"

# T4: trusted_proxy_ips dropped from the rendered config — unset trusts
# 0.0.0.0/0 for back-compat, re-opening the X-Forwarded-Uri spoofing surface
# (CVE-2026-40575) the floor bump was raised to close.
prove "trusted_proxy_ips dropped from the proxy config" \
  "tests.unit.test_sso_render.TestProxyTomlShape.test_presence_pins" \
  's|trusted_proxy_ips = \["127.0.0.1/32"\]|# dropped|' \
  "oauth2proxy.py"

# T5: the socket perm-pairing dropped — a world-writable (0666) socket that
# still answers HTTP would read as HEALTHY, since root's probe bypasses 0660.
# The perms ARE the passwordless authz policy.
prove "socket health drops the perm pairing (0666 reads healthy)" \
  "tests.unit.test_sso_foundations.TestSocketPermGate.test_wrong_mode_socket_is_unhealthy_even_if_it_answers" \
  's|if st is None or not st.is_socket or st.mode != 0o660:|if st is None:|' \
  "registry.py"

# T6: cookie_refresh sneaking into the render — with session_cookie_minimal it
# is a startup crash-loop (the proxy rejects the combo), i.e. a fleet-wide
# outage; the absence pin is the cheapest possible insurance.
prove "cookie_refresh added to the render (crash-loop with minimal cookie)" \
  "tests.unit.test_sso_render.TestProxyTomlShape.test_forbidden_keys_never_rendered_as_keys" \
  's|cookie_expire = "720h"|cookie_expire = "720h"\ncookie_refresh = "1h"|' \
  "oauth2proxy.py"

# --- preflight required inputs teeth (the smoke §3 finding + D2/D4) ----------

# T7: credentials_needed collapsed back to the fail-open three-file provisioned()
# — a torn proxy.env with an empty client secret then reads as 'done', so the
# install silently inherits a proxy that can never authenticate (the D2 hole).
prove "credentials_needed keyed on bare provisioned() (silent torn-proxy inherit)" \
  "tests.unit.test_sso_foundations.TestBootstrapNeeded.test_torn_env_empty_secret_reads_provisioned_but_needs_bootstrap" \
  's|return not (provisioned(cfg) and credentials_recorded(cfg))|return not provisioned(cfg)|' \
  "oauth2proxy.py"

# T8: the cookie secret regenerated on every (re-)affirm instead of preserved —
# a converge that had to re-affirm a torn proxy would sign out the entire fleet
# (the D4/H1 hazard). The pin: an existing cookie secret survives record_credentials.
prove "record_credentials re-mints the cookie secret (fleet sign-out on converge)" \
  "tests.unit.test_sso_verbs.TestEnsureProxyPreservesCookieSecret.test_recorded_cookie_secret_survives_reaffirm" \
  's|recorded.get("OAUTH2_PROXY_COOKIE_SECRET")|""|' \
  "oauth2proxy.py"

# T9: the fqdn shape-check dropped from resolve — an upper-case fqdn then passes
# presence + the (valid, derived) parent checks and mutates the host before dying
# in the renderer, permanently pinning the poisoned parent domain (D3).
prove "fqdn shape-check dropped from resolve (upper-case fqdn poisons fleet.env)" \
  "tests.unit.test_no_mutation_before_ask.TestNoMutationBeforeRequiredInputs.test_malformed_fqdn_mutates_nothing" \
  's|    oauth2proxy.check_dns_name(fqdn, "fqdn")|    pass|' \
  "install_flow.py"

# T10: the tombstone reload made fail-HARD again — on the box a failed install
# leaves (Caddy absent), destroy re-raises before stop/disable/rm, so the one
# cleanup verb is unusable exactly when it is needed (D6).
prove "tombstone reload fail-hard (destroy aborts before teardown)" \
  "tests.unit.test_sso_verbs.TestDestroyFailSoftReload.test_tombstone_drops_allowlist_even_when_reload_fails" \
  's|reload_caddy(ex, rep, fail_soft=True)|reload_caddy(ex, rep)|' \
  "sso.py"

# T11: the union seed reverted to the VERBATIM historical bug — the
# exists()-GUARDED blind empty write outside the lock. Its race outcome (a
# concurrent `vide allow` populating the union between the exists() check and
# the write) is a truncated union, i.e. fail-closed fleet-wide 401s. The
# deterministic pin is the union-MISSING state at the converge_proxy boundary:
# the guarded mutant writes "" there instead of deriving from the allow-lists.
prove "union seed reverted to the exists()-guarded blind write (historical)" \
  "tests.unit.test_sso_verbs.TestUnionSeed.test_converge_seeds_missing_union_from_allowlists" \
  's|vide_sso.seed_union(cfg, ex)|(lambda p: p.exists() or p.write_text(""))(__import__("pathlib").Path(cfg.sso_dir, "authenticated-emails"))|' \
  "oauth2proxy.py"

# T12: the parent-domain guard dropped from the body render — a lost/blank
# fleet.env (the restored-from-backup box) then writes `redir * https://auth.//
# oauth2/start...` into every body and reloads caddy with no error anyone sees.
prove "parent-domain guard dropped (lost fleet.env renders auth.// silently)" \
  "tests.unit.test_sso_verbs.TestParentDomainGuard.test_allow_refuses_when_parent_domain_lost" \
  's|        _require_parent(cfg, parent)|        pass|' \
  "sso.py"

# --- post-restore audit mediums (T13-T17) -------------------------------------

# T13: download reverted to writing dest DIRECTLY — a connection reset mid-body
# then leaves a truncated file at the destination, which a later run (or an
# operator) mistakes for the real artifact.
prove "download writes dest directly (mid-body reset leaves a partial file)" \
  "tests.unit.test_net.TestDownloadAtomicity.test_midbody_failure_leaves_nothing_at_dest" \
  's|with open(tmp, "wb") as out:|with open(dest, "wb") as out:|' \
  "net.py"

# T14: the EPIPE guard dropped from the ticking stdin feed — a child that exits
# without draining its one-liner turns into an unhandled BrokenPipeError that
# upstages the child's own exit code.
prove "ticking stdin feed loses the EPIPE guard (BrokenPipeError escapes)" \
  "tests.unit.test_misc.TestTickingSpawn.test_child_exiting_without_draining_stdin_is_not_a_crash" \
  's|except BrokenPipeError:|except InterruptedError:|' \
  "executor.py"

# T15: the ROOT ceremony back to rejecting CRLF — a correctly typed ROOT over
# an SSH client in CRLF discipline reads "ROOT\r" and refuses a deliberate yes.
prove "ROOT ceremony rejects a CRLF-terminated answer" \
  "tests.unit.test_users_confirm.TestConfirmer.test_root_challenge_accepts_a_crlf_terminated_root" \
  's|rstrip("\\r\\n")|rstrip("\\n")|' \
  "confirm.py"

# T16: the twin loses its quoting — a recorded value carrying a space or shell
# metacharacter is re-parsed (or executed) by the shell the operator pastes into.
prove "equivalent-command twin renders values unquoted" \
  "tests.unit.test_tui_session.TestTwinQuoting.test_metacharacter_values_render_as_single_arguments" \
  's|shlex.quote(v)|v|' \
  "tui/screens.py"

# T16b/T16c: the resume note drops a client id the wizard already trusted.
# FOUND BY WALKING THE MANUAL GATE, 2026-08-08 (tests/manual/sso-smoke.md), and
# the kind no hermetic tier reaches, because it needs a human to press Ctrl-C in
# the one place a human actually presses it. Both flags used to be recorded AFTER
# the secret was accepted, so aborting on the secret field returned a resume
# command carrying neither, and the operator re-typed a client id VIDE had
# validated and stored for prefill one line earlier. Moving them ahead of the
# secret prompt is the fix; these two rows are what stop it moving back.
prove "the resume note forgets a ratified client id" \
  "tests.unit.test_sso_wizard.TestSsoScreens.test_an_abort_on_the_secret_field_keeps_the_client_id" \
  's|            self._flags\["--sso-client-id"\] = cid|            pass|' \
  "tui/screens.py"
# …and the flag that makes the note RUNNABLE. Without it the pasted command dies
# at "missing required value: pass --sso-secrets-stdin", so a note carrying the
# client id alone is a note that still cannot be pasted. Addressed by position —
# the line after the cid assignment — because the same statement appears verbatim
# in the dry-run branch above and a bare substitution would hit the wrong one.
prove "the resume note omits the stdin flag it needs to run" \
  "tests.unit.test_sso_wizard.TestSsoScreens.test_an_abort_on_the_secret_field_keeps_the_client_id" \
  '/self\._flags\["--sso-client-id"\] = cid/{n;s|.*|            pass|}' \
  "tui/screens.py"

# T16d/T16e: the two message defects the manual walk turned up on 2026-08-08,
# both on the path the product itself prints and invites you to paste. Neither
# was reachable by any automated tier: the first is invisible through a pipe,
# and the second is a sentence no tier reads.
prove "the stdin hint stops short of saying how to end it" \
  "tests.unit.test_sso_wizard.TestSsoScreens.test_the_password_twin_also_says_how_to_end_stdin" \
  's|, then Ctrl-D"|"|' \
  "tui/screens.py"
prove "a --no-gui refusal blames the terminal again" \
  "tests.unit.test_sso_wizard.TestSsoScreens.test_a_no_gui_refusal_does_not_blame_a_missing_terminal" \
  's|(this run does |(running without a terminal, so there is nobody to ask) (this run does |' \
  "prompter.py"
# T16f: and the pointer in the block the operator actually pastes. It sent them
# to <sso_dir>/caddy/auth.caddy for the shared block — true while that file WAS
# the block, false since it became the imported body. Following it yields a
# config Caddy rejects: the very failure the import change was meant to end,
# surviving in the sentence describing it.
#
# The first mutation written for this row changed "must exist in" to "must exist
# — see" and the harness reported NO TEETH: it reworded the sentence without
# touching either thing the test reads. Kept as a note because the harness
# caught the mutation rather than the product, which is what it is for — a row
# whose mutation cannot reach its own assertion proves nothing and looks green.
prove "the instance block points at the body for the block again" \
  "tests.unit.test_sso_render.TestCaddyBody.test_the_sso_shell_does_not_point_at_the_body_for_the_block" \
  's|It is NOT {sso_dir}/caddy/auth.caddy:|see {sso_dir}/caddy/auth.caddy|' \
  "caddy.py"

# T16g-T16i: the filled mark. The V is a HOLE subtracted from the shield, and
# three separate things have to hold for that: the fill rule, the two subpaths
# living in ONE `d`, and the favicon staying derived rather than re-typed. Lose
# any one and the mark still renders — right silhouette, right teal, no letter —
# which is the failure mode worth three rows rather than one.
prove "the fill rule stops subtracting the V" \
  "tests.unit.test_branding.TestTheMarkHasOneSource.test_the_v_is_a_hole_and_not_a_second_shape" \
  's|MARK_FILL_RULE = "evenodd"|MARK_FILL_RULE = "nonzero"|' \
  "contract.py"
# Splitting the subpaths is the same defect wearing a tidier shape: two <path>
# elements, evenodd with nothing to subtract, a solid shield.
prove "the shield and the V become two paths" \
  "tests.unit.test_branding.TestTheMarkHasOneSource.test_the_v_is_a_hole_and_not_a_second_shape" \
  's|    "M32 0 L60.4 11.4 V34.1 C60.4 51.2 46.2 59.7 32 64 "|    "M32 0 L60.4 11.4 V34.1 C60.4 51.2 46.2 59.7 32 64",|' \
  "contract.py"
# And the encoding that keeps the favicon inside its Caddy token. safe="" is why
# no angle bracket, quote or brace survives; widen it and the data URI can close
# the href it sits in.
# T16j: the art shrinks back inside its own box. This one was found by eye, not
# by any tier — every rendering was byte-correct and the geometry was simply
# small: 62% x 70% of the viewBox, so a 16px favicon drew a 10 x 11 mark.
prove "the mark stops reaching the edges of its viewBox" \
  "tests.unit.test_branding.TestTheMarkHasOneSource.test_the_art_fills_the_viewbox_on_its_long_axis" \
  's|"M32 0 L60.4 11.4|"M32 4 L60.4 11.4|' \
  "contract.py"
prove "the favicon payload keeps characters that can escape it" \
  "tests.unit.test_branding.TestTheMarkHasOneSource.test_the_favicon_payload_cannot_escape_its_caddy_token" \
  's|_quote(standalone_mark_svg().strip(), safe="")|_quote(standalone_mark_svg().strip(), safe="<>")|' \
  "contract.py"

# T17: the failure-path rm dropped from rotate-sso — the .prev (old cookie
# secret + LIVE client secret) then outlives the failed rotation on disk.
# Range-addressed to the failure branch; the success-path rm survives.
prove "failed rotate-sso leaves the .prev secret material on disk" \
  "tests.unit.test_sso_verbs.TestRotatePrevHygiene.test_failed_rotation_restores_and_removes_the_prev" \
  '/# Restored/,/raise StateError/s|ex.run(\["rm", "-f", str(prev)\])|pass|' \
  "oauth2proxy.py"

# T18: the replay bound frozen at the last-FOLDED offset instead of the file's
# real size — the stale-snapshot bug class: a straggler child's bytes appended
# during the final fold vanish from the replay under the "nothing was lost"
# banner.
prove "replay bound frozen at the pre-fold offset (straggler bytes dropped)" \
  "tests.unit.test_tui_session.TestStdioCapture.test_straggler_bytes_arriving_during_the_final_fold_are_replayed" \
  's|                off = 0|                off = 0; size = min(size, self._read_off)|' \
  "tui/session.py"

# T19: the ROOT-waiver exclusion dropped from the .env injection — a persisted
# `.env: VIDE_CONFIRM_ROOT=ROOT` row then waives the typed-ROOT ceremony for
# every future run on the box (the process-env-only invariant, fail-open).
prove ".env injection carries the ROOT waiver (persisted ceremony bypass)" \
  "tests.unit.test_config.TestDotenvInjection.test_the_root_waiver_is_never_injected" \
  's|if k == "VIDE_CONFIRM_ROOT":|if False:|' \
  "config.py"

# T24: the authz body loses its `route` wrapper. Caddy then sorts by its own
# global directive order, which puts `handle` AHEAD of forward_auth — so /vide
# renders an identity, read off an unverified header, for anyone who asks. The
# most expensive possible one-word regression.
prove "authz body loses its route wrapper (/vide answers before auth)" \
  "tests.unit.test_sso_render.TestVidePage.test_auth_runs_before_the_page_can_render" \
  's|    return f"""route {{|    return f"""dummy_wrapper {{|' \
  "caddy.py"

# T25: the markup guard dropped from normalize_email — an allow-listed address
# carrying a tag is then reflected verbatim into the /vide page's HTML, in the
# instance's own origin, at another allow-listed user.
prove "normalize_email stops refusing markup (reflected into /vide)" \
  "tests.unit.test_sso_verbs.TestNormalize.test_refuses_markup_so_the_vide_page_can_reflect_it" \
  's|    bad = set(e) & set("<>\\"'"'"'`&{}\\\\")|    bad = set()|' \
  "sso.py"

# --- shipped-unit teeth (T20-T21) -------------------------------------------
# The pins above all mutate src/. These two mutate a SHIPPED SYSTEMD UNIT, which
# the tests read from REPO/units — so the scratch tree needs that directory too.
prove_unit() { # <bug-name> <test-id> <sed-expr> <unit-file>
  local name=$1 test_id=$2 sed_expr=$3 file=$4
  rm -rf "$SCRATCH/src" "$SCRATCH/units"
  cp -r "$REPO/src" "$SCRATCH/src"
  cp -r "$REPO/units" "$SCRATCH/units"
  sed -i "$sed_expr" "$SCRATCH/units/$file"
  if cmp -s "$SCRATCH/units/$file" "$REPO/units/$file"; then
    printf '  FAIL %s (the mutation did not apply — sed expression rotted)\n' "$name"
    fail=$((fail+1)); return
  fi
  red_or_fail "$name" "$test_id"
}

# T20: the network ordering dropped again — the 2026-07-27 reboot finding. The
# proxy resolves its OIDC issuer at STARTUP, so starting before the network is
# usable is a coin flip it lost by 122ms of luck on the observed boot.
prove_unit "proxy unit loses its network-online ordering" \
  "tests.unit.test_sso_units.TestProxyUnitLiterals.test_survives_a_boot_where_the_issuer_is_slow" \
  '/^After=network-online.target$/d' \
  "oauth2-proxy.service"

# T21: the start limiter comes BACK to the proxy service. This reads like
# restoring a sensible guard and is the single most dangerous edit in the tree:
# systemd propagates a service's start_limit_hit to the socket unit that triggers
# it, a failed socket unit calls socket_close_fds(), and the fleet's
# authorization port is free — for good, since a socket unit has no Restart=.
# The old numbers reached that in ~100s on an ordinary slow-resolver boot.
prove_unit "the proxy service gets its start limiter back" \
  "tests.unit.test_sso_units.TestProxyUnitLiterals.test_survives_a_boot_where_the_issuer_is_slow" \
  's|^StartLimitIntervalSec=0$|StartLimitIntervalSec=300\nStartLimitBurst=20|' \
  "oauth2-proxy.service"

# T21b: …and the half that looks like pure tidying. Restart=on-failure leaves a
# clean exit(0) as a resting state, and this process is the fleet's sole gate —
# a compromised one chooses its own exit code.
prove_unit "the gate may exit cleanly and stay gone" \
  "tests.unit.test_sso_units.TestProxyUnitLiterals.test_survives_a_boot_where_the_issuer_is_slow" \
  's|^Restart=always$|Restart=on-failure|' \
  "oauth2-proxy.service"

# --- rotate-sso recovery teeth (T22-T23) -------------------------------------
# Both come from the 2026-07-27 manual-gate walk: rotate-sso works, but the operator's
# own way back out of it dead-ends. Neither hermetic tier caught it, because
# both retry with a FRESH cookie jar and a human retries in the same browser.

# T22: the auth host's root handler stops matching the root — back to letting
# oauth2-proxy 404 it. That 404 is what a SUCCESSFUL post-rotation re-login
# lands on, so the operator reads a working fleet as a broken one.
prove "auth root handler no longer matches / (post-rotation login 404s)" \
  "tests.unit.test_sso_render.TestAuthBlockRoot.test_the_root_is_answered_not_left_to_the_proxy" \
  's|handle / {{|handle /nowhere {{|' \
  "caddy.py"

# T23: the retry warning demoted to debug (invisible by default) — the operator
# meets upstream's "potential attack" 403 with no warning, on the one verb they
# reach for when they believe they ARE under attack.
prove "rotate-sso stops warning about its own first-attempt 403" \
  "tests.unit.test_sso_verbs.TestRotateWarnsAboutItsOwnRecovery.test_it_names_the_403_before_the_operator_meets_it" \
  's|rep.warn(contract.MSG_ROTATE_RETRY.format(|rep.debug(contract.MSG_ROTATE_RETRY.format(|' \
  "oauth2proxy.py"

# --- launcher flag teeth (T24-T26) -------------------------------------------
# The launcher is the one file where a flag can be added to ONE binding and
# silently missed on the other: SSO instances take the socket branch, password
# instances the port branch, and no operator exercises both.

# T24: the shared array stops reaching the port binding. A password instance
# then quietly loses the flags an SSO instance has — the exact drift the array
# exists to prevent, and invisible until someone runs the other mode.
prove_unit "launcher flags reach the socket binding but not the port one" \
  "tests.unit.test_sso_units.TestUnitLauncherLiterals.test_common_args_reach_both_bindings" \
  's|^  --bind-addr "127.0.0.1:${VIDE_PORT}" \\$|  --bind-addr "127.0.0.1:${VIDE_PORT}" \\\n  --nothing-here \\|; s|^  "${common_args\[@\]}" \\$||' \
  "code-server-launch"

# T25: Workspace Trust hardens back to upstream's default. Not a security
# regression — the opposite — but it silently reverses what the operator asked
# for, and a default that flips itself back is exactly what a pin is for.
prove_unit "workspace trust quietly returns to upstream's default" \
  "tests.unit.test_sso_units.TestUnitLauncherLiterals.test_workspace_trust_defaults_off_but_is_recoverable" \
  's|^  common_args+=(--disable-workspace-trust)$|  :|' \
  "code-server-launch"

# T26: the knob is removed and the flag applied unconditionally. This is the
# dangerous direction: a deliberate weakening of a security control with no way
# back short of editing VIDE itself.
prove_unit "the workspace-trust knob is dropped and the weakening made permanent" \
  "tests.unit.test_sso_units.TestUnitLauncherLiterals.test_workspace_trust_defaults_off_but_is_recoverable" \
  's|^if \[\[ "${VIDE_WORKSPACE_TRUST:-0}" != "1" \]\]; then$|if true; then|' \
  "code-server-launch"

# --- branding teeth (T27-T30) ------------------------------------------------
# Branding's expected failure mode is a SILENT no-op — it warns and continues by
# design — so nothing on a live box would ever tell you it stopped working.
# These are the only alarm.

# T27: branding detaches from the install/upgrade choke point. A fresh install
# still looks right, and the next `vide upgrade` lays down a clean tree that
# quietly loses the favicon and the font. The worst kind: correct until you
# update.
prove "branding stops re-applying on upgrade" \
  "tests.unit.test_steps.TestBrandingHangsOffTheChokePoint.test_an_upgrade_re_brands" \
  's|^    branding.apply(ex, rep, user)$|    pass|' \
  "codeserver.py"

# T28: the @font-face URL hardcodes the root instead of workbench.html's {{BASE}}
# placeholder. Works on a code-server at /, 404s on every face for one served
# under a sub-path — and a 404 font just silently falls back.
prove "webfont URLs hardcode / instead of the workbench base" \
  "tests.unit.test_branding.TestFontFaceCss.test_urls_go_through_the_workbench_base_placeholder" \
  's|{{{{BASE}}}}/_static|/_static|' \
  "branding.py"

# T29: the seed-if-absent guard drops and settings.json is converged. VIDE then
# silently reverts the operator's own editor settings on every install — the
# defect class the config.yaml never-regenerate guard exists to prevent.
prove "user settings converge instead of seeding once" \
  "tests.unit.test_branding.TestSeedUserSettings.test_an_existing_settings_file_is_left_alone" \
  's|^    if system.probe_as(user, \["test", "-e", str(dest)\]):$|    if False:|' \
  "branding.py"

# T30: a font pin degrades to a placeholder. Without this row the pin-integrity
# check is itself unproven — and an unpinned third-party binary is the one
# supply-chain hole this design was built to avoid.
prove "a font sha256 pin degrades to a placeholder" \
  "tests.unit.test_branding.TestFontPins.test_every_face_carries_a_real_sha256" \
  's|"a9cb1cd82332b23a47e3a1239d25d13c86d16c4220695e34b243effa999f45f2"|"TODO-real-hash-here"|' \
  "branding.py"

# T31: ligatures fall back to VS Code's default. Not a crash, not a warning —
# the font simply renders with its headline feature switched off, and it reads
# as a bad font rather than a missing setting. The build ships
# OFF = '"liga" off, "calt" off', and JetBrains Mono's ligatures are ALL in
# `calt` (its `liga` is empty), so the default is not neutral here: it actively
# disables them.
prove "editor ligatures fall back to the default that disables calt" \
  "tests.unit.test_branding.TestLigaturesAreOn.test_editor_and_terminal_both_enable_ligatures" \
  's|^    "editor.fontLigatures": True,$|    "editor.fontLigatures": False,|' \
  "branding.py"

# T32: the auth root's fallback matcher narrows back to 401 alone. Nothing
# crashes and no page changes — but forward_auth's default for an unhandled
# non-2xx is to copy the PROXY's response to the client, so a 403 (valid fleet
# cookie, address since revoked) puts oauth2-proxy's own error page on the most
# public URL VIDE owns. The failure is invisible to every render assertion,
# because the rendered pages are still correct; only the matcher moved.
prove "the auth root stops catching every non-2xx and leaks the proxy's page" \
  "tests.unit.test_sso_render.TestAuthBlockRoot.test_every_non_success_falls_back_to_the_anonymous_answer" \
  's|@anon status 1xx 3xx 4xx 5xx|@anon status 401|' \
  "caddy.py"

# T33: the inbound-header strip is dropped from the auth root. copy_headers
# overwrites X-Auth-Request-Email from the auth RESPONSE — but only if the proxy
# actually sets it. Without the strip, a 202 that sets no header leaves the
# CLIENT's own header standing, and the page names whoever asked to be named.
# This is the one mutation that turns an identity page into an identity oracle.
prove "the auth root reflects a client-supplied identity header" \
  "tests.unit.test_sso_render.TestAuthBlockRoot.test_the_named_answer_is_unreachable_without_a_202" \
  's|^            request_header -X-Auth-Request-Email$|            header_up X-Noop 1|' \
  "caddy.py"

# T34: the same strip dropped from the INSTANCE body. /vide is the older of the
# two identity pages and shipped without this guard; T33 covers the auth root,
# and without this row the instance page could silently lose it again.
prove "the /vide page reflects a client-supplied identity header" \
  "tests.unit.test_sso_render.TestVidePage.test_auth_runs_before_the_page_can_render" \
  's|^    request_header -X-Auth-Request-Email$|    header_up X-Noop 1|' \
  "caddy.py"

# T35: the auth-block drift check goes permanently quiet. The nastiest shape of
# failure in this file — a check that reports nothing looks exactly like a system
# with nothing wrong. The real divergence it exists for went unnoticed for two
# days precisely because nothing spoke.
prove "the auth-block drift check can never report drift" \
  "tests.unit.test_sso_foundations.TestAuthBlockDrift.test_a_stale_copy_is_named_with_its_path" \
  's|    if on_disk.strip() == want.strip():|    if True:|' \
  "oauth2proxy.py"

# T36: the OFL licence stops being placed beside the faces. Nothing breaks and
# nothing warns — the font renders exactly as before, so no test on the box and
# no reading of a running instance would ever surface it. Only the licence
# obligation is gone, which is the kind of defect that is discovered by someone
# else, later, and in public.
prove "the font licence stops being placed beside the faces" \
  "tests.unit.test_branding.TestTheLicenceTravelsWithTheFont.test_the_licence_is_placed_beside_the_faces" \
  's|^        ex.run_as(user, \["install", "-m", "0644", str(licence),$|        ex.run(["true", str(licence),|' \
  "branding.py"

# T37: the checkout gate collapses to always-pass. A gate that never refuses is
# indistinguishable from no gate at all on every box where the checkout happens
# to be fine — which is every box the maintainer owns. The only way to notice is
# a test that asserts the refusal, so the refusal is what is mutated here.
prove "the checkout gate stops refusing a world-writable path" \
  "tests.unit.test_preflight.TestCheckoutGate.test_world_writable_is_refused_whatever_the_group_says" \
  's|if f.mode & 0o002:|if False:|' \
  "preflight.py"

# T38: the gate's group resolution is replaced by the naive `mode & 0o022`. This
# is the predicate the plan originally specified, and it is wrong in the one
# direction that gets a security control deleted rather than fixed: Debian and
# Ubuntu default to umask 002 AND user-private groups, so it refuses a plain
# `git clone` — the very clone the README's quick start runs — on a stock box.
prove "the checkout gate refuses ordinary user-private-group clones" \
  "tests.unit.test_preflight.TestCheckoutGate.test_a_user_private_group_is_NOT_refused" \
  's|            writers = group_writers(f.gid)|            writers = frozenset({-1})|' \
  "preflight.py"

# T39: the shared proxy's converge gated back behind the first install — the
# original defect. Every hardening directive in units/oauth2-proxy.service and
# every line of render_proxy_toml (trusted_proxy_ips included, the mitigation
# the CVE floor names) then describes new boxes only, and nothing anywhere
# reports it: proxy_health checks unit-active, /ping, the version and caddy's
# group, never the unit body or the config.
prove "the shared proxy converges only on the first install" \
  "tests.unit.test_no_mutation_before_ask.TestAuthzBeforeStart.test_allow_precedes_enable_start" \
  's|    block = oauth2proxy.converge_proxy(cfg, ex, rep, parent_domain=parent,|    block = "" if not plan.sso_bootstrap else oauth2proxy.converge_proxy(cfg, ex, rep, parent_domain=parent,|' \
  "install_flow.py"

# T40: the converge stops saying a restart is owed. It deliberately does NOT
# restart — installing user B must not be able to drop the auth gate for A, C
# and D — so the report is the entire mechanism by which the hardening ever
# reaches a running process. Silently dropping it turns "lands at the next
# upgrade-sso" into "never".
prove "a changed proxy unit/config no longer reports the pending restart" \
  "tests.unit.test_sso_verbs.TestConvergeIsUnconditional.test_a_changed_unit_or_toml_reports_a_pending_restart" \
  's|        rep.warn(contract.MSG_PROXY_RESTART_PENDING)|        pass|' \
  "oauth2proxy.py"

# T41: the caddy-admin probe reads /config/ instead of /reverse_proxy/upstreams.
# That endpoint returns the operator's ENTIRE running config — ACME references,
# DNS-provider tokens, basic_auth hashes — into VIDE's process. Detecting an
# exposure by committing a worse one is the failure this row pins.
prove "the caddy admin probe reads the operator's whole config" \
  "tests.unit.test_sso_verbs.TestCaddyAdminProbe.test_the_probe_never_reads_the_operators_running_config" \
  's|path="/reverse_proxy/upstreams"|path="/config/"|' \
  "oauth2proxy.py"

# T42-T44: branding's three path constants. Every other assertion in
# test_branding.py builds its expected path out of these same constants, so they
# were tautologies over the values that decide whether ANY of the work lands
# where code-server serves. And branding downgrades every failure to a warning,
# so a wrong value produces no red anywhere and no complaint on a live box —
# the module could be entirely non-functional today and nothing would say so.
prove "the media dir moves out of what code-server serves" \
  "tests.unit.test_branding.TestTheLicenceTravelsWithTheFont.test_the_paths_that_decide_whether_any_of_this_is_served" \
  's|^MEDIA = "src/browser/media"|MEDIA = "src/browser/media-x"|' \
  "branding.py"

prove "the favicon stops being written at all" \
  "tests.unit.test_branding.TestFaviconActuallyRuns.test_it_writes_both_faces_0644_into_the_served_media_dir" \
  's|^FAVICONS = ("favicon.svg", "favicon-dark-support.svg")|FAVICONS = ("favicon.svg",)|' \
  "branding.py"

prove "the workbench patch reads and writes the wrong document" \
  "tests.unit.test_branding.TestPatchWorkbench.test_it_reads_and_writes_the_upstream_entry_document" \
  's|^WORKBENCH = "lib/vscode/out/vs/code/browser/workbench/workbench.html"|WORKBENCH = "lib/vscode/out/vs/code/browser/workbench/workbench.htm"|' \
  "branding.py"

# T45: branding moved above the installer. code_server_root then resolves
# nothing on a fresh box, branding warns, and silently no-ops — while the three
# call-COUNT rows that pinned its placement all stay green.
prove "branding runs before the tree it patches exists" \
  "tests.unit.test_steps.TestBrandingHangsOffTheChokePoint.test_branding_runs_after_the_installer_not_before_it" \
  's|^    branding.apply(ex, rep, user)$|    pass|' \
  "codeserver.py"

# T46: the state home is not created by the first writer. This shipped: the
# split moved the proxy.env write ahead of the only ensure_dir calls, and the
# first SSO install died in mkstemp — behind 508 green rows, because the fake
# executor mkdir'd parents that the real one does not. Both fakes are honest now
# and this row is the pin.
prove "the first writer no longer creates /etc/vide/sso" \
  "tests.unit.test_sso_verbs.TestFirstInstallOnABareBox" \
  's|^    _ensure_state_home(cfg, ex)$||' \
  "oauth2proxy.py"

# T49: the identity step stops happening. This is T46's sibling and the SECOND
# crash on the same journey: the fix for T46's bug added a helper that asserted
# a directory owned by vide-proxy, and `install -d` resolves -o/-g during option
# parsing and exits 1 with `invalid group` before it creates anything — so a
# first SSO install on a bare box died again, one line later, behind 515 green
# rows. It was invisible because both doubles accepted any owner string and
# dropped it; they now resolve identities against a ledger the product's own
# groupadd/useradd mutate. Where T46 pins the instance, this pins the invariant:
# nothing may be owned by an identity nothing has created.
prove "the identity step stops running before anything is owned by it" \
  "tests.unit.test_sso_verbs.TestFirstInstallOnABareBox" \
  's|^    ensure_identities(ex, rep)$|    pass|' \
  "oauth2proxy.py"

# T53: the group-owned helper stops establishing the identity it NAMES, while
# converge_proxy's own call survives. T49 above proves the identity step matters
# at all; this proves the OTHER half of the fix — that the helper carries no
# invisible "somebody ran ensure_identities first" precondition, which is the
# thing that broke twice. It cannot be observed through converge_proxy, which
# calls ensure_identities itself, so the row names the test that calls the
# helper the way a future caller would.
prove "the caddy-dir helper stops creating the group it names" \
  "tests.unit.test_sso_verbs.TestFirstInstallOnABareBox.test_the_caddy_dir_helper_stands_alone_on_a_bare_box" \
  '/^def _ensure_caddy_dir/,/^    ex\.ensure_dir/s|^    ensure_identities(ex, rep)$|    pass|' \
  "oauth2proxy.py"

# T47: the fleet's issuer and port read live from config again. proxy.toml is
# re-rendered on EVERY converge now, and both values are .env-settable — so one
# row would repoint the whole fleet's root of trust at the next restart, and
# move the proxy off the port baked into the auth block the operator pasted.
prove "the fleet's issuer stops being pinned in fleet.env" \
  "tests.unit.test_sso_verbs.TestFleetPinsAreNotEnvLive.test_a_dot_env_row_cannot_repoint_a_provisioned_fleet" \
  's|fleet_pins(cfg).get("VIDE_SSO_ISSUER_URL")|""|' \
  "sso.py"

# T50: the PORT half of the same pin, which T47 never mutated — and it is the
# half with an attacker. The pin landed in proxy.toml alone while _render_all
# still read config live, so one .env row rewrote every instance's forward_auth
# body to a port the proxy is not listening on, and `vide allow`/`revoke` then
# reloaded Caddy on the spot. Any local account can bind a free loopback port
# and answer 202 for every instance on the box.
prove "the authz bodies read the proxy port live from config again" \
  "tests.unit.test_sso_verbs.TestTheFleetPortIsOneReader.test_every_renderer_names_the_pinned_port" \
  's|^        port = fleet_port(cfg)$|        port = cfg.sso_proxy_port|' \
  "sso.py"

# T51: the loopback carve-out disappears. https-only on the issuer is right for
# a value read back from a 0644 file; applied to config it refused the fake IdP
# the sso-mode, host-smoke and live-fleet tiers are built on — the three tiers
# that would have caught it were the three it broke, and every unit row stayed
# green. The guard reads the issuer literal out of the gate scripts themselves,
# so the product and the harness cannot drift apart in either direction.
prove "a product tightening silently invalidates the documented test seam" \
  "tests.unit.test_harness_guards.TestTheDocumentedTestSeamStillWorks.test_every_tier_issuer_is_accepted_by_the_renderer" \
  's|    if not (_HTTPS_URL.match(url) or _HTTP_LOOPBACK_URL.match(url)):|    if not _HTTPS_URL.match(url):|' \
  "oauth2proxy.py"

# T52: …and the carve-out widened into a hole, which fails in the opposite
# direction. A cleartext issuer that is NOT on loopback is a full authentication
# bypass: the fleet's root of trust fetched over a network anyone can answer.
prove "the loopback carve-out widens to any plaintext issuer" \
  "tests.unit.test_harness_guards.TestTheDocumentedTestSeamStillWorks.test_a_public_plaintext_issuer_is_still_refused" \
  's|_HTTP_LOOPBACK_URL.match(url)|url.startswith("http://")|' \
  "oauth2proxy.py"

# T48: INVERTED WITH ITS SUBJECT. It used to prove that a converge does NOT
# refresh the persisted auth block — refreshing it made _auth_block_drift compare
# equal forever and disabled a working control while leaving its code in place.
# That was correct while the file was the operator's pasted reference. It is
# VIDE's now, imported by the three lines they paste, so refusing to write it is
# the failure and the old row proved the wrong thing.
#
# What replaces it is the half that makes the write mean anything at all: Caddy
# holds its config in memory, so a re-rendered file it never re-reads is a silent
# no-op and the converge would report success over a login host still serving the
# old body. Drop the reload and the write becomes theatre.
prove "the re-rendered body is never re-read by Caddy" \
  "tests.unit.test_sso_verbs.TestConvergeRelandsTheAuthBody.test_a_changed_body_reloads_caddy_and_an_unchanged_one_does_not" \
  's|        _sso_for_port.reload_caddy(ex, rep, fail_soft=True)|        pass|' \
  "oauth2proxy.py"
# …and the other sign, because a reload on every converge bounces the fleet's
# front door on runs that changed nothing, which is how a safety measure becomes
# the thing operators disable.
prove "every converge bounces the operator's front door" \
  "tests.unit.test_sso_verbs.TestConvergeRelandsTheAuthBody.test_a_changed_body_reloads_caddy_and_an_unchanged_one_does_not" \
  's|    if changed and not ex.dry_run:|    if not ex.dry_run:|' \
  "oauth2proxy.py"

# T54: a renderer or probe goes back to reading the port live from config. One
# row rather than one per site, deliberately: the I10 census in test_invariants
# is DERIVED from the source, so it sees any new reader anywhere in src/vide.
# A row per site is a list a human maintains, and this class recurs precisely
# because such lists go stale — this proves the census itself can go red, which
# is what makes it evidence rather than decoration. The previous commit shipped
# a comment claiming this census existed before anyone had written it.
prove "a probe reads the proxy port live from config again" \
  "tests.unit.test_invariants.TestI10OneReaderForTheFleetPins.test_the_fleet_rows_are_read_in_one_place" \
  's|^    pin = vide_sso.fleet_port(cfg)$|    pin = cfg.sso_proxy_port|' \
  "oauth2proxy.py"

# T55: the same mutation, judged by CONSEQUENCE rather than by census. A census
# proves a rule was broken; this proves what breaking it costs. rotate_sso reads
# a failed probe as "the proxy rejected the new cookie secret" and restores the
# secret it was invoked to burn — so a port divergence here does not fail loudly,
# it silently disarms the stolen-cookie kill switch, which is the one lever that
# answers a leaked fleet-wide session cookie.
prove "the readiness probe stops naming the pinned port" \
  "tests.unit.test_sso_verbs.TestTheFleetPortIsOneReader.test_every_probe_answers_on_the_pinned_port" \
  's|    return system.healthz(gate_port(cfg) if port is None else port,|    return system.healthz(4180,|' \
  "oauth2proxy.py"

# T56: the census's own blind spot, stated as a row. I10 looks for reads of the
# cfg ATTRIBUTES, so a hardcoded literal is invisible to it — and a literal is
# exactly what a hurried edit reaches for when the pin is inconvenient. The two
# rows above and this one cover the three ways this can go wrong: the rule, the
# consequence, and the way around the rule.
prove "the authz bodies hardcode a port literal the census cannot see" \
  "tests.unit.test_sso_verbs.TestTheFleetPortIsOneReader.test_every_renderer_names_the_pinned_port" \
  's|^        port = fleet_port(cfg)$|        port = 4180|' \
  "sso.py"

# T57: the re-affirm restart stops being gated on the proxy having been LIVE.
# Then a first install restarts the proxy converge started one second earlier —
# a second bounce during OIDC discovery, immediately before proxy_ready begins
# timing it — and announces re-affirmed credentials on a box that never had any.
# Shipped once with no test at either arm, which is why both arms exist now.
prove "the re-affirm restart fires on a proxy that was never running" \
  "tests.unit.test_sso_verbs.TestTheReaffirmRestartIsGatedOnLiveness.test_a_dead_proxy_is_not_restarted_because_enable_now_already_read_it" \
  's|    if creds_changed and not ex.dry_run and was_active:|    if creds_changed and not ex.dry_run:|' \
  "install_flow.py"

# T58: …and the other arm. A gate that never fires is the same defect with the
# opposite sign: a corrected client secret written to proxy.env and never
# re-read has fixed nothing, and `--sso-reaffirm` exists for exactly the case
# nothing on this box can detect — a typo'd secret, which only Google sees.
prove "the re-affirm restart stops firing on a live fleet" \
  "tests.unit.test_sso_verbs.TestTheReaffirmRestartIsGatedOnLiveness.test_a_live_proxy_is_restarted_so_it_re_reads_the_secret" \
  's|    if creds_changed and not ex.dry_run and was_active:|    if False:|' \
  "install_flow.py"

# T59: the masked check narrows back to an exact compare. `systemctl mask
# --runtime` reports `masked-runtime`, so the exact form let a runtime-masked
# unit through to `enable --now`, which dies with a bare CommandFailed instead
# of naming the remedy — and atomic_write's os.replace would have replaced the
# /dev/null symlink itself on the way, silently unmasking what the operator
# switched off.
prove "a runtime-masked unit is no longer recognised as masked" \
  "tests.unit.test_sso_verbs.TestAMaskedUnitIsRefused.test_a_RUNTIME_masked_unit_is_refused_too" \
  's|    if system.unit_enable_state(UNIT).startswith("masked"):|    if system.unit_enable_state(UNIT) == "masked":|' \
  "oauth2proxy.py"

# T60: the host-read census stops being able to fail. It is the tripwire on the
# way this whole class recurs — a systemctl/getent READ in a domain module is a
# live-host dependency the unit tier cannot stub — and it shipped in the same
# commit as T54 with no proof it could go red, which is verbatim the defect T54
# was written to close for the sibling census.
prove "the host-read census cannot detect a new live-host read" \
  "tests.unit.test_invariants.TestI11HostStateIsReadInOnePlace.test_systemd_and_identity_reads_live_in_system_py" \
  's|    return system.healthz(gate_port(cfg) if port is None else port,|    system.query(["systemctl", "is-active", UNIT])\n    return system.healthz(gate_port(cfg) if port is None else port,|' \
  "oauth2proxy.py"

# T61: doctor probes one port and names another. It shipped exactly once, as the
# FIX for a review finding about a diagnostic reporting an untested number — the
# repair reproduced the defect it repaired, and did so with no row, which is how
# it reached a second review round.
prove "doctor names a port it did not probe" \
  "tests.unit.test_sso_verbs.TestTheFleetPortIsOneReader.test_doctor_probes_the_port_it_reports" \
  's|    answers = system.healthz(port, path="/ping")|    answers = system.healthz(4180, path="/ping")|' \
  "oauth2proxy.py"

# --- the socket-directory freeze (T62-T68) -----------------------------------
# The 2026-07-31 whole-tree block. /run/vide/%i is created for the INSTANCE USER
# (RuntimeDirectory + User=%i), so until root takes it away that user unlinks and
# renames entries in it freely — the launcher's own `rm -f` is the proof VIDE
# relies on exactly that. Caddy re-resolves `reverse_proxy unix/<socket>` on every
# connection, so a symlink planted at that name minutes after start points the
# operator's internet-facing Caddy at another instance's auth: none IDE, or at
# /run/caddy/admin.sock — the remedy docs/sso.md makes mandatory.
#
# Four of these rows name a BEHAVIOURAL test that runs the ExecStartPost payload
# under sh with the mutating commands shimmed; the rest name text pins, and that
# split is stated because it matters: a text pin over the whole unit FILE would be
# satisfied by the rationale comment this fix is required to carry, which is
# exactly the vacuity this file exists to refuse. The text pins here are all scoped
# to the ExecStartPost= line for that reason (test_sso_units._exec_start_post).

# T62: the freeze itself removed, relabel left in place. This is the block.
prove_unit "the socket directory is left in the instance user's hands" \
  "tests.unit.test_sso_units.TestTheFreezeScriptRunsAsWritten.test_a_real_socket_is_frozen_then_relabelled_in_that_order" \
  's@chown root:vide-proxy "\$\$D" || exit 1; @@' \
  "code-server@.service"

# T62b: the group grant put back BEFORE the wait — the tidier mechanism, where the
# socket inherits vide-proxy from a setgid directory at bind(2). It leaves the
# directory `2750 <user>:vide-proxy` for the whole start: Caddy can already walk
# it and the instance user still owns it, and she controls the ExecStart binary so
# she decides how long that lasts. One request through Caddy during it survives
# the refusal that follows, because Caddy pools per upstream address.
prove_unit "Caddy can traverse the directory while the instance user still owns it" \
  "tests.unit.test_sso_units.TestTheSocketDirectoryIsFrozen.test_caddy_is_granted_traversal_only_after_the_freeze" \
  's@n=0; while@chgrp vide-proxy "\$\$D" || exit 1; chmod 2750 "\$\$D" || exit 1; n=0; while@' \
  "code-server@.service"

# T63: fail-OPEN restored — the historical shape. The loop fell out with `sleep`
# as the last command and `sh` exited 0, so an instance too slow to bind started
# happily with its directory still writable by its user and NOTHING said so.
prove_unit "a socket that never appears starts the unit anyway (fail-open)" \
  "tests.unit.test_sso_units.TestTheFreezeScriptRunsAsWritten.test_a_socket_that_never_appears_fails_the_unit" \
  's@writable by %i" >&2; exit 1@writable by %i" >\&2; exit 0@' \
  "code-server@.service"

# T64: the budget narrowed back to the historical 6s, which was chosen when loop
# exhaustion cost nothing and is far under one cold code-server start.
prove_unit "socket-wait budget narrowed back to 6s" \
  "tests.unit.test_sso_units.TestTheSocketDirectoryIsFrozen.test_the_budget_is_bounded_by_both_ceilings" \
  's@"\$\$n" -lt 150@"\$\$n" -lt 20@' \
  "code-server@.service"

# T65: chmod before chown — the widened-mode window. The instance user owns the
# directory until the chown lands and may chmod it 0777 a millisecond earlier;
# chown does not narrow a mode, so this order leaves a root-owned world-writable
# directory and hands the swap to every local account instead of one.
prove_unit "the mode is asserted before the chown, not after (0777 window)" \
  "tests.unit.test_sso_units.TestTheSocketDirectoryIsFrozen.test_the_mode_is_narrowed_after_the_chown" \
  's@chown root:vide-proxy "\$\$D" || exit 1; chmod 2750 "\$\$D" || exit 1; if \[ ! -S@chmod 2750 "\$\$D" || exit 1; chown root:vide-proxy "\$\$D" || exit 1; if \[ ! -S@' \
  "code-server@.service"

# T66: the LINK-COUNT half dropped. `[ -S ] && [ ! -L ]` is TRUE of a HARD LINK,
# and renameat2(RENAME_EXCHANGE) installs one atomically — so type alone was never
# enough, and %h closes the family without depending on fs.protected_hardlinks, a
# sysctl VIDE does not set.
prove_unit "the socket check stops looking at the link count (hard links pass)" \
  "tests.unit.test_sso_units.TestTheFreezeScriptRunsAsWritten.test_a_hard_linked_socket_is_refused" \
  's@%%U %%h" "\$\${VIDE_SOCKET}")" != "%i 1"@%%U" "\$\${VIDE_SOCKET}")" != "%i"@' \
  "code-server@.service"

# T75: the OWNERSHIP half dropped — the other conjunct of the same test, and it
# needs its own row because a socket at the path that the expected user does not
# own is a different thing from one with two links.
prove_unit "the socket check stops looking at who owns the inode" \
  "tests.unit.test_sso_units.TestTheFreezeScriptRunsAsWritten.test_a_socket_owned_by_someone_else_is_refused" \
  's@%%U %%h" "\$\${VIDE_SOCKET}")" != "%i 1"@%%h" "\$\${VIDE_SOCKET}")" != "1"@' \
  "code-server@.service"

# T76: stat's translated %F put back into the comparison. It shipped that way for
# exactly one commit: on a box whose LANG is not C — which systemd exports into
# every service from /etc/default/locale — `stat -c %F` on a socket prints e.g.
# `Socket`, so the check refuses EVERY SSO start and the journal blames an attack
# that never happened. No tier would see it; they all run under C.
prove_unit "the socket check compares a gettext-translated field again" \
  "tests.unit.test_sso_units.TestTheSocketDirectoryIsFrozen.test_the_check_compares_no_gettext_translated_field" \
  's@stat -c "%%U %%h"@stat -c "%%F %%U %%h"@' \
  "code-server@.service"

# T77: the settle removed. code-server chmods its socket to --socket-mode AFTER
# bind, and once the directory is frozen it can no longer resolve its own socket
# path — freezing inside that window hands it EACCES on its own chmod.
prove_unit "the freeze lands in code-server's own post-bind chmod window" \
  "tests.unit.test_sso_units.TestTheFreezeScriptRunsAsWritten.test_a_real_socket_is_frozen_then_relabelled_in_that_order" \
  's@; sleep 0.3; chown root:vide-proxy@; chown root:vide-proxy@' \
  "code-server@.service"

# T78: the start-limit window narrowed back to the value that predates the freeze.
# 5 x (45 + 20 + 3) = 340 does not fit in 300, so the fifth start falls outside the
# window, the burst limit never applies, and a permanently stuck instance restarts
# forever instead of landing in 'failed' where `vide status` can surface it.
prove_unit "the start-limit window no longer fits five whole cycles" \
  "tests.unit.test_sso_units.TestTheSocketDirectoryIsFrozen.test_the_budget_is_bounded_by_both_ceilings" \
  's@^StartLimitIntervalSec=400$@StartLimitIntervalSec=300@' \
  "code-server@.service"

# T67: one more Exec* after the freeze. systemd re-runs its exec-directory setup
# before EVERY Exec* command and chowns RuntimeDirectory back to User= —
# recursively, socket included (systemd#12713) — so this silently undoes the whole
# control and fails GREEN. No systemd directive enforces the ordering; this row is
# the only thing between the control and a one-line deletion nobody would notice.
prove_unit "a second ExecStartPost is added after the freeze (systemd re-chowns)" \
  "tests.unit.test_sso_units.TestTheSocketDirectoryIsFrozen.test_the_freeze_is_the_last_exec_command_of_the_start_job" \
  '/^ExecStart=/a ExecStartPost=+/bin/true' \
  "code-server@.service"

# T68: the stat format loses its systemd escape. `%U` is a systemd specifier (the
# unit user's numeric uid), so `stat -c %U` becomes `stat -c <uid>` and the whole
# ownership comparison collapses to a constant — silently, and invisibly to any
# test that only greps for `stat -c`.
prove_unit "the stat format is eaten by systemd's own %U specifier" \
  "tests.unit.test_sso_units.TestTheSocketDirectoryIsFrozen.test_the_stat_format_is_escaped_from_systemd" \
  's@%%U@%U@' \
  "code-server@.service"

# --- what the freeze makes detectable (T69-T74) -------------------------------
# The freeze converts a silent degradation into a unit failure, and doctor could
# not see a unit failure: --quiet consulted instances only through the SSO branch,
# and the full report printed the state word without ever folding it into rc. A
# change whose own worst case is invisible on the box's only monitoring surface is
# a change that ships blind, so these land in the same commit as the unit.

# T69: --quiet stops consulting instances again — the cron hook goes silent by
# construction, because cron mails on OUTPUT and --quiet prints nothing.
prove "doctor --quiet exits 0 with every instance dead" \
  "tests.unit.test_sso_cli.TestDoctorSeesADeadInstance.test_quiet_folds_instances_in_on_a_password_box_too" \
  's|    ok = ok and not any(_instance_down(u) for u in instances)|    ok = ok and True|' \
  "cli.py"

# T70: the verdict widens to every not-active word — i.e. what branching on
# unit_is_active's boolean would give you. A cron run during boot, or during the
# operator's own restart, then pages on a healthy box, and a hook that cries wolf
# once is a hook nobody reads again.
prove "doctor calls a unit that is still starting a fault" \
  "tests.unit.test_sso_cli.TestDoctorSeesADeadInstance.test_a_unit_still_moving_is_not_a_fault" \
  's|_DOWN_STATES = ("failed", "inactive")|_DOWN_STATES = ("failed", "inactive", "activating", "deactivating", "reloading")|' \
  "cli.py"

# T71: the `enabled` requirement dropped. `vide down` disables the unit, and that
# is the ONLY discriminator between "the operator turned it off" and "it died".
prove "doctor pages on an instance the operator deliberately downed" \
  "tests.unit.test_sso_cli.TestDoctorSeesADeadInstance.test_a_deliberately_downed_instance_stays_silent" \
  's|    return system.unit_enable_state(unit) == "enabled"|    return True|' \
  "cli.py"

# T72: the frozen-directory row removed. The freeze is per-ACTIVATION state and a
# converge never restarts an instance, so on an upgraded box every already-running
# SSO instance is still unfrozen — and without this row nothing anywhere says so.
prove "doctor stops observing whether the socket directory is frozen" \
  "tests.unit.test_sso_cli.TestDoctorObservesTheSocketDirectory.test_a_user_owned_directory_is_a_fault" \
  's|        elif not frozen:|        elif False:|' \
  "cli.py"

# T73: the non-root gate removed. A frozen directory is unreadable to everyone
# but root and vide-proxy, so socket_stat returns None and the reaped branch
# reports MISSING on a healthy box — sending an operator to restart a working
# instance on the strength of a permission error.
prove "a non-root doctor reports a healthy socket as reaped" \
  "tests.unit.test_sso_cli.TestDoctorObservesTheSocketDirectory.test_a_non_root_caller_is_told_it_cannot_see_rather_than_lied_to" \
  's|    if not system.is_root():|    if False:|' \
  "cli.py"

# T74: socket_stat follows the link again. The detector then describes the thing
# the swapped entry points AT rather than the entry itself.
prove "socket_stat answers about a symlink's target instead of the symlink" \
  "tests.unit.test_sso_cli.TestDoctorObservesTheSocketDirectory.test_socket_stat_answers_about_the_entry_not_its_target" \
  's|        st = os.lstat(path)|        st = os.stat(path)|' \
  "system.py"

# T78b: the converge stops saying a restart is owed. Without it a template change
# is silent until a reboot applies it to every instance at once — and since the
# freeze the template can FAIL a start, so that reboot is the worst possible place
# to discover it. Both directions are pinned: the twin row below its named test
# requires a FIRST install to stay quiet.
prove "a converge changes the shared template and says nothing" \
  "tests.unit.test_sso_units.TestATemplateChangeIsAnnounced.test_a_changed_template_says_a_restart_is_owed" \
  's|    if existed and not ex.dry_run:|    if False:|' \
  "sysd.py"

# T78c: …and the opposite sign. A warning that fires on a first install, where
# there is nothing to restart, is how a warning gets ignored on the day it matters.
prove "the restart warning fires on a first install too" \
  "tests.unit.test_sso_units.TestATemplateChangeIsAnnounced.test_a_first_install_says_nothing" \
  's|    if existed and not ex.dry_run:|    if not ex.dry_run:|' \
  "sysd.py"

# T79: doctor treats "systemd said nothing" as healthy again. The enable-state
# check below it answers "unknown" too, so without this arm the whole verdict
# fails OPEN on a wedged box — the one that most needs the alarm.
prove "doctor exits 0 on a box whose systemd cannot answer" \
  "tests.unit.test_sso_cli.TestDoctorSeesADeadInstance.test_a_box_whose_systemd_says_nothing_is_a_fault" \
  's|    if word == "unknown":|    if False:|' \
  "cli.py"

# T80-T83: doctor's frozen-directory predicate, one conjunct at a time. A predicate
# proven only by its uid arm is a predicate whose other four conjuncts could be
# deleted in silence — and `not d.is_symlink` in particular is the one that makes
# the row an lstat rather than a stat.
prove "doctor accepts a SYMLINK where the socket directory should be" \
  "tests.unit.test_sso_cli.TestDoctorObservesTheSocketDirectory.test_a_symlinked_directory_is_a_fault" \
  's|and not d.is_symlink|and True|' \
  "cli.py"

prove "doctor accepts something that is not a directory at all" \
  "tests.unit.test_sso_cli.TestDoctorObservesTheSocketDirectory.test_a_directory_that_is_not_a_directory_is_a_fault" \
  's|d is not None and d.is_dir|d is not None and True|' \
  "cli.py"

prove "doctor stops checking which group may traverse the socket directory" \
  "tests.unit.test_sso_cli.TestDoctorObservesTheSocketDirectory.test_a_directory_group_owned_by_anything_else_is_a_fault" \
  's|and d.gid == want_gid and d.mode|and True and d.mode|' \
  "cli.py"

# T82: `vide status` collapses "cannot observe" back into "unhealthy". After the
# freeze the socket is unreadable to everyone but root and vide-proxy, so a
# non-root `vide status` — which the shim documents as supported — reported every
# healthy SSO instance as `unreachable`.
prove "a non-root vide status reports a healthy sso instance as unreachable" \
  "tests.unit.test_sso_cli.TestDoctorObservesTheSocketDirectory.test_status_says_unobservable_rather_than_unreachable" \
  's|        if st is None and not system.is_root():|        if False:|' \
  "registry.py"

# T84: `vide status` collapses "cannot observe" back into "unreachable" at the
# PRINT site. registry answers three states now; this is the branch that shows
# them, and nothing in the tier called cmd_status at all before, so deleting it
# re-shipped the round-1 regression at full green.
prove "vide status prints 'unreachable' for a socket it merely cannot read" \
  "tests.unit.test_sso_cli.TestDoctorObservesTheSocketDirectory.test_status_distinguishes_all_three_health_answers" \
  's|        if health is None:|        if False:|' \
  "cli.py"

# T85: doctor's directory row reports a permission error as UNFROZEN. path_facts
# maps every OSError to None, so without the denied check an unreadable parent
# reads as a fault — the same "cannot see reported as broken" conflation this
# round fixed one level down, reappearing the moment the row ran without root.
prove "doctor calls a directory it cannot read UNFROZEN" \
  "tests.unit.test_sso_cli.TestDoctorObservesTheSocketDirectory.test_a_directory_that_cannot_be_read_is_not_called_unfrozen" \
  's|        if not frozen and d is None and system.path_is_denied(parent):|        if False:|' \
  "cli.py"

# T86: the wedged-manager line reverts to the enabled-unit one, which asserts a
# fact that arm never read and prescribes reset-failed to the manager that is not
# answering. A confident wrong remedy is worse than none.
prove "a box whose systemd is wedged is told to reset-failed" \
  "tests.unit.test_sso_cli.TestDoctorSeesADeadInstance.test_an_unknown_state_gets_its_own_line" \
  's|            msg = (contract.MSG_INSTANCE_UNKNOWN if state == "unknown"|            msg = (contract.MSG_INSTANCE_DOWN if state == "unknown"|' \
  "cli.py"

# T87: the converge warns about an owed restart under --dry-run, where nothing
# was written and no restart is owed. Its named twin excludes the preview for the
# same reason: a dry run that prints an action item teaches the reader that the
# preview says things which are not true.
prove "a dry run claims a restart is owed" \
  "tests.unit.test_sso_units.TestATemplateChangeIsAnnounced.test_a_dry_run_says_nothing" \
  's|    if existed and not ex.dry_run:|    if existed:|' \
  "sysd.py"

# T88: path_is_denied stops distinguishing anything. Every doctor row stubs this
# seam, so without a row against the real filesystem `return False` re-opens the
# EACCES-as-a-fault defect while all of them stay green — which is the shape this
# task has now hit six times.
prove "the denied-vs-absent seam answers the same for both" \
  "tests.unit.test_sso_cli.TestDoctorObservesTheSocketDirectory.test_path_is_denied_really_distinguishes_the_two_failures" \
  's|    except PermissionError:|    except OSError:|' \
  "system.py"

# T89: a MISSING directory is described with UNFROZEN's ownership sentence, which
# says nothing about a directory that is not there and sends the operator to look
# at permissions for a problem that is an absence.
prove "a missing socket directory is reported as one the user owns" \
  "tests.unit.test_sso_cli.TestDoctorObservesTheSocketDirectory.test_a_missing_directory_is_not_described_as_the_users_to_rewrite" \
  's|                print(contract.MSG_SOCKET_DIR_MISSING.format(user=user, dir=parent))|                print(contract.MSG_SOCKET_DIR_UNFROZEN.format(user=user, dir=parent, found="MISSING"))|' \
  "cli.py"

# T90: a host tier clones back under a world-writable ancestor. /var/tmp is 1777, so
# the checkout gate refuses the tier's own install with exit 78 and the tier cannot
# pass on any stock box — which is how it sat there for months in
# host-smoke/rollback.sh, since the gate it was tripping is one of the things that
# tier exists to exercise.
prove_host_tier() { # <bug-name> <test-id> <sed-expr> <file>
  local name=$1 test_id=$2 sed_expr=$3 file=$4
  rm -rf "$SCRATCH/src" "$SCRATCH/units"
  cp -r "$REPO/src" "$SCRATCH/src"
  cp -r "$REPO/units" "$SCRATCH/units"
  rm -rf "$SCRATCH/tests"; cp -r "$REPO/tests" "$SCRATCH/tests"
  sed -i "$sed_expr" "$SCRATCH/tests/host-smoke/$file"
  if cmp -s "$SCRATCH/tests/host-smoke/$file" "$REPO/tests/host-smoke/$file"; then
    printf '  FAIL %s (the mutation did not apply — sed expression rotted)\n' "$name"
    fail=$((fail+1)); return
  fi
  red_or_fail "$name" "$test_id"
  # …and put tests/ back. This is the only helper that mutates it, and leaving a
  # mutated copy behind is the hazard `prove` records about units/: a later row
  # going red for the previous row's mutation is a proof of nothing. `return`
  # inside red_or_fail returns from red_or_fail, so this always runs.
  rm -rf "$SCRATCH/tests"; cp -r "$REPO/tests" "$SCRATCH/tests"
}

prove_host_tier "the rollback tier installs from a world-writable ancestor again" \
  "tests.unit.test_harness_guards.TestHostTiersInstallFromATreeTheGateAccepts.test_no_host_tier_clones_where_the_gate_would_refuse" \
  's|^CLONE=/opt/vide-rollback-clone$|CLONE=/var/tmp/vide-rollback-clone|' \
  "rollback.sh"

# --- the two SSO recovery verbs (T91-T93) -------------------------------------
# Both restart the fleet's SOLE authentication gate, and both were wrong about
# what happens next, in opposite directions. An operator reaches for these while
# something is already going badly, which is the worst possible time to be told
# a comforting untruth.

# T91: the health window narrowed back to the literal 20s, against a unit runway
# of StartLimitBurst x RestartSec = 120s. A slow OIDC discovery — the transient
# that runway was widened for — then reads as "the proxy rejected the new cookie
# secret", and rotate-sso RESTORES the secret it was invoked to burn.
prove "the rotate health window gives up before the unit stops retrying" \
  "tests.unit.test_sso_verbs.TestTheRecoveryVerbsOutlastTheUnitTheyRestart.test_the_wait_spends_the_whole_budget_in_WALL_CLOCK_not_iterations" \
  's|    for _ in range(UNIT_RESTART_BUDGET_S):|    for _ in range(20):|' \
  "oauth2proxy.py"

# T92: upgrade-sso stops checking that the gate came back. It then exits 0 with
# every auth: none IDE on the box unreachable — and prunes, deleting the N-1
# version its own failure message tells the operator to roll back to.
prove "an upgrade that leaves the whole fleet dark reports success" \
  "tests.unit.test_sso_verbs.TestTheRecoveryVerbsOutlastTheUnitTheyRestart.test_an_upgrade_that_leaves_the_fleet_dark_does_not_exit_zero" \
  's|^    _verify_proxy_came_back(cfg, ex, rep)$|    pass|' \
  "oauth2proxy.py"

# T93: …and the opposite sign. A verification that never passes is the same
# defect wearing the other face: the upgrade never completes and the rollback
# lever accumulates forever.
prove "a healthy upgrade is refused and never prunes" \
  "tests.unit.test_sso_verbs.TestTheRecoveryVerbsOutlastTheUnitTheyRestart.test_a_healthy_upgrade_still_prunes" \
  's|    if ex.dry_run or _proxy_pings(cfg):|    if False:|' \
  "oauth2proxy.py"

# T94: the squat case stops being looked at. Gating the probe on the unit being
# active means doctor never asks the one question that matters — "is the thing
# answering the fleet's authorization hop OUR proxy" — so the widest-blast-radius
# hole in the tree is the one state the diagnostic is blind to.
prove "doctor never looks at who is answering the authz hop" \
  "tests.unit.test_sso_verbs.TestSomethingElseAnsweringTheAuthzHopIsNamedAsBypass.test_an_answer_from_a_dead_unit_is_called_a_bypass" \
  's|    if usurped or harvesting or (answers and not holds and (failed or main_pid is None)):|    if False:|' \
  "oauth2proxy.py"

# T95: …and the opposite sign, which is the one that gets a check ignored.
# unit_is_active is False for `activating` and `deactivating`, so keying on it
# accuses the operator of an attack during their own restart.
prove "doctor calls a restarting proxy a bypass" \
  "tests.unit.test_sso_verbs.TestSomethingElseAnsweringTheAuthzHopIsNamedAsBypass.test_a_restarting_proxy_is_not_accused_of_being_an_attacker" \
  's|    if usurped or harvesting or (answers and not holds and (failed or main_pid is None)):|    if answers and not active:|' \
  "oauth2proxy.py"

# --- the checkout gate's second door (T96-T99) --------------------------------
# The root-level shims are NOT in the scratch tree that `prove` builds, and that
# is a trap rather than an inconvenience: the tests read REPO/vide, REPO resolves
# to $SCRATCH under this harness, and a MISSING file makes the test error — which
# red_or_fail would score as "the mutation went red". Every row aimed at a shim
# without this helper would be a vacuous proof of the exact kind this file exists
# to refuse. So the shims are copied in, mutated, and copied back pristine.
prove_shim() { # <bug-name> <test-id> <sed-expr> <file>
  local name=$1 test_id=$2 sed_expr=$3 file=$4
  rm -rf "$SCRATCH/src" "$SCRATCH/units"
  cp -r "$REPO/src" "$SCRATCH/src"
  cp -r "$REPO/units" "$SCRATCH/units"
  cp "$REPO/vide" "$REPO/install.sh" "$SCRATCH/"
  sed -i "$sed_expr" "$SCRATCH/$file"
  if cmp -s "$SCRATCH/$file" "$REPO/$file"; then
    printf '  FAIL %s (the mutation did not apply — sed expression rotted)\n' "$name"
    fail=$((fail+1))
    cp "$REPO/vide" "$REPO/install.sh" "$SCRATCH/"; return
  fi
  red_or_fail "$name" "$test_id"
  # Restore rather than delete: a later row whose test reads a MISSING shim would
  # error, and an error is indistinguishable from a red here.
  cp "$REPO/vide" "$REPO/install.sh" "$SCRATCH/"
}

# T96: the `vide` shim loses its checkout gate again — the state this repo shipped
# in for months, where "VIDE refuses an untrusted checkout" was true of
# `sudo ./install.sh` and false of `sudo vide`, which is the door every root
# management verb comes through.
prove_shim "the vide shim has no checkout gate" \
  "tests.unit.test_shims.TestCheckoutGateParity.test_both_shims_carry_the_byte_identical_checkout_gate" \
  '/^# >>> VIDE-CHECKOUT-GATE/,/^# <<< VIDE-CHECKOUT-GATE/d' \
  "vide"

# T97: -B dropped, so a root run writes .pyc files again and widens the window in
# which a poisoned __pycache__ can be planted and then preferred to the reviewed
# source.
prove_shim "a root run writes bytecode into the tree it just judged" \
  "tests.unit.test_shims.TestCheckoutGateParity.test_both_shims_refuse_to_write_bytecode" \
  's|^exec python3 -B |exec python3 |' \
  "vide"

# T98: the walk reverts to the enumeration. src/vide/tui — imported as root on
# every wizard install — was missing from BOTH gate halves for exactly as long as
# the list existed, because a list must be extended whenever a subpackage is added.
prove "the checkout gate stops walking and goes back to a list" \
  "tests.unit.test_preflight.TestCheckoutGate.test_a_world_writable_subpackage_is_refused" \
  's|_GATED_TREES: tuple\[str, ...\] = ("src", "units")|_GATED_TREES: tuple[str, ...] = ()|' \
  "preflight.py"

# T99: the refusal stops naming what still works without it. This gate can refuse
# EVERY verb including `vide doctor`, so an operator who trips it at a bad moment
# has just lost their diagnostics; telling them what did not go through the gate
# is the difference between a refusal and a dead end.
prove "the refusal takes away doctor without saying what is left" \
  "tests.unit.test_preflight.TestCheckoutGate.test_the_refusal_leads_with_re_clone_and_names_pycache" \
  's|f"work: systemctl status code-server@<user>, journalctl -u "|f"work: "|' \
  "preflight.py"

# --- the port reservation (T100-T182) -----------------------------------------
#
# FOUR HOUSE RULES FOR THIS BLOCK, all four learned the expensive way:
#
#   1. A ROW MAY NOT NAME A TEST THAT MOCKS THE FUNCTION IT MUTATES. T108c named
#      one for a whole round: the test patched the staleness predicate itself, so
#      the row proved the CALL SITE and nothing below it while two defects lived
#      underneath. Its sed is unchanged and its meaning is not — see its comment.
#   2. THE TWO FAILURE TEXTS ARE DIFFERENT DIAGNOSES. "the mutation did not apply
#      — sed expression rotted" means the LINE guess was wrong: re-aim it at
#      whatever now carries the property. "test stayed GREEN — no teeth" means
#      the TEST is wrong: re-name it. NEITHER IS EVER FIXED BY WEAKENING A TEST —
#      that is how T113 came to mutate `holds` while a different branch carried
#      the property it claimed to destroy.
#   3. `grep -c` the pattern before adding a row. The harness detects a sed that
#      matched NOTHING; it cannot detect one that matched TWICE.
#   4. `|` is the delimiter used throughout, so a target line CONTAINING a pipe
#      needs a different one — `s@…@…@`. sed reports the malformed expression as
#      "did not apply", i.e. as rule 2's ROTTED diagnosis, which sends you
#      hunting for a moved line that never moved. One row here uses `@` for
#      exactly this reason (the set-union in `legitimate`).
# units/oauth2-proxy.socket is the whole fix for the squattable authorization
# port, and every line in it that matters looks removable. A failed socket unit
# calls socket_close_fds() and hands the address straight back, so each of the
# first two rows below re-enables one documented path to `failed`.

# T100: the trigger limiter comes back. Default is 20 activations per 2s, and
# systemd's own words are that hitting it leaves the unit "not connectible
# anymore until restarted" — i.e. the fd closes, on precisely the crash loop the
# reservation exists for. One code-server page load makes more than 20
# forward_auth sub-requests, so this needs no attacker at all.
prove_unit "the socket can be trigger-limited into giving the port back" \
  "tests.unit.test_sso_units.TestTheReservationUnitCannotBeMadeToLetGo.test_both_rate_limiters_are_disabled_on_the_socket" \
  '/^TriggerLimitIntervalSec=0$/d' \
  "oauth2-proxy.socket"

# T101: the socket's OWN start limiter comes back (5 starts / 10s by default).
# Reachable during recovery — the service's Requires= re-attempts this unit on
# every auto-restart, and an operator restarting by hand exceeds it without
# trying.
prove_unit "the socket can be start-limited into giving the port back" \
  "tests.unit.test_sso_units.TestTheReservationUnitCannotBeMadeToLetGo.test_both_rate_limiters_are_disabled_on_the_socket" \
  '/^StartLimitIntervalSec=0$/d' \
  "oauth2-proxy.socket"

# T102: a second ListenStream. `fd:3` is an INDEX, not a name — oauth2-proxy
# takes position (3 - SD_LISTEN_FDS_START) out of the list systemd passed, in
# ListenStream= order. Adding an IPv6 twin looks like completeness and silently
# repoints the fleet's authorization gate at the wrong socket, with no error.
prove_unit "a second listener silently repoints the gate" \
  "tests.unit.test_sso_units.TestTheReservationUnitCannotBeMadeToLetGo.test_exactly_one_listen_stream_because_fd_3_is_an_index" \
  's|^Accept=no$|ListenStream=[::1]:4180\nAccept=no|' \
  "oauth2-proxy.socket"

# T103: SO_REUSEPORT. Reads like a hardening or a restart-smoothing option; it
# lets a SECOND process bind the same address alongside systemd, which is the
# exact hole this unit closes, reopened silently.
prove_unit "ReusePort lets a second process share the fleet's port" \
  "tests.unit.test_sso_units.TestTheReservationUnitCannotBeMadeToLetGo.test_the_directives_that_would_reopen_the_hole_are_absent" \
  's|^Accept=no$|Accept=no\nReusePort=yes|' \
  "oauth2-proxy.socket"

# T104: the boot window reopens. multi-user.target is reached long after
# sockets.target — after login sessions and user units exist — so the reservation
# is downgraded from "before anything unprivileged runs" to "after", which is the
# window the OIDC-discovery gap used to leave open.
prove_unit "the reservation is downgraded to a late-boot one" \
  "tests.unit.test_sso_units.TestTheReservationUnitCannotBeMadeToLetGo.test_it_binds_at_sockets_target_which_is_the_boot_window" \
  's|^WantedBy=sockets.target$|WantedBy=multi-user.target|' \
  "oauth2-proxy.socket"

# T105: the service stops requiring the socket. Then `systemctl start` on a box
# whose socket is down execs the proxy anyway, it dies with "fd outside of range
# of available file descriptors", and the migration no longer completes by
# itself on a plain service restart.
prove_unit "the service starts without the descriptor it needs" \
  "tests.unit.test_sso_units.TestTheReservationUnitCannotBeMadeToLetGo.test_it_binds_at_sockets_target_which_is_the_boot_window" \
  '/^Requires=vide-oauth2-proxy.socket$/d' \
  "oauth2-proxy.service"

# T106: proxy.toml goes back to binding the address itself. This is the revert
# that looks like a simplification — it removes a whole unit's worth of
# indirection and puts the port back where a reader expects it — and it restores
# the original defect exactly: the proxy binds, so the address is free whenever
# the proxy is not on it.
prove "the proxy binds the fleet's port itself again" \
  "tests.unit.test_sso_verbs.TestTheFleetPortIsOneReader.test_every_renderer_names_the_pinned_port" \
  's|^http_address = "fd:3"$|http_address = "127.0.0.1:4180"|' \
  "oauth2proxy.py"

# T108c: the OTHER half of the closed loop. Dropping the staleness check leaves
# upgrade-sso a no-op for a changed unit or proxy.toml on a migrated box — the
# converge wrote those files and warned about a pending restart, and the verb
# that warning names then finds nothing to do.
#
# WHAT THIS ROW NOW PROVES, and it is more than it used to. Its named test used
# to patch the staleness predicate itself, so the row could only establish that
# the call site consulted SOMETHING — the whole chain below it (the file compare,
# the start-time reader, the /proc parse) was mocked away and could have been a
# constant. That mock is gone: the test drives the real decision against real
# mtimes, so this sed now destroys the property end to end. The sed is unchanged;
# the meaning is not.
prove "the pending-restart warning dead-ends in upgrade-sso" \
  "tests.unit.test_sso_verbs.TestTheRecoveryVerbsOutlastTheUnitTheyRestart.test_upgrade_restarts_when_the_running_proxy_predates_its_config" \
  's|            elif m > started + _START_TIME_SLACK:|            elif False:|' \
  "oauth2proxy.py"

# T113: the root-verified holder row is removed. Then the reload-orphaned box —
# socket unit `active`, configured for the pin, systemd holding nothing after a
# bare daemon-reload — reads as healthy the moment an unprivileged account binds
# the port, because every remaining signal is either the manager's own claim or
# ambient state the attacker just satisfied. The attack produces the health
# report. (Targets the ROW, not `holds`: the row is what names this state, and a
# mutation of `holds` alone leaves it firing — which is how this proof was found
# to have no teeth in the first place.)
prove "a squatter can turn the reservation row green" \
  "tests.unit.test_sso_verbs.TestDoctorTellsTheTruthAboutTheReservation.test_a_squatter_cannot_turn_the_reservation_row_green" \
  's|    if usurped:|    if False:|' \
  "oauth2proxy.py"

# T114: the proxy's own MainPID stops being excluded from `usurped`. Then every
# converged-but-not-yet-restarted box — i.e. the whole fleet on upgrade day —
# is accused of a squat under root, because the proxy legitimately holds the
# port itself until the gate restarts. The containment ladder tells every
# operator to stop caddy, and the one alarm that means "you are being attacked"
# becomes the one they learn to ignore.
prove "a healthy un-migrated box is accused of a squat" \
  "tests.unit.test_sso_verbs.TestDoctorTellsTheTruthAboutTheReservation.test_an_unmigrated_box_is_not_accused_of_a_squat" \
  's@    legitimate = {0} | ({proxy_uid} if proxy_uid is not None else set())@    legitimate = {0}@' \
  "oauth2proxy.py"

# T109: the reservation takes its port from `.env` instead of the fleet pin. It
# would bind one address while every rendered Caddy body dials another — the
# fleet's real hop left free, and no other row noticing, because the unit file
# and the bodies are each internally consistent.
prove "the reservation binds .env's port instead of the pin" \
  "tests.unit.test_sso_verbs.TestTheReservationUnitIsActuallyRendered.test_converge_reserves_THE_PIN_never_the_env_row" \
  's|    port = vide_sso.fleet_port(cfg)|    port = cfg.sso_proxy_port|' \
  "oauth2proxy.py"

# T110: converging over a MASKED reservation unit. Masking this one does not
# switch the SSO gate off — it hands the fleet's authorization address to
# whoever binds it next — so silently converging over it is VIDE agreeing.
prove "a masked reservation unit is converged over in silence" \
  "tests.unit.test_sso_verbs.TestTheReservationUnitIsActuallyRendered.test_a_masked_reservation_unit_is_refused" \
  's|    if system.unit_enable_state(SOCKET_UNIT).startswith("masked"):|    if False:|' \
  "oauth2proxy.py"

# T111: the drift compare goes back to a substring. `f"127.0.0.1:{port}" in ln`
# reads fine and matches 41800 against a pin of 4180, so a drifted unit reports
# as covering the fleet's port while that port is open to anyone.
prove "the drift check matches a prefix port" \
  "tests.unit.test_sso_verbs.TestDoctorTellsTheTruthAboutTheReservation.test_a_prefix_port_is_not_mistaken_for_the_pin" \
  's|    return any(ln.split()\[0\] == want for ln in listening if ln.split())|    return any(want in ln for ln in listening)|' \
  "oauth2proxy.py"

# T112: doctor trusts the manager about what is bound. `show -p Listen` answers
# from the unit FILE, so after a ListenStream= edit plus a bare daemon-reload it
# names an address systemd is no longer holding — and the row agrees with itself
# over an open port.
prove "doctor believes a configured port is a bound one" \
  "tests.unit.test_sso_verbs.TestDoctorTellsTheTruthAboutTheReservation.test_configured_but_unbound_is_reported_not_believed" \
  's|    bound = bool(on_hop)|    bound = True|' \
  "oauth2proxy.py"

# T108: upgrade-sso goes back to asking whether a FILE moved. This is the closed
# loop, and it is the most dangerous mutation in this group because it looks
# like a simplification: the converge has already written every one of those
# files by the time an operator runs this verb, so all three comparisons say
# "unchanged", nothing restarts, and the reservation never takes effect on any
# box — while doctor keeps naming the same command.
prove "upgrade-sso asks about files instead of live state" \
  "tests.unit.test_sso_verbs.TestTheRecoveryVerbsOutlastTheUnitTheyRestart.test_upgrade_restarts_when_the_reservation_is_not_yet_in_effect" \
  's|^    elif socket_state != "active":|    elif False:|' \
  "oauth2proxy.py"

# T108b: …and the opposite sign. Restarting unconditionally would bounce the
# fleet's sole authorization gate on a verb operators run to LOOK at things,
# which is how a lever three messages point at stops being used.
prove "upgrade-sso bounces the gate every time it is run" \
  "tests.unit.test_sso_verbs.TestConvergeIsUnconditional.test_a_second_converge_does_not_restamp_an_unchanged_proxy_toml" \
  's|^    if toml_changed:|    if True:|' \
  "oauth2proxy.py"

# T107: converge stops enabling the socket. `enable` is what puts the reservation
# into the boot transaction at sockets.target; without it the unit exists, the
# tests that read the FILE still pass, and no box ever reserves anything at boot.
# ANCHORED TO THE FIRST MATCH ONLY. The bare form matched TWICE — converge's
# enable and upgrade-sso's — so the row silently stripped both while its prose
# named one. House rule 3 above says the harness cannot see a double match; this
# is the row it was written about. `0,/re/s//repl/` bounds the substitution to
# the first occurrence, which is converge's (it comes first in the file).
prove "the reservation is installed but never enabled" \
  "tests.unit.test_sso_verbs.TestConvergeIsUnconditional.test_the_port_reservation_is_installed_and_enabled_but_never_forced" \
  '0,/    ex.run(\["systemctl", "enable", SOCKET_UNIT\])/s//    pass/' \
  "oauth2proxy.py"

# T115: the gate's age is read off /proc/<pid>'s own mtime again — the defect
# this round exists to remove, verbatim. That is the INODE's stamp: procfs
# allocates it lazily at lookup and the kernel recreates it with a FRESH
# timestamp whenever the dentry is reclaimed, which ordinary memory pressure (or
# a plain `echo 2 > /proc/sys/vm/drop_caches`) does. So a process that has been
# up for a week reports thirty seconds — and the error only ever runs in the
# DECLINING direction: upgrade-sso refuses to restart, the migration never lands,
# and every verb reports success.
prove "the gate's age is read off a restamped inode" \
  "tests.unit.test_sso_foundations.TestProcessStartTimeIsNotTheInodeStamp.test_restamping_the_proc_directory_does_not_move_the_answer" \
  's|    return btime + ticks / hz|    return (proc_root / str(pid)).stat().st_mtime|' \
  "system.py"

# T116: the LAST ')' becomes the FIRST one — the plausible respelling, not a
# strawman. comm is field 2, printed raw between parentheses, and it is a
# filename: it may contain spaces AND ')'. An executable named
# `oauth2 proxy (old)` then shifts every later field and field 22 is read out of
# the wrong column. The answer stays a perfectly reasonable-looking timestamp,
# which is why nothing downstream can catch it.
prove "the comm field shifts the process start time" \
  "tests.unit.test_sso_foundations.TestProcessStartTimeIsNotTheInodeStamp.test_a_comm_with_spaces_and_parens_does_not_shift_the_field" \
  's|    tail = raw.rpartition(b")")\[2\].split()|    tail = raw.partition(b")")[2].split()|' \
  "system.py"

# T117: the boot-time anchor is dropped, so the answer is seconds since BOOT
# while every mtime it is compared against is seconds since the EPOCH. Every
# file on the box then outranks every process: the staleness clause is
# permanently true and upgrade-sso bounces the fleet's sole authorization gate
# on every run, forever — on the verb operators run to LOOK at things.
prove "the gate's age is measured from boot instead of the epoch" \
  "tests.unit.test_sso_foundations.TestProcessStartTimeIsNotTheInodeStamp.test_the_answer_is_boot_time_plus_the_processs_own_start" \
  's|    return btime + ticks / hz|    return ticks / hz|' \
  "system.py"

# T118: the same mutation as T108b, deliberately, and a DIFFERENT test — this is
# the only row binding the WRITER's conditionality to the READER's correctness.
# T108b proves the mtime does not move; this proves what the moved mtime COSTS,
# across two verbs: converge writes a byte-identical proxy.toml, that restamps
# it newer than the running gate, and the next upgrade-sso reads the gate as
# stale and restarts it. Both halves were green in isolation while exactly that
# shipped, so one row has to stand in the gap between them.
prove "a converge restamps proxy.toml and makes the next upgrade bounce the gate" \
  "tests.unit.test_sso_verbs.TestAConvergeDoesNotMakeTheNextUpgradeBounceTheGate.test_a_converge_then_an_upgrade_leaves_the_gate_alone" \
  's|^    if toml_changed:|    if True:|' \
  "oauth2proxy.py"

# T119: the opposite sign of T108c on the same line, and the sign this round's
# second defect actually shipped. The file compare stops asking and always says
# "newer", so the migration lever restarts the gate every single time it is run
# — proven here at the level where an operator would feel it: run the documented
# lever twice on a box that is already migrated and the second run must be
# silent. A clause that is not FALSE immediately after the restart it demanded
# is not a reason to restart, it is a loop.
prove "upgrade-sso bounces the gate on every run" \
  "tests.unit.test_sso_verbs.TestTheUnmigratedBoxWalksToMigrated.test_a_second_upgrade_on_the_migrated_box_does_not_bounce_the_gate" \
  's|            elif m > started + _START_TIME_SLACK:|            elif True:|' \
  "oauth2proxy.py"

# T120: the unreadable-/proc exit is removed. `started` is then None, the
# comparison raises TypeError — which is NOT OSError and so is caught nowhere —
# and the migration lever three separate messages send the operator to dies with
# a traceback instead of declining to restart. AN INPUT THAT CANNOT BE READ MAY
# NOT DECIDE, and it may not crash either.
prove "an unreadable /proc turns the migration lever into a traceback" \
  "tests.unit.test_sso_verbs.TestTheRestartDecisionAsksAboutTheRUNNINGProcess.test_an_unreadable_start_time_does_not_bounce_the_gate" \
  's|    elif pid is None or started is None:|    elif False:|' \
  "oauth2proxy.py"

# T121: doctor can never report the reservation as being in effect. Then every
# CORRECTLY MIGRATED box in the fleet — the state this whole release exists to
# produce — reads DRIFT, and `doctor --quiet`, the documented cron hook, is red
# fleet-wide with no way to clear it. An alarm that cannot be cleared is an alarm
# that gets switched off.
prove "a migrated box can never read green" \
  "tests.unit.test_sso_verbs.TestDoctorTellsTheTruthAboutTheReservation.test_root_beside_the_proxy_is_still_not_reserved" \
  's|    holds = socket_state == "active" and covers and root_held|    holds = socket_state == "active" and covers|' \
  "oauth2proxy.py"

# T129: doctor stops looking at who is being SERVED on the hop. This is the one
# state a listener-only check structurally cannot see: an attacker hands the
# LISTENING socket back — so the address reads reserved and every holder signal
# goes green — while staying alive and answering every connection Caddy already
# had open. The containment ladder's own step 2 calls that check "not optional",
# and until this signal existed nothing in doctor performed it.
prove "the harvest continues behind a reserved-looking port" \
  "tests.unit.test_sso_verbs.TestDoctorTellsTheTruthAboutTheReservation.test_a_stranger_serving_connections_on_the_hop_is_a_bypass" \
  's|    harvesting = (holders is not None|    harvesting = (False|' \
  "oauth2proxy.py"

# T130: the v6 ranking is dropped and `::` rows are counted beside a definite
# v4 answer. A v6only `[::]:<port>` bind needs no privilege and legally
# coexists with systemd's `127.0.0.1:<port>` — that is what makes sshd's
# 0.0.0.0:22 + :::22 pair possible — so ONE unprivileged bind(2) then clears
# the affirmative row on a correctly reserved box and fires a containment
# ladder whose first step is `systemctl stop caddy`. A deliberate fleet outage,
# on every box, caused by a listener that carries no v4 traffic at all.
prove "one unprivileged bind on [::] fires the containment ladder fleet-wide" \
  "tests.unit.test_sso_foundations.TestWhoHoldsTheFleetsPort.test_a_v6only_wildcard_beside_the_reservation_is_dropped_entirely" \
  's|                      possible=frozenset() if certain else frozenset(possible),|                      possible=frozenset(possible),|' \
  "system.py"

# T122: the squat arm stops asking WHO holds the port. On a box where the socket
# unit drifted onto the wrong address AND a stranger took the fleet's real hop,
# the service is `active` with a MainPID and is not `failed` — so nothing else in
# that predicate fires, the operator gets an advisory reservation row and NO
# containment ladder, and the stranger goes on answering forward_auth for every
# instance on the box. This is the one state that earns `usurped` its place in a
# fail-loud arm.
prove "the containment ladder is withheld from the one state only the holder check sees" \
  "tests.unit.test_sso_verbs.TestDoctorTellsTheTruthAboutTheReservation.test_a_drifted_unit_over_a_squatted_hop_gets_the_containment_ladder" \
  's|    if usurped or harvesting or (answers and not holds and (failed or main_pid is None)):|    if (answers and not holds and (failed or main_pid is None)):|' \
  "oauth2proxy.py"

# T123: "not root, could not tell" collapses into "nobody is listening". That
# distinction IS the reader — every caller branches on it — and losing it turns
# a non-root doctor's ignorance into a positive claim of an empty port, on the
# one signal that separates PID 1 from an attacker.
# T124: the restart decision stops watching the service unit. The membership of
# _gate_inputs was covered by NOTHING — every end-to-end row moves all three
# files at once, so any single member could be deleted with the suite green.
# The box that breaks is this release's own: a converge writes a hardened
# service unit on a MIGRATED box, warns that a restart is pending, and the
# operator runs the verb that message names — by then unit_changed is False, the
# gate is active, the socket is active and proxy.toml is unchanged, so the
# service unit's mtime is the only clause left. Drop it and the hardening never
# lands while the verb reports success: defect 1, verbatim.
prove "the restart decision stops watching the service unit" \
  "tests.unit.test_sso_verbs.TestTheRestartDecisionAsksAboutTheRUNNINGProcess.test_the_three_gate_inputs_are_exactly_these_three" \
  's|    return \[SYSTEMD_DIR / UNIT,|    return [|' \
  "oauth2proxy.py"

# T125: the usurpation signal is switched off. Everything else in the section is
# either the manager's own claim about a unit or ambient state an unprivileged
# account can create, so this is the only thing standing between a stranger on
# the fleet's authorization hop and a doctor that describes the box as merely
# drifted — advisory row, no containment ladder, no BYPASS token, while the
# stranger answers forward_auth for every instance.
prove "doctor stops asking whether the holder is legitimate" \
  "tests.unit.test_sso_verbs.TestDoctorTellsTheTruthAboutTheReservation.test_no_name_a_process_can_choose_reaches_this_verdict" \
  's|    usurped = holders is not None and bool(on_hop) and not (on_hop <= legitimate)|    usurped = False|' \
  "oauth2proxy.py"

# T126: the same mutation as T122, and a DIFFERENT property — the containment
# ladder goes back to being gated on the attacker's cooperation. A squatter that
# answers Caddy's real forward_auth request while 404-ing /ping leaves `answers`
# False, so the operator gets an advisory row and NO containment steps during
# the harvest the ladder exists to stop. The uid read is a kernel fact; it needs
# no corroboration from the process being reported.
prove "the containment ladder waits for the squatter's permission" \
  "tests.unit.test_sso_verbs.TestDoctorTellsTheTruthAboutTheReservation.test_the_containment_ladder_does_not_wait_for_the_squatter_to_answer" \
  's|    if usurped or harvesting or (answers and not holds and (failed or main_pid is None)):|    if (answers and not holds and (failed or main_pid is None)):|' \
  "oauth2proxy.py"

# T127: the converge's pending warning loses its gate and fires on every
# converge of every MIGRATED box, forever — about a box where systemd has held
# the address since sockets.target, in the same string doctor uses as its
# migration-day red row. An alarm that is always on is an alarm nobody reads,
# and this one names a verb that then has nothing to do.
prove "a migrated box is told forever that its reservation is pending" \
  "tests.unit.test_sso_verbs.TestTheUnmigratedBoxWalksToMigrated.test_a_migrated_box_is_not_told_its_reservation_is_pending" \
  's|    elif not ex.dry_run and system.unit_state(SOCKET_UNIT) != "active":|    elif not ex.dry_run:|' \
  "oauth2proxy.py"

# T128: the posture repair is retired again. Guarding the proxy.toml write on a
# byte-compare is right and it took this repair with it; the argument that the
# loss was free holds only for a NARROWING. A widening — 0660, or an owner
# change to vide-oauth2 — is silent everywhere in the tree and hands WRITE
# access over trusted_proxy_ips (the CVE-2026-40575 mitigation) to the one
# account on the box with a pre-authentication surface facing the internet.
prove "a widened proxy.toml is left widened" \
  "tests.unit.test_sso_verbs.TestConvergeIsUnconditional.test_a_proxy_toml_whose_mode_drifted_is_repaired_without_a_rewrite" \
  's|    _repair_toml_posture(cfg, ex, rep)|    pass|' \
  "oauth2proxy.py"

prove "a withheld process column is read as an empty port" \
  "tests.unit.test_sso_foundations.TestWhoHoldsTheFleetsPort.test_an_unreadable_v4_table_is_unknown_even_when_v6_answers" \
  's@        v4_text = (proc_root / "net/tcp").read_text()@        v4_text = (proc_root / "net/tcp").read_text() if (proc_root / "net/tcp").exists() else ""@' \
  "system.py"

# T131: the abandoned-hop row is deleted, and with it the ONLY thing in the
# product that can see the terminal state of a hand-edited fleet pin. Every
# other row in the reservation section is computed against the PIN, so after an
# edit + converge + reboot systemd holds the NEW address, `covers` is true for
# it, the holder is uid 0 and the proxy answers /ping on it: doctor prints
# `proxy port: reserved` and exits 0 while the address the operator's own pasted
# Caddyfile still dials is unheld, squattable, and every SSO instance behind it
# returns 502. A diagnostic that is green during a fleet-wide outage with an open
# authorization hop is the failure this whole section exists to prevent.
prove "doctor is green over an abandoned authorization hop" \
  "tests.unit.test_sso_foundations.TestTheAbandonedHop.test_a_moved_pin_is_RED_and_names_both_addresses" \
  's|    stale = sorted(p for p in pasted if p != pin)|    stale = []|' \
  "oauth2proxy.py"

# T132: the row stops asking the kernel about the abandoned address and always
# says it is free. The pasted port alone establishes only that two numbers
# differ; whether that address is HELD is what separates "a migration somebody
# started" from "an open door", and it is the half that earns the row its place
# in `ok`.
#
# RE-AIMED when the boolean became a four-state classifier. The old target,
# `held = holders is not None and bool(holders.on_hop)`, is gone — it collapsed
# "nobody is there", "we could not look" and "this box's own reservation is
# there" into one word, and the middle two were being reported as the first and
# the third as a squatter. The SUBJECT is unchanged and so is the named test:
# force the classifier's NOBODY arm and the row calls the address open without
# having looked.
prove "the abandoned hop is called open without looking" \
  "tests.unit.test_sso_foundations.TestTheAbandonedHop.test_it_says_whether_the_abandoned_address_is_held" \
  's|    if not holders.on_hop:|    if True:|' \
  "oauth2proxy.py"

# T133: the move refusal is deleted, so a hand-edited pin walks straight through
# a converge: VIDE writes the new ListenStream= and reloads, systemd drops the
# descriptor it was holding and binds NOTHING in its place. The fleet's gate is
# down and its address unowned at the same moment, while the block in the
# operator's own Caddyfile still dials the old number.
prove "a moved pin is written over the loaded reservation" \
  "tests.unit.test_sso_verbs.TestTheReservationUnitIsActuallyRendered.test_a_pin_that_moved_away_from_the_loaded_unit_refuses_the_write" \
  's|    if loaded and not _covers_port(loaded, port):|    if False:|' \
  "oauth2proxy.py"

# T134: …and the opposite sign. The refusal loses its DIRECTION and fires
# whenever any reservation is loaded, so the unit's own hardening — a corrected
# limiter, a new directive — can never again be re-rendered onto a migrated box.
# Same silence, opposite cause.
prove "the reservation can never be re-rendered once it is loaded" \
  "tests.unit.test_sso_verbs.TestTheReservationUnitIsActuallyRendered.test_a_unit_already_on_the_pin_is_re_rendered_normally" \
  's|    if loaded and not _covers_port(loaded, port):|    if loaded:|' \
  "oauth2proxy.py"

# T135: the declined write is REPORTED as a write. `wrote` then names the socket
# unit on every run and the restart clause never self-clears — so `upgrade-sso`
# bounces the fleet's sole authorization gate forever, on a box where nothing
# changed. Range-addressed: this function has other `return False`s and rule 3
# cannot see a sed that matches twice — and the range now STARTS at the pin-move
# message, so the unreadable-manager branch above it keeps its own `return
# False`. That is why the named test has to be the one that walks the pin-move
# arm: the unreadable row never reaches the mutated line, so naming it left this
# row with no teeth for one run.
prove "the write that was refused is reported as done" \
  "tests.unit.test_sso_verbs.TestTheReservationUnitIsActuallyRendered.test_a_pin_that_moved_away_from_the_loaded_unit_refuses_the_write" \
  '/MSG_PROXY_PIN_MOVE_REFUSED/,/return False/s|        return False|        return True|' \
  "oauth2proxy.py"

# T136: the converge stops noticing a reservation that holds nothing. The unit
# reads `active`, is configured for the pin, and the address is free — and
# `systemctl start` on it returns -EALREADY and reports success, so nothing else
# in the run can see it either.
prove "a converge is silent about a reservation holding nothing" \
  "tests.unit.test_sso_verbs.TestWhatAConvergeSaysAboutTheReservationItJustInstalled.test_an_active_reservation_that_holds_nothing_is_named" \
  's|    if not ex.dry_run and system.unit_state(SOCKET_UNIT) == "active":|    if False:|' \
  "oauth2proxy.py"

# T137: the `covers` conjunct goes, so a DRIFTED box is described in NOT BOUND's
# words — and NOT BOUND prescribes a restart, which on a drifted box rebinds the
# wrong address and does not clear the row. These two states were described in
# each other's words for two rounds already.
prove "a drifted unit is handed the wrong remedy" \
  "tests.unit.test_sso_verbs.TestWhatAConvergeSaysAboutTheReservationItJustInstalled.test_a_drifted_unit_is_not_described_in_not_bounds_words" \
  's|        if (_covers_port(system.unit_listen_streams(SOCKET_UNIT), port)|        if (True|' \
  "oauth2proxy.py"

# T138: an unreadable /proc decides. The converge then prints "the fleet's
# authorization port is open right now" from a measurement that never happened,
# with a remedy that restarts the gate.
prove "an unreadable kernel produces the open-port alarm" \
  "tests.unit.test_sso_verbs.TestWhatAConvergeSaysAboutTheReservationItJustInstalled.test_an_unreadable_kernel_does_not_produce_the_warning" \
  's|                and held is not None and 0 not in held.certain):|                and 0 not in (held.certain if held else set())):|' \
  "oauth2proxy.py"

# T139: the move-aware branch is switched off, so a box whose pin moved is told
# the ordinary migration remedy — and on that box `sudo vide upgrade-sso` and a
# reboot are precisely the two commands that PERFORM the move.
prove "a moved pin is told the remedy that moves the fleet" \
  "tests.unit.test_sso_verbs.TestWhatAConvergeSaysAboutTheReservationItJustInstalled.test_a_pin_with_nothing_on_it_is_not_told_the_ordinary_remedy" \
  's|                  if holders is not None and not holders.on_hop|                  if False|' \
  "oauth2proxy.py"

# T140: …and the opposite sign, which is mandatory over a message-selection
# branch: forced always-on, every un-migrated box in the fleet loses the one
# command that migrates it, on the day it is upgraded.
prove "the migration lever disappears from the ordinary row" \
  "tests.unit.test_sso_verbs.TestWhatAConvergeSaysAboutTheReservationItJustInstalled.test_the_ordinary_unmigrated_box_still_gets_the_migration_lever" \
  's|                  if holders is not None and not holders.on_hop|                  if True|' \
  "oauth2proxy.py"

# T141: the guard leaves _render_all and one edited .env row again rewrites every
# instance's forward_auth upstream — then `vide allow` reloads Caddy and pushes
# it live. Any local account binds the address and answers 202 for every
# instance on the box, collecting the fleet cookie on every request.
prove "a grant repoints every instance's authorization hop" \
  "tests.unit.test_sso_verbs.TestAGrantMayNotMoveTheFleetsAuthorizationHop.test_a_moved_pin_does_not_repoint_every_instances_authz_hop" \
  's|        _refuse_a_hop_move(cfg, port, \[f.name for f in files\])|        pass|' \
  "sso.py"

# T142: the union write moves BELOW the guard, so on a moved-pin box a revoke
# stops evicting fleet-wide during the one incident it exists for. The ordering
# inside _render_all is a security property, not a style. Range-addressed —
# seed_union calls the same helper and must survive.
prove "a refused render also cancels the revocation" \
  "tests.unit.test_sso_verbs.TestAGrantMayNotMoveTheFleetsAuthorizationHop.test_a_revoke_still_evicts_fleet_wide_when_the_body_render_refuses" \
  '/^def _render_all/,/^def _require_parent/s|^    _write_union(cfg, ex)$|    pass|' \
  "sso.py"

# T143: the permit stops asking whether the root-held address is OUR reservation.
# hop_holders' v4 match set includes the 0.0.0.0 wildcard, so `certain == {0}` is
# satisfied by any unrelated root daemon on a wildcard port — and the bodies,
# carrying the fleet cookie, are repointed at that service.
prove "any root daemon's port is accepted as the fleet's reservation" \
  "tests.unit.test_sso_verbs.TestAGrantMayNotMoveTheFleetsAuthorizationHop.test_root_holding_some_other_wildcard_port_is_not_our_reservation" \
  's|            and _covers_port(system.unit_listen_streams(SOCKET_UNIT), port)|            and True|' \
  "oauth2proxy.py"

# T144: the migration lever dies in the re-render it performs AFTER the binary
# was swapped, the gate restarted and the old version pruned — a traceback out
# of the one verb three other messages name.
prove "a moved pin turns upgrade-sso into a traceback" \
  "tests.unit.test_sso_verbs.TestAGrantMayNotMoveTheFleetsAuthorizationHop.test_the_upgrade_lever_warns_instead_of_dying_in_the_re_render" \
  '/^def rerender_bodies/,/^def reload_caddy/s|    except (StateError, ConfigError) as e:|    except _NeverRaised as e:|' \
  "sso.py"

# --- finishing the family: the rows the review fixes shipped without ----------
# Every row below was watched go red under its own mutation BEFORE it was
# written, and green on the pristine tree, and its target `grep -c`'d for
# uniqueness. Three targets are NOT unique and are range-addressed for that
# reason: `if not on_pin:` appears in _auth_block_drift and _stale_authz_bodies,
# `if holders is None:` three times, and the enable guard once per verb.

# T145-T147: the WRITE PERMIT on the auth body, all three signs. It replaced the
# advice-selection branch these rows used to guard: once the operator stopped
# pasting the body, VIDE writes it — and writing it is a move that can REPOINT
# the fleet's authorization sub-request, so it carries the same permit the
# per-instance bodies do. Three rows and not two, because the conjunct matters
# independently of the branch: forced-permit releases the hop on a moved-pin box,
# forced-refuse freezes the login flow forever, and dropping `gate_is_on_hop`
# alone strands the LAST step of the documented move, which is the state nobody
# tests by accident.
prove "the body is re-rendered onto an address the gate does not serve" \
  "tests.unit.test_sso_verbs.TestConvergeRelandsTheAuthBody.test_a_repoint_is_refused_when_the_gate_is_not_on_the_pin" \
  's|    if repoint and not gate_is_on_hop(pin):|    if False:|' \
  "oauth2proxy.py"
prove "the body is never re-rendered at all" \
  "tests.unit.test_sso_verbs.TestConvergeRelandsTheAuthBody.test_an_existing_body_is_re_landed" \
  's|    if repoint and not gate_is_on_hop(pin):|    if True:|' \
  "oauth2proxy.py"
prove "a completed move can never land its body" \
  "tests.unit.test_sso_verbs.TestConvergeRelandsTheAuthBody.test_a_repoint_is_PERMITTED_once_the_gate_has_followed" \
  's|    if repoint and not gate_is_on_hop(pin):|    if repoint:|' \
  "oauth2proxy.py"

# T148: and the empty-hop rule, which is caddy.hops' own and which this guard is
# the second site to need. Dropping it reports a body carrying NO upstream as a
# refused repoint, in a sentence naming the address it dials — with nothing to
# put there.
prove "a body with no hop is called a repoint" \
  "tests.unit.test_sso_verbs.TestConvergeRelandsTheAuthBody.test_an_existing_body_is_re_landed" \
  's|    repoint = bool(on_disk) and old_hops and old_hops != _caddy_hops.hops(body)|    repoint = bool(on_disk) and old_hops != _caddy_hops.hops(body)|' \
  "oauth2proxy.py"

# T149a/T149b: doctor's copy of the same split. Not "which imperative" any more —
# nobody pastes — but whether the verb the row prescribes will actually RUN:
# on a box where the write permit refuses, "run upgrade-sso" is an instruction
# that declines. Range-addressed: `if not on_pin` recurs further down the file.
prove "doctor prescribes a verb that will decline" \
  "tests.unit.test_sso_foundations.TestAuthBlockDrift.test_a_moved_pin_does_not_prescribe_a_verb_that_will_decline" \
  '/^def _auth_block_drift/,/^def _abandoned_hop/s|    if not on_pin and old and old != caddy.hops(want):|    if False:|' \
  "oauth2proxy.py"
prove "doctor calls every ordinary drift a refused repoint" \
  "tests.unit.test_sso_foundations.TestAuthBlockDrift.test_a_stale_copy_is_named_with_its_path" \
  '/^def _auth_block_drift/,/^def _abandoned_hop/s|    if not on_pin and old and old != caddy.hops(want):|    if True:|' \
  "oauth2proxy.py"
prove "doctor calls a hopless body a refused repoint" \
  "tests.unit.test_sso_foundations.TestAuthBlockDrift.test_a_body_with_no_hop_is_not_called_a_repoint" \
  '/^def _auth_block_drift/,/^def _abandoned_hop/s|    if not on_pin and old and old != caddy.hops(want):|    if not on_pin and old != caddy.hops(want):|' \
  "oauth2proxy.py"

# T149: THE ORDERING, and the highest-severity row in this block. Forcing the
# manager read to lose puts the reader back to file-first — and on a box where
# the operator removed the fragment without a daemon-reload, the unit is still
# loaded and still HOLDING. A file-first reader answers "no reservation here",
# permits the write, reloads, and systemd drops the descriptor and binds nothing
# in its place: VIDE releasing the fleet's authorization hop by its own hand,
# out of the one function written to prevent that.
prove "the file outranks the manager about the reservation" \
  "tests.unit.test_sso_foundations.TestTheReservationReaderDecidesPresenceOnDisk.test_a_removed_fragment_that_is_still_loaded_still_refuses" \
  's|    if loaded:|    if False:|' \
  "oauth2proxy.py"

# T150/T151: the tie-break, both signs. Permitting on an unreadable manager is
# the fail-open half; refusing on an absent unit is the other, and it would
# refuse every FIRST SSO INSTALL and then die at the enable that follows.
prove "an unreadable manager permits the move" \
  "tests.unit.test_sso_foundations.TestTheReservationReaderDecidesPresenceOnDisk.test_an_installed_unit_the_manager_will_not_describe_is_unknown" \
  's|    return None if _reservation_unit_present() else \[\]|    return []|' \
  "oauth2proxy.py"
prove "a first install is refused its own reservation" \
  "tests.unit.test_sso_foundations.TestTheReservationReaderDecidesPresenceOnDisk.test_a_first_install_has_no_reservation_and_permits_the_write" \
  's|    return None if _reservation_unit_present() else \[\]|    return None|' \
  "oauth2proxy.py"

# T152/T153: the presence predicate's two holes. `is_file()` reads a MASKED unit
# — a symlink to /dev/null — as "no reservation here", and on this unit masking
# does not switch the gate off, it gives the address away. A content test reads
# an unreadable or zero-byte fragment the same way, and `_read` maps every
# OSError to "" — so both land on the single answer that PERMITS a move.
prove "a masked reservation reads as no reservation" \
  "tests.unit.test_sso_foundations.TestTheReservationReaderDecidesPresenceOnDisk.test_a_masked_unit_is_present_not_absent" \
  's|    return p.exists() or p.is_symlink()|    return p.is_file()|' \
  "oauth2proxy.py"
prove "an unreadable fragment reads as no reservation" \
  "tests.unit.test_sso_foundations.TestTheReservationReaderDecidesPresenceOnDisk.test_an_empty_fragment_reads_as_present_and_refuses" \
  's|    return p.exists() or p.is_symlink()|    return bool(_read(p))|' \
  "oauth2proxy.py"

# T154/T155: the CASE-2 gate — the only permit in gate_is_on_hop an attacker can
# reach. `certain == {0}` is not attacker-reachable (SO_REUSEPORT needs a
# matching effective uid and the unit carries no ReusePort=); `certain ==
# {proxy_uid}` is reachable by exactly one account, the gate itself, which is
# the one identity on the box with a pre-authentication surface. Both rows must
# name a test that passes `identities=` — the parity row cannot serve here,
# because bare_host's default `user_uid` is None and CASE 2 is then
# unsatisfiable in both signs.
prove "any account holding a moved pin is accepted as the gate" \
  "tests.unit.test_sso_verbs.TestAGrantMayNotMoveTheFleetsAuthorizationHop.test_a_gate_that_bound_a_moved_pin_itself_is_not_a_permit" \
  's|    if loaded_reservation() != \[\]:|    if False:|' \
  "oauth2proxy.py"
prove "the un-migrated box loses its permit entirely" \
  "tests.unit.test_sso_verbs.TestAGrantMayNotMoveTheFleetsAuthorizationHop.test_the_unmigrated_box_where_the_proxy_holds_the_pin_is_permitted" \
  's|    if loaded_reservation() != \[\]:|    if True:|' \
  "oauth2proxy.py"

# T156/T157: holder ATTRIBUTION, both signs. Never claiming "ours" puts the row
# back to accusing this box's own PID-1 reservation of squatting on the state
# the refusal deliberately parks operators in; always claiming it exonerates a
# real stranger.
prove "the box's own reservation is accused of squatting" \
  "tests.unit.test_sso_foundations.TestTheAbandonedHop.test_the_boxs_own_reservation_is_not_reported_as_a_squatter" \
  's|    if (loaded is not None and _covers_port(loaded, port)|    if (False|' \
  "oauth2proxy.py"
prove "a stranger on the abandoned hop is called our own gate" \
  "tests.unit.test_sso_foundations.TestTheAbandonedHop.test_a_stranger_on_the_abandoned_address_is_still_named_as_one" \
  's|    if (loaded is not None and _covers_port(loaded, port)|    if (True or (loaded is not None and _covers_port(loaded, port))|' \
  "oauth2proxy.py"

# T158: THE INVERSION HopHolders WAS SPLIT APART TO PREVENT. `on_hop` includes
# `possible` — the `::` bucket — and a v6only bind there needs no privilege at
# all. Keying the REASSURING arm on it lets any local account flip an open-door
# row into a this-is-fine row by binding [::]:<old>.
prove "an unprivileged v6 bind buys the reassuring sentence" \
  "tests.unit.test_sso_foundations.TestTheAbandonedHop.test_a_v6only_squatter_cannot_buy_the_reassuring_sentence" \
  's|            and set(holders.certain) == {0}):|            and bool(holders.on_hop)):|' \
  "oauth2proxy.py"

# T159: an unreadable /proc decides. The row then prints "which NOTHING is
# holding: any local account can bind it" from a measurement that never
# happened — the same open-door claim out of a failed read that T138 covers one
# function away. Range-addressed: three `if holders is None:` in this file.
prove "an unreadable kernel is reported as an open door" \
  "tests.unit.test_sso_foundations.TestTheAbandonedHop.test_an_unreadable_kernel_makes_no_claim_in_either_direction" \
  '/^def _who_holds/,/^def _gate_on_pin/s|    if holders is None:|    if False:|' \
  "oauth2proxy.py"

# T160/T161: the remedy's DIRECTION, both signs, over one row that asserts both.
# "Put VIDE_SSO_PROXY_PORT back" is the cheap no-outage direction only while the
# gate is still on the old address; on a box where the move LANDED it marches
# the reservation off an address it is now holding — the row prescribing the
# outage it exists to prevent. Range-addressed: `if on_pin:` is unique today but
# the file has two other on_pin branches within a hundred lines.
prove "a landed move is told to walk the pin back" \
  "tests.unit.test_sso_foundations.TestTheAbandonedHop.test_a_landed_move_is_not_told_to_walk_the_pin_back" \
  '/^def _abandoned_hop/,/^def _stale_authz_bodies/s|    if on_pin:|    if False:|' \
  "oauth2proxy.py"
prove "a parked box loses the no-outage direction" \
  "tests.unit.test_sso_foundations.TestTheAbandonedHop.test_a_landed_move_is_not_told_to_walk_the_pin_back" \
  '/^def _abandoned_hop/,/^def _stale_authz_bodies/s|    if on_pin:|    if True:|' \
  "oauth2proxy.py"

# T162: several stale hops collapse back to one. emit_auth_block renders exactly
# one address, so two means the file was hand-edited — and the single-number
# remedy has no correct value there. A remedy still true after the operator
# follows it is the one shape this module forbids outright.
prove "a hand-merged auth block is given a one-number remedy" \
  "tests.unit.test_sso_foundations.TestTheAbandonedHop.test_several_stale_hops_name_them_all_and_ask_for_a_hand" \
  's|    if len(stale) > 1:|    if False:|' \
  "oauth2proxy.py"

# T163-T167: the sensor. It closes the one state in which doctor ASSERTED
# cleanliness over a live authorization bypass — a per-instance body dialling a
# free loopback port while every reservation row is green and `doctor --quiet`,
# the documented cron hook, exits 0.
prove "doctor stops reading the instance bodies" \
  "tests.unit.test_sso_foundations.TestDoctorSeesABodyThatDialsAnotherHop.test_a_body_that_dials_another_address_is_red_and_names_the_instance" \
  's|    off = sorted(u for u, hops in bodies.items() if hops - {pin})|    off = []|' \
  "oauth2proxy.py"
prove "the body row reddens a fleet that agrees with its pin" \
  "tests.unit.test_sso_foundations.TestDoctorSeesABodyThatDialsAnotherHop.test_a_fleet_whose_bodies_agree_with_the_pin_says_nothing" \
  's|    if not off:|    if False:|' \
  "oauth2proxy.py"
# …and the tombstone rule, which is not decoration: a destroyed instance's body
# carries no upstream, and if absence read as disagreement this row would redden
# every box that ever ran `vide destroy`.
prove "a tombstoned body is read as a disagreement" \
  "tests.unit.test_sso_foundations.TestDoctorSeesABodyThatDialsAnotherHop.test_a_tombstoned_body_carries_no_hop_and_is_not_a_disagreement" \
  's|    off = sorted(u for u, hops in bodies.items() if hops - {pin})|    off = sorted(u for u, hops in bodies.items() if hops != {pin})|' \
  "oauth2proxy.py"
# The fail-OPEN half: these files are 0640 root:vide-proxy, so a non-root doctor
# reads none of them, and "no hops found" would be indistinguishable from "every
# hop agrees" — silence reading as health, in the row that exists to be
# fail-closed.
prove "bodies that could not be read are counted as agreement" \
  "tests.unit.test_sso_foundations.TestDoctorSeesABodyThatDialsAnotherHop.test_an_unlistable_directory_is_said_and_is_not_agreement" \
  's|    if unreadable:|    if False:|' \
  "oauth2proxy.py"
# T181: …and the half a per-FILE arm cannot reach. `<sso_dir>/caddy` is 0750
# root:vide-proxy and doctor is needs_root=False, so the ordinary non-root run
# cannot LIST it — and Path.glob swallows exactly that error and yields nothing,
# which the row then read as "every body agrees". Anyone who can list a 0750
# directory can read the 0640 files in it, so this is the ONLY shape the
# fail-open state takes on a shipped box.
prove "an unlistable authorization directory reads as agreement" \
  "tests.unit.test_sso_foundations.TestDoctorSeesABodyThatDialsAnotherHop.test_an_unlistable_directory_is_said_and_is_not_agreement" \
  's|        return {}, \["<the authorization directory could not be listed>"\]|        return {}, []|' \
  "sso.py"
# T182: one unreadable sibling may not discard the evidence already collected.
prove "one unreadable body hides every other one" \
  "tests.unit.test_sso_foundations.TestDoctorSeesABodyThatDialsAnotherHop.test_a_readable_body_still_counts_when_a_sibling_is_not" \
  's|    off = sorted(u for u, hops in bodies.items() if hops - {pin})|    off = [] if unreadable else sorted(u for u, hops in bodies.items() if hops - {pin})|' \
  "oauth2proxy.py"
prove "the body row fires where its own remedy is refused" \
  "tests.unit.test_sso_foundations.TestDoctorSeesABodyThatDialsAnotherHop.test_it_is_silent_when_the_gate_is_not_on_the_pin" \
  '/^def _stale_authz_bodies/,/^def _proxy_pings/s|    if not on_pin:|    if False:|' \
  "oauth2proxy.py"

# T168: the sensor is computed and then thrown away — the exact shape of the
# defect it was written to close, since the lines would still print while
# `doctor --quiet` exits 0 and cron stays quiet.
prove "the body row is printed but not counted" \
  "tests.unit.test_sso_verbs.TestTheUnmigratedBoxWalksToMigrated.test_a_half_applied_move_is_not_green" \
  's|    ok = ok and body_ok|    ok = ok and True|' \
  "oauth2proxy.py"

# T169: the enable guard. The manager-first refusal can decline with NO fragment
# on disk, and `systemctl enable` on an absent unit is a hard error on every
# supported systemd — so an ungated enable turns a deliberate, recoverable
# refusal ("nothing was written; the rest of this run continues") into a dead
# run. Range-addressed: upgrade_sso carries the same guard.
prove "a refused converge dies at the enable that follows" \
  "tests.unit.test_sso_verbs.TestTheReservationUnitIsActuallyRendered.test_a_refused_converge_does_not_die_at_the_enable" \
  '/^def converge_proxy/,/^def rotate_sso/s|    if ex.dry_run or _reservation_unit_present():|    if True:|' \
  "oauth2proxy.py"

# T172/T173: …and the SECOND way the same box killed the same run, three
# statements further down, which §16d-b found on a real manager as `exit 5`
# while every unit row stayed green. The service Requires= the socket unit, so
# with the fragment gone systemd cannot resolve it. Both signs, because the
# tolerance is narrow by design: swallow it when the fragment really is absent,
# and never otherwise.
prove "an unresolvable Requires= still kills a refused converge" \
  "tests.unit.test_sso_verbs.TestTheReservationUnitIsActuallyRendered.test_a_refused_converge_survives_an_unresolvable_requires" \
  's|        if _reservation_unit_present():|        if True:|' \
  "oauth2proxy.py"
prove "every failing gate start is swallowed, not just this one" \
  "tests.unit.test_sso_verbs.TestTheReservationUnitIsActuallyRendered.test_a_failing_enable_still_takes_the_run_down_normally" \
  's|        if _reservation_unit_present():|        if False:|' \
  "oauth2proxy.py"

# T170: `vide info` and the property that RETIRED a caveat rather than softening
# it. This verb used to hand over the whole auth body, so on a moved-pin box the
# text it printed named an address nothing held and pasting it published the
# fleet's login flow under the operator's real TLS — hence the DO NOT RE-PASTE
# warning these rows used to guard in both signs.
#
# The warning is gone because its subject is: the emitted text is a site header
# and an import, and names no port at all. That is a claim about the artifact,
# so it is mutated at the artifact — put a hop back into what the operator
# pastes and the row that asserts `hops(...) == set()` must go red. If it does
# not, the caveat was retired on a promise nothing checks.
prove "the pasted block names a hop again" \
  "tests.unit.test_sso_cli.TestInfoUsesRecordedFqdn.test_a_moved_pin_box_needs_no_caveat_because_the_block_carries_no_hop" \
  's|    import {sso_dir}/caddy/auth.caddy|    reverse_proxy 127.0.0.1:4180|' \
  "caddy.py"

# T174-T176: pin_is_served, whose only reader before these rows was `vide info`'s
# fixture — and that fixture answers None from `user_uid`, so the proxy-uid arm
# (the entire reason this predicate is separate from gate_is_on_hop) was
# unreachable in every test that touched it. Same shape as the CASE-2 gate this
# release already had to repair once. Range-addressed: gate_is_on_hop ends on a
# byte-identical line, and `if holders is None:` occurs four times in the file.
prove "the gate holding the pin itself is not a demonstration" \
  "tests.unit.test_sso_foundations.TestWhetherThePinIsBeingServed.test_the_converged_but_not_restarted_box_is_served_by_the_proxy" \
  '/^def pin_is_served/,/^def _pin_served/s|    return proxy_uid is not None and certain == {proxy_uid}|    return False|' \
  "oauth2proxy.py"
# `0 in certain` instead of `== {0}`: root AND somebody else then reads as a
# demonstration, and a second listener sharing the port had to share root's
# effective uid to get there. That is a state to alarm about, not to paste over.
prove "root sharing the pin with somebody else is pasted over" \
  "tests.unit.test_sso_foundations.TestWhetherThePinIsBeingServed.test_root_plus_somebody_else_is_not_a_demonstration" \
  's|    if certain == {0}:|    if 0 in certain:|' \
  "oauth2proxy.py"
prove "an unreadable kernel is read as a served pin" \
  "tests.unit.test_sso_foundations.TestWhetherThePinIsBeingServed.test_an_unreadable_kernel_is_not_a_demonstration" \
  '/^def pin_is_served/,/^def _pin_served/s|    if holders is None:|    if False:|' \
  "oauth2proxy.py"

# T177: the OTHER sign of the enable guard, and the one that keeps a preview
# honest. A dry run writes nothing, so on a first install the fragment is
# legitimately absent at that instant while the real run creates and enables it
# moments later — testing the file alone drops the step from every preview of
# the commonest path there is.
prove "a dry-run first install previews no reservation enable" \
  "tests.unit.test_sso_verbs.TestTheReservationUnitIsActuallyRendered.test_a_dry_run_first_install_still_previews_the_enable" \
  '/^def converge_proxy/,/^def rotate_sso/s|    if ex.dry_run or _reservation_unit_present():|    if _reservation_unit_present():|' \
  "oauth2proxy.py"

# T178/T179: the promise in proxy_health's own docstring — a diagnostic reports
# and does not die — which nothing called with an unreadable pin until now.
# Every other 99999 fixture in the suite drives a single row directly, so the
# section's guard was the one clause its docstring described and no test reached.
prove "an unreadable pin reads as a healthy fleet" \
  "tests.unit.test_sso_verbs.TestDoctorSurvivesTheThingItDiagnoses.test_an_unreadable_pin_is_reported_rather_than_raised" \
  's|        return False, lines|        return True, lines|' \
  "oauth2proxy.py"
prove "doctor dies on the very pin it exists to diagnose" \
  "tests.unit.test_sso_verbs.TestDoctorSurvivesTheThingItDiagnoses.test_an_unreadable_pin_is_reported_rather_than_raised" \
  '/^def proxy_health/,/^def _abandoned_hop/s|    except ConfigError as e:|    except UnavailableError as e:|' \
  "oauth2proxy.py"

# T180: the suffix filter, which arrived with the switch from glob() to
# iterdir() and was pinned by nothing. caddy.hops finds a 127.0.0.1:<port> in
# ANY text, so a `.bak`, an editor swap file or the operator's own notes beside
# the bodies would redden a perfectly healthy fleet — in the row `doctor
# --quiet` mails from cron, which is where a false positive costs the most.
prove "any file beside the bodies is read as a body" \
  "tests.unit.test_sso_foundations.TestDoctorSeesABodyThatDialsAnotherHop.test_a_file_that_is_not_a_body_is_not_read_as_one" \
  's|        if f.suffix != ".caddy" or f.name == "auth.caddy":|        if f.name == "auth.caddy":|' \
  "sso.py"

# T181/T182: the https refusal in the LATEST-TAG RESOLVER, which download() had
# and this path did not. Found by re-auditing the published tree against its own
# docs: threat-model.md states the refusal with no exception, and this was the
# exception. Reachable by configuration alone — both release URLs are .env rows.
# Two rows because the two callers reach `target` differently (oauth2-proxy passes
# `url=`, code-server falls through to cfg), and a guard placed on one side of the
# `url or cfg...` fallback would cover only one of them while looking complete.
prove "the latest-tag resolver fetches a plain-http release URL" \
  "tests.unit.test_net.TestLatestTagResolver.test_a_non_https_url_is_refused_before_any_request" \
  's|        if urllib.parse.urlsplit(target).scheme != "https":|        if False:|' \
  "net.py"
prove "…and the same gap by way of the config default" \
  "tests.unit.test_net.TestLatestTagResolver.test_the_refusal_also_covers_the_url_that_comes_from_config" \
  's|        if urllib.parse.urlsplit(target).scheme != "https":|        if False:|' \
  "net.py"

printf '\nPASS=%d FAIL=%d\n' "$pass" "$fail"
(( fail == 0 ))
