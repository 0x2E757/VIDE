"""Port registry: read, allocation, the flock, exhaustion."""
from __future__ import annotations

import fcntl
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests" / "unit"))

from fakes import make_config, quiet_reporter  # noqa: E402
from vide import ports  # noqa: E402
from vide.errors import StateError  # noqa: E402
from vide.executor import Executor  # noqa: E402


class TestGetPort(unittest.TestCase):
    def test_reads_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sd = Path(td)
            (sd / "bob.env").write_text("VIDE_PORT=12345\n")
            self.assertEqual(ports.get_port(sd, "bob"), 12345)

    def test_absent_is_none(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(ports.get_port(Path(td), "nobody"))

    def test_malformed_is_none(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sd = Path(td)
            (sd / "bob.env").write_text("GARBAGE\n")
            self.assertIsNone(ports.get_port(sd, "bob"))


class TestChoosePort(unittest.TestCase):
    def test_lowest_free(self) -> None:
        self.assertEqual(ports.choose_port({9797, 9798}, 9797, 9996), 9799)

    def test_exhaustion_is_none(self) -> None:
        self.assertIsNone(ports.choose_port({9797, 9798}, 9797, 9798))


class NonRootExecutor(Executor):
    """A real Executor minus ownership: claim_port passes owner=root:root
    (correct in production, where it runs as root), which chown-fails under
    the unprivileged test uid. Everything else — the real install -d, the
    real atomic same-dir-temp write — still executes."""

    def atomic_write(self, dest, content, *, mode, owner=None):  # type: ignore[override]
        super().atomic_write(dest, content, mode=mode, owner=None)

    def ensure_dir(self, path, *, mode, owner=None):  # type: ignore[override]
        super().ensure_dir(path, mode=mode, owner=None)


class TestClaimPort(unittest.TestCase):
    def _ctx(self, tmp: Path):
        cfg = make_config(tmp, port_base=9797, port_max=9800)
        rep = quiet_reporter()
        ex = NonRootExecutor(dry_run=False, reporter=rep, cfg=cfg)
        return cfg, ex, rep

    def test_reuses_persisted_without_touching_anything(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg, ex, rep = self._ctx(Path(td))
            cfg.state_dir.mkdir(parents=True)
            (cfg.state_dir / "bob.env").write_text("VIDE_PORT=9799\n")
            self.assertEqual(ports.claim_port(cfg, ex, rep, "bob"), 9799)

    def test_allocates_lowest_free_and_persists_the_contract_shape(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg, ex, rep = self._ctx(Path(td))
            with mock.patch.object(ports.system, "listening_ports",
                                   return_value={9797}), \
                 mock.patch.object(ports.system, "port_free",
                                   side_effect=lambda p: p != 9797):
                got = ports.claim_port(cfg, ex, rep, "bob")
            self.assertEqual(got, 9798)
            self.assertEqual((cfg.state_dir / "bob.env").read_text(),
                             "VIDE_PORT=9798\n")

    def test_skips_recorded_ports_of_other_instances(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg, ex, rep = self._ctx(Path(td))
            cfg.state_dir.mkdir(parents=True)
            (cfg.state_dir / "alice.env").write_text("VIDE_PORT=9797\n")
            with mock.patch.object(ports.system, "listening_ports",
                                   return_value=set()), \
                 mock.patch.object(ports.system, "port_free", return_value=True):
                self.assertEqual(ports.claim_port(cfg, ex, rep, "bob"), 9798)

    def test_exhaustion_raises_state_75(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg, ex, rep = self._ctx(Path(td))
            with mock.patch.object(ports.system, "listening_ports",
                                   return_value={9797, 9798, 9799, 9800}), \
                 mock.patch.object(ports.system, "port_free", return_value=False):
                with self.assertRaises(StateError) as cm:
                    ports.claim_port(cfg, ex, rep, "bob")
            self.assertEqual(int(cm.exception.code), 75)

    def test_dry_run_narrates_and_returns_base_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg, _, rep = self._ctx(Path(td))
            ex = Executor(dry_run=True, reporter=rep, cfg=cfg)
            self.assertEqual(ports.claim_port(cfg, ex, rep, "bob"), 9797)
            self.assertFalse(cfg.state_dir.exists(), "a preview wrote state")


class TestPortLock(unittest.TestCase):
    def test_held_lock_times_out_with_state_75(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sd = Path(td)
            # Hold the lock through a second open-file-description: flock locks
            # are per-OFD, so a second open in the SAME process contends —
            # exactly how util-linux flock(1) contends with us.
            fd = os.open(sd / ".portlock", os.O_WRONLY | os.O_CREAT, 0o644)
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                with self.assertRaises(StateError):
                    with ports._port_lock(sd, timeout=0.4):
                        pass
            finally:
                os.close(fd)

    def test_lock_is_released_on_exit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sd = Path(td)
            with ports._port_lock(sd, timeout=1):
                pass
            with ports._port_lock(sd, timeout=1):  # must not time out
                pass


if __name__ == "__main__":
    unittest.main()
