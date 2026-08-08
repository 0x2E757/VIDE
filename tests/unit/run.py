"""Unit-tier runner: stdlib unittest discovery with the repo's one reporting
dialect (`  ok   ...` / `  FAIL ...` + a PASS=/FAIL= tally), so a human or a
parser reads this tier exactly like every other gate in the repo.

No pytest, no dependencies — the suite must run on a stock system python3.
"""
from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests" / "unit"))


class _Result(unittest.TextTestResult):
    def addSuccess(self, test):  # noqa: N802
        super(unittest.TextTestResult, self).addSuccess(test)
        print(f"  ok   {test.id()}")

    def addFailure(self, test, err):  # noqa: N802
        super(unittest.TextTestResult, self).addFailure(test, err)
        print(f"  FAIL {test.id()}")

    def addError(self, test, err):  # noqa: N802
        super(unittest.TextTestResult, self).addError(test, err)
        print(f"  FAIL {test.id()} (error)")

    def addSubTest(self, test, subtest, err):  # noqa: N802
        # A subTest failure used to print NOTHING while still counting in FAIL=,
        # for the same reason addSkip above was wrong: unittest routes subtests
        # through their OWN hook, and overriding addFailure/addError does not
        # reach them. So a run could end `PASS=708 FAIL=4` with not one `FAIL`
        # line anywhere in its output — every grep a human or a script runs over
        # this tier came back clean while four rows were red. The tally knew; the
        # dialect this file exists to speak did not say it.
        super(unittest.TextTestResult, self).addSubTest(test, subtest, err)
        if err is not None:
            print(f"  FAIL {subtest.id()}")

    def addSkip(self, test, reason):  # noqa: N802
        # A skip used to print NOTHING and be counted in PASS, because the tally
        # was testsRun - failed. So a row that could not run looked exactly like a
        # row that ran and held — in the tier whose number this repo quotes as
        # evidence. A skip is not a pass; it is a row that said why it could not
        # be evidence, and the reason is the whole value of it.
        super(unittest.TextTestResult, self).addSkip(test, reason)
        print(f"  SKIP {test.id()} ({reason})")


def main() -> int:
    started = time.monotonic()
    loader = unittest.TestLoader()
    suite = loader.discover(str(REPO / "tests" / "unit"), pattern="test_*.py")
    runner = unittest.TextTestRunner(resultclass=_Result, verbosity=0,
                                     stream=open("/dev/null", "w"))
    result = runner.run(suite)
    failed = len(result.failures) + len(result.errors)
    skipped = len(result.skipped)
    passed = result.testsRun - failed - skipped
    # SKIP= appears only when there are any, so the common line stays byte-stable
    # for the readers that quote it — and cannot be missed when it does appear.
    extra = f" SKIP={skipped}" if skipped else ""
    print(f"\nPASS={passed} FAIL={failed}{extra}  ({time.monotonic() - started:.1f}s)")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
