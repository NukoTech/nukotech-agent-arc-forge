#!/usr/bin/env python3
"""Assert a pytest JUnit XML report has the expected passed and skipped counts."""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def _testcases(root: ET.Element) -> list[ET.Element]:
    return [element for element in root.iter("testcase")]


def summarize(path: Path) -> tuple[int, int, int, int, int]:
    root = ET.parse(path).getroot()
    cases = _testcases(root)
    if not cases:
        raise ValueError("no testcase elements")
    # Count <testcase> nodes, not the suite tests= attribute. pytest 9's
    # unittest subtests inflate tests= (and nested suites) without extra
    # testcase elements, so summing suite totals disagrees with the
    # "N passed, M skipped" line.
    tests = len(cases)
    skipped = failures = errors = 0
    for case in cases:
        if case.find("skipped") is not None:
            skipped += 1
        elif case.find("failure") is not None:
            failures += 1
        elif case.find("error") is not None:
            errors += 1
    passed = tests - skipped - failures - errors
    return passed, skipped, failures, errors, tests


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("junit_xml", type=Path)
    parser.add_argument("passed", type=int)
    parser.add_argument("skipped", type=int)
    args = parser.parse_args(argv)

    try:
        passed, skipped, failures, errors, tests = summarize(args.junit_xml)
    except (OSError, ET.ParseError, ValueError) as exc:
        print(f"assert_pytest_counts: could not read {args.junit_xml}: {exc}", file=sys.stderr)
        return 2

    print(
        f"assert_pytest_counts: passed={passed} skipped={skipped} "
        f"failures={failures} errors={errors} tests={tests}"
    )
    if failures or errors:
        print("assert_pytest_counts: report contains failures or errors", file=sys.stderr)
        return 1
    if passed != args.passed or skipped != args.skipped:
        print(
            f"assert_pytest_counts: expected passed={args.passed} skipped={args.skipped}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
