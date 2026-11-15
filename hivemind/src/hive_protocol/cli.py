"""Command-line boundary for the disposable Hive reference turn."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable

from .core import ProtocolError
from .distribution import (
    build_governance_release,
    rollback_governance_release,
    stage_governance_release,
)
from .m003 import promote_turn, propose_turn, retrieve_next_turn, review_turn
from .observer import observe_repositories
from .turn import (
    _load_marker,
    _process_namespace,
    consume_turn,
    prepare_turn,
    rollback_turn,
    route_turn,
)


def _emit(document: dict[str, Any]) -> None:
    print(json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hive-lab",
        description="Run a disposable, signed LAB organizational turn.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare", help="create a signed work envelope")
    prepare.add_argument("--lab-root", type=Path, required=True)
    prepare.add_argument("--commit", required=True)

    for name, help_text in (
        ("route", "route the envelope through the authorized mailbox"),
        ("consume", "consume the envelope and acknowledge state"),
        ("propose", "stage signed persona and surface memory proposals"),
        ("review", "validate proposals and detect conflicts without PRIME writes"),
        ("promote", "promote only independently approved non-private knowledge"),
        ("retrieve", "verify retrieval during the next turn"),
    ):
        command = subparsers.add_parser(name, help=help_text)
        command.add_argument("--run-dir", type=Path, required=True)

    rollback = subparsers.add_parser("rollback", help="remove disposable operational state")
    rollback.add_argument("--run-dir", type=Path, required=True)
    rollback.add_argument("--lab-root", type=Path, required=True)

    observe = subparsers.add_parser("observe", help="observe repository refs without Git mutation")
    observe.add_argument("--roster", type=Path, required=True)
    observe.add_argument("--output-dir", type=Path, required=True)
    observe.add_argument("--git-helper", type=Path, required=True)

    release_build = subparsers.add_parser(
        "release-build", help="build a signed, non-private LAB governance release"
    )
    release_build.add_argument("--run-dir", type=Path, required=True)
    release_build.add_argument("--version", required=True)
    release_build.add_argument("--tree", required=True)

    for name, help_text in (
        ("release-stage", "verify and stage a pinned release without activation"),
        ("release-rollback", "remove the staged release and restore the prior pin"),
    ):
        command = subparsers.add_parser(name, help=help_text)
        command.add_argument("--run-dir", type=Path, required=True)
        command.add_argument("--version", required=True)
    return parser


def _run(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    commands: dict[str, Callable[[], dict[str, Any]]] = {
        "prepare": lambda: prepare_turn(args.lab_root, args.commit),
        "route": lambda: route_turn(args.run_dir),
        "propose": lambda: propose_turn(args.run_dir),
        "review": lambda: review_turn(args.run_dir),
        "promote": lambda: promote_turn(args.run_dir),
        "retrieve": lambda: retrieve_next_turn(args.run_dir),
        "rollback": lambda: rollback_turn(args.run_dir, args.lab_root),
        "observe": lambda: observe_repositories(args.roster, args.output_dir, args.git_helper),
        "release-build": lambda: build_governance_release(
            args.run_dir,
            _load_marker(args.run_dir),
            args.version,
            args.tree,
            _process_namespace(),
        ),
        "release-stage": lambda: stage_governance_release(
            args.run_dir,
            _load_marker(args.run_dir),
            args.version,
            _process_namespace(),
        ),
        "release-rollback": lambda: rollback_governance_release(
            args.run_dir,
            _load_marker(args.run_dir),
            args.version,
            _process_namespace(),
        ),
    }
    if args.command == "consume":
        return consume_turn(args.run_dir)
    return commands[args.command](), 0


def main() -> int:
    args = _parser().parse_args()
    try:
        result, exit_status = _run(args)
    except ProtocolError as exc:
        _emit({"outcome": "REFUSED", "reason_code": exc.code, "detail": exc.detail})
        return exc.exit_status
    except (OSError, ValueError) as exc:
        _emit({"outcome": "REFUSED", "reason_code": "RUNTIME_ERROR", "detail": str(exc)})
        return 2
    _emit(result)
    return exit_status


if __name__ == "__main__":
    sys.exit(main())
