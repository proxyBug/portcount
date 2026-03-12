from __future__ import annotations

import argparse
from pathlib import Path

from .collectors import collect_inventory
from .formatters import format_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portcount",
        description="Generate a clean inventory of listening ports, services, and containers on a Linux host.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="scan the local host and render an inventory")
    scan.add_argument(
        "--format",
        choices=("markdown", "json", "table"),
        default="markdown",
        help="output format (default: markdown)",
    )
    scan.add_argument("--output", help="write the rendered report to a file instead of stdout")
    scan.add_argument("--no-docker", dest="docker", action="store_false", help="skip Docker inspection")
    scan.add_argument("--no-systemd", dest="systemd", action="store_false", help="skip systemd unit inference")
    scan.set_defaults(command="scan", docker=True, systemd=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 1

    report = collect_inventory(include_docker=args.docker, include_systemd=args.systemd)
    rendered = format_report(report, args.format)

    if args.output:
        output_path = Path(args.output)
        output_path.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")

    return 0
