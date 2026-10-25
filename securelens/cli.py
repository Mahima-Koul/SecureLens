"""SecureLens command line entry point."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .scanner import scan_project


def main() -> int:
    """Run the scan command and display normalized findings and diagnostics."""
    parser = argparse.ArgumentParser(prog="securelens")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="scan a Python project")
    scan_parser.add_argument("project", type=Path)
    args = parser.parse_args()
    if args.command == "scan":
        findings, errors = scan_project(args.project)
        print(json.dumps([finding.model_dump(mode="json") for finding in findings], indent=2))
        for error in errors:
            print(f"ERROR: {error}")
        return 1 if errors else 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
