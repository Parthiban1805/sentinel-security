"""Sentinel command-line entry point."""

import argparse
from collections.abc import Sequence

from sentinel import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel", description="Sentinel security system")
    parser.add_argument("--version", action="version", version=f"sentinel {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    build_parser().parse_args(argv)
    return 0
