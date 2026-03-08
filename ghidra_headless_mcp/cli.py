"""CLI runner for the Ghidra Headless MCP server."""

from __future__ import annotations

import argparse
import os
import sys
from types import ModuleType
from typing import Any

from ._version import __version__
from .backend import GhidraBackend
from .fake_ghidra import FakeGhidraBackend
from .server import SimpleMcpServer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Ghidra Headless MCP server")
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "tcp"],
        default="stdio",
        help="Transport mode. stdio is default for MCP clients.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host when using TCP transport")
    parser.add_argument("--port", type=int, default=8765, help="Port when using TCP transport")
    parser.add_argument(
        "--fake-backend",
        action="store_true",
        help="Use a local fake backend for tests and smoke runs.",
    )
    parser.add_argument(
        "--ghidra-install-dir",
        help="Override GHIDRA_INSTALL_DIR for the real PyGhidra-backed server.",
    )
    parser.add_argument(
        "--deterministic",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable deterministic process-level startup behavior. Default: true.",
    )
    return parser


def load_pyghidra_module() -> ModuleType:
    try:
        import pyghidra  # pylint: disable=import-outside-toplevel
    except ImportError as exc:  # pragma: no cover - depends on system environment
        raise RuntimeError(
            "pyghidra is not available. Install it or run with --fake-backend."
        ) from exc
    return pyghidra


def resolve_install_dir(explicit: str | None) -> str:
    install_dir = explicit or os.environ.get("GHIDRA_INSTALL_DIR")
    if install_dir:
        return install_dir
    raise RuntimeError(
        "GHIDRA_INSTALL_DIR is required for the real backend. Set the environment variable or pass --ghidra-install-dir."
    )


def build_backend(args: argparse.Namespace) -> Any:
    if args.fake_backend or os.environ.get("GHIDRA_HEADLESS_MCP_FAKE_BACKEND") == "1":
        return FakeGhidraBackend(deterministic=args.deterministic)
    install_dir = resolve_install_dir(args.ghidra_install_dir)
    pyghidra_module = load_pyghidra_module()
    return GhidraBackend(
        pyghidra_module,
        install_dir=install_dir,
        deterministic=args.deterministic,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    backend = build_backend(args)
    server = SimpleMcpServer(backend)

    if args.transport == "tcp":
        print(
            f"ghidra_headless_mcp listening on tcp://{args.host}:{args.port}",
            file=sys.stderr,
            flush=True,
        )
        server.serve_tcp(args.host, args.port)
        return 0

    server.serve_stdio()
    return 0
