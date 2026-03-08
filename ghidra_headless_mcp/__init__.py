"""Ghidra Headless MCP server."""

from ._version import __version__
from .backend import GhidraBackend, GhidraBackendError
from .fake_ghidra import FakeGhidraBackend
from .server import JsonRpcError, SimpleMcpServer

__all__ = [
    "FakeGhidraBackend",
    "GhidraBackend",
    "GhidraBackendError",
    "JsonRpcError",
    "SimpleMcpServer",
    "__version__",
]
