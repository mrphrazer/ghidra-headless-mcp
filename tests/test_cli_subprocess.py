from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from ghidra_headless_mcp import __version__

ROOT = Path(__file__).resolve().parents[1]


def _pythonpath_env() -> dict[str, str]:
    env = os.environ.copy()
    current = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(ROOT) if not current else f"{ROOT}:{current}"
    return env


def _encode_mcp_messages(messages: list[dict[str, Any]]) -> bytes:
    frames: list[bytes] = []
    for message in messages:
        body = json.dumps(message, sort_keys=True).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        frames.append(header + body)
    return b"".join(frames)


def _encode_json_lines(messages: list[dict[str, Any]]) -> bytes:
    return ("\n".join(json.dumps(message, sort_keys=True) for message in messages) + "\n").encode(
        "utf-8"
    )


def _decode_mcp_messages(data: bytes) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    offset = 0
    while offset < len(data):
        header_end = data.find(b"\r\n\r\n", offset)
        if header_end < 0:
            raise AssertionError("missing MCP header terminator in subprocess output")
        header_blob = data[offset:header_end].decode("ascii")
        content_length: int | None = None
        for line in header_blob.split("\r\n"):
            name, sep, value = line.partition(":")
            if not sep:
                raise AssertionError(f"invalid MCP header line: {line!r}")
            if name.lower() == "content-length":
                content_length = int(value.strip())
        if content_length is None:
            raise AssertionError("missing Content-Length header in subprocess output")

        body_start = header_end + 4
        body_end = body_start + content_length
        body = data[body_start:body_end]
        if len(body) != content_length:
            raise AssertionError("truncated MCP body in subprocess output")
        payloads.append(json.loads(body))
        offset = body_end
    return payloads


def _decode_json_lines(data: bytes) -> list[dict[str, Any]]:
    return [json.loads(line) for line in data.decode("utf-8").splitlines() if line.strip()]


def test_cli_version_reports_package_version() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "ghidra_headless_mcp", "--version"],
        capture_output=True,
        cwd=ROOT,
        env=_pythonpath_env(),
        check=True,
        text=True,
    )
    assert proc.stdout.strip() == f"__main__.py {__version__}"


def test_cli_stdio_fake_backend_round_trip() -> None:
    request_bytes = _encode_mcp_messages(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-03-26"},
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "health.ping", "arguments": {}},
            },
            {"jsonrpc": "2.0", "id": 3, "method": "shutdown", "params": {}},
        ]
    )
    proc = subprocess.run(
        [sys.executable, "-m", "ghidra_headless_mcp", "--fake-backend"],
        input=request_bytes,
        capture_output=True,
        cwd=ROOT,
        env=_pythonpath_env(),
        check=True,
    )
    lines = _decode_mcp_messages(proc.stdout)
    assert len(lines) == 3
    assert lines[0]["result"]["serverInfo"]["name"] == "ghidra_headless_mcp"
    assert lines[0]["result"]["protocolVersion"] == "2025-03-26"
    assert lines[1]["result"]["structuredContent"]["status"] == "ok"
    assert lines[2]["result"] == {"ok": True}


def test_cli_stdio_fake_backend_round_trip_json_lines() -> None:
    request_bytes = _encode_json_lines(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-03-26"},
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "health.ping", "arguments": {}},
            },
            {"jsonrpc": "2.0", "id": 3, "method": "shutdown", "params": {}},
        ]
    )
    proc = subprocess.run(
        [sys.executable, "-m", "ghidra_headless_mcp", "--fake-backend"],
        input=request_bytes,
        capture_output=True,
        cwd=ROOT,
        env=_pythonpath_env(),
        check=True,
    )
    lines = _decode_json_lines(proc.stdout)
    assert len(lines) == 3
    assert lines[0]["result"]["serverInfo"]["name"] == "ghidra_headless_mcp"
    assert lines[0]["result"]["protocolVersion"] == "2025-03-26"
    assert lines[1]["result"]["structuredContent"]["status"] == "ok"
    assert lines[2]["result"] == {"ok": True}


@pytest.mark.socket
def test_cli_tcp_fake_backend_round_trip() -> None:
    try:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            host, port = sock.getsockname()
    except PermissionError as exc:
        pytest.skip(f"localhost sockets are unavailable in this environment: {exc}")

    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "ghidra_headless_mcp",
            "--fake-backend",
            "--transport",
            "tcp",
            "--host",
            host,
            "--port",
            str(port),
        ],
        cwd=ROOT,
        env=_pythonpath_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                with socket.create_connection((host, port), timeout=0.2) as client:
                    client.sendall(
                        (
                            json.dumps(
                                {
                                    "jsonrpc": "2.0",
                                    "id": 1,
                                    "method": "tools/call",
                                    "params": {"name": "health.ping", "arguments": {}},
                                }
                            )
                            + "\n"
                        ).encode("utf-8")
                    )
                    response = client.recv(65536).decode("utf-8").strip()
                    payload = json.loads(response)
                    assert payload["result"]["structuredContent"]["status"] == "ok"
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise AssertionError("tcp server did not become ready")
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_cli_invalid_install_dir_returns_tool_error() -> None:
    pytest.importorskip("pyghidra")
    request_bytes = _encode_mcp_messages(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "ghidra.info", "arguments": {}},
            },
            {"jsonrpc": "2.0", "id": 2, "method": "shutdown", "params": {}},
        ]
    )
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "ghidra_headless_mcp",
            "--ghidra-install-dir",
            "/definitely/not/ghidra",
        ],
        input=request_bytes,
        capture_output=True,
        cwd=ROOT,
        env=_pythonpath_env(),
        check=True,
    )
    lines = _decode_mcp_messages(proc.stdout)
    assert lines[0]["result"]["isError"] is True
    assert "error" in lines[0]["result"]["structuredContent"]
    assert lines[1]["result"] == {"ok": True}
