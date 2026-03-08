from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from ghidra_headless_mcp.backend import GhidraBackend
from ghidra_headless_mcp.fake_ghidra import FakeGhidraBackend
from ghidra_headless_mcp.server import SimpleMcpServer


@pytest.fixture
def sample_binary_path() -> str:
    fixtures = Path(__file__).resolve().parent / "fixtures"
    source_path = fixtures / "hello.c"
    binary_path = fixtures / "hello"

    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("no C compiler found (cc/gcc/clang)")

    if not binary_path.exists() or binary_path.stat().st_mtime < source_path.stat().st_mtime:
        subprocess.run(
            [compiler, str(source_path), "-O0", "-g", "-fno-inline", "-o", str(binary_path)],
            check=True,
        )

    return str(binary_path)


@pytest.fixture
def fake_backend() -> FakeGhidraBackend:
    return FakeGhidraBackend()


@pytest.fixture
def fake_server(fake_backend: FakeGhidraBackend) -> SimpleMcpServer:
    return SimpleMcpServer(fake_backend)


@pytest.fixture
def ghidra_install_dir() -> str:
    from pathlib import Path

    env_value = os.environ.get("GHIDRA_INSTALL_DIR")
    if env_value:
        return env_value

    system_install = Path("/usr/share/ghidra")
    if system_install.exists():
        return str(system_install)

    pytest.skip("GHIDRA_INSTALL_DIR is not set and /usr/share/ghidra is unavailable")


@pytest.fixture
def real_backend(ghidra_install_dir: str) -> GhidraBackend:
    os.environ.setdefault("XDG_CONFIG_HOME", "/tmp/codex-config")
    Path(os.environ["XDG_CONFIG_HOME"]).mkdir(parents=True, exist_ok=True)
    pyghidra = pytest.importorskip("pyghidra")
    backend = GhidraBackend(pyghidra, install_dir=ghidra_install_dir)
    yield backend
    backend.shutdown()


@pytest.fixture
def real_server(real_backend: GhidraBackend) -> SimpleMcpServer:
    return SimpleMcpServer(real_backend)
