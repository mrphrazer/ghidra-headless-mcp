"""Regression tests for the project-open deduplication fix.

Two sessions opened without an explicit ``project_location`` used to allocate a
fresh ``tempfile.mkdtemp()`` directory each time. ``_find_open_project`` keys on
``(resolved_location, project_name)``, so those two sessions never matched, each
called ``GhidraProject.openProject()``, and Ghidra handed back a second
``ProgramDB`` for the same ``.gpr``. That is the state in which memory block
reads come back as zeroes.

The fix derives the scratch location from the project name, so repeat opens of
the same program resolve to one directory and reuse one Project object.
"""
from __future__ import annotations

import threading
import types

import pytest

from ghidra_headless_mcp.backend import GhidraBackend


def _bare_backend() -> GhidraBackend:
    """A backend with just enough state to exercise project allocation."""
    backend = GhidraBackend.__new__(GhidraBackend)  # skip __init__ (starts JVM)
    backend._sessions = {}
    backend._lock = threading.Lock()
    backend._project_open_lock = threading.Lock()
    backend._temp_counter = 0
    return backend


def test_allocate_project_is_stable_for_the_same_program_name(tmp_path, monkeypatch):
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    backend = _bare_backend()

    first_location, first_name, first_managed = backend._allocate_project(
        "DFI2.mot", project_location=None, project_name=None
    )
    second_location, second_name, second_managed = backend._allocate_project(
        "DFI2.mot", project_location=None, project_name=None
    )

    assert first_managed is True and second_managed is True
    assert first_name == second_name
    # The whole point: the same program must resolve to the same location,
    # otherwise _find_open_project can never match and openProject() runs twice.
    assert first_location == second_location


def test_different_programs_still_get_different_projects(tmp_path, monkeypatch):
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    backend = _bare_backend()

    a_location, _, _ = backend._allocate_project(
        "DFI2.mot", project_location=None, project_name=None
    )
    b_location, _, _ = backend._allocate_project(
        "other.mot", project_location=None, project_name=None
    )

    assert a_location != b_location


def test_same_project_name_is_opened_only_once(tmp_path, monkeypatch):
    """Three opens of one (location, name) must perform a single openProject()."""
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    calls = {"open": 0, "create": 0, "mkdir": 0}

    class FakeLocator:
        def __init__(self, location, name):
            self.location = location
            self.name = name

        def exists(self) -> bool:
            return False

    class FakeGhidraProject:
        @staticmethod
        def openProject(location, name):
            calls["open"] += 1
            return types.SimpleNamespace(location=location, name=name)

        @staticmethod
        def createProject(location, name, remember):
            calls["create"] += 1
            return types.SimpleNamespace(location=location, name=name)

        @staticmethod
        def close():
            return None

    fake_project_module = types.ModuleType("ghidra.base.project")
    fake_project_module.GhidraProject = FakeGhidraProject
    fake_model_module = types.ModuleType("ghidra.framework.model")
    fake_model_module.ProjectLocator = FakeLocator

    monkeypatch.setitem(__import__("sys").modules, "ghidra", types.ModuleType("ghidra"))
    monkeypatch.setitem(__import__("sys").modules, "ghidra.base", types.ModuleType("ghidra.base"))
    monkeypatch.setitem(
        __import__("sys").modules, "ghidra.framework", types.ModuleType("ghidra.framework")
    )
    monkeypatch.setitem(__import__("sys").modules, "ghidra.base.project", fake_project_module)
    monkeypatch.setitem(__import__("sys").modules, "ghidra.framework.model", fake_model_module)

    backend = _bare_backend()
    location, name, _ = backend._allocate_project(
        "DFI2.mot", project_location=None, project_name=None
    )

    class FakeRecord:
        def __init__(self, project):
            self.project_location = location
            self.project_name = name
            self.project = project

    first = backend._open_or_create_project(location, name)
    backend._sessions["a"] = FakeRecord(first)
    second = backend._open_or_create_project(location, name)
    backend._sessions["b"] = FakeRecord(second)
    third = backend._open_existing_project(location, name)

    assert calls["open"] + calls["create"] == 1, calls
    assert first is second is third


def test_explicit_project_location_is_still_honoured(tmp_path):
    backend = _bare_backend()
    location, name, managed = backend._allocate_project(
        "anything.mot", project_location=str(tmp_path), project_name="explicit"
    )

    assert managed is False
    assert name == "explicit"
    assert location == str(tmp_path.resolve())