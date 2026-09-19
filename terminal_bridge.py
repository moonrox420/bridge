"""
TERMINAL BRIDGE
===============

A standalone, local-first Windows bridge for exposing terminal/system
information to AI clients through a simple HTTP API.

Python 3.10+
Standard library only.

DEFAULT MODE:
    Read-only.
    Binds to 127.0.0.1.
    Makes NO outbound network connections.

OPTIONAL CONTROL MODE:
    --allow-control

    Enables:
      - launching a shell
      - sending commands to that shell
      - stopping the shell
      - clearing the event buffer

    Control operations require a bearer token.

START (HTTP + DASHBOARD):
    python terminal_bridge.py
    python terminal_bridge.py --allow-control
    python terminal_bridge.py --open

START (MCP STDIO SERVER):
    python terminal_bridge.py --stdio
    python terminal_bridge.py --stdio --allow-control

CUSTOM PORT:
    python terminal_bridge.py --port 8765

API:
    GET  /api/status
    GET  /api/snapshot
    GET  /api/events
    GET  /api/events/stream
    GET  /api/processes
    GET  /api/tree?path=...
    GET  /api/file?path=...
    GET  /api/mcp
    POST /api/mcp

CONTROL:
    POST /api/shell/start
    POST /api/shell/input
    POST /api/shell/stop
    POST /api/events/clear

SECURITY
========
The server binds to 127.0.0.1 by default.

That means other machines on your network cannot connect to it.

Do NOT change --host to 0.0.0.0 unless you understand the security
implications.

The bridge does not contact ChatGPT, Gemini, Grok, Claude, or any other
AI provider. It simply exposes a local interface that an AI client can
use if that client supports connecting to a local HTTP/MCP service.

The control API is disabled unless --allow-control is explicitly supplied.

"""

from __future__ import annotations

import argparse
import datetime as datetime_module
import json
import logging
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import urllib.parse
import webbrowser
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

logger = logging.getLogger("terminal_bridge")

# ============================================================================
# CONFIGURATION
# ============================================================================

APP_NAME = "Terminal Bridge"
VERSION = "2.0.0"

ENV_FILE = Path(__file__).resolve().parent / ".env"


def strip_quotes(value: str) -> str:
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    return value


def _parse_env_fallback(target: Path) -> bool:
    try:
        with open(target, encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if "=" in stripped:
                    key, value = stripped.split("=", 1)
                    os.environ.setdefault(key.strip(), strip_quotes(value.strip()))
        return True
    except OSError as exc:
        logger.debug("Failed reading fallback .env: %s", exc)
        return False


def load_env_file(env_path: Path | str | None = None) -> bool:
    """Load environment variables from a .env file.

    Prefers python-dotenv if installed, with a standard-library fallback.
    """
    target = Path(env_path) if env_path is not None else ENV_FILE

    if not target.is_file():
        cwd_target = Path.cwd() / ".env"
        if cwd_target.is_file():
            target = cwd_target
        else:
            return False

    try:
        from dotenv import load_dotenv

        load_dotenv(dotenv_path=target)
        return True
    except ImportError:
        return _parse_env_fallback(target)


# Automatically load .env at module import
load_env_file(ENV_FILE)

DEFAULT_HOST = os.environ.get("BRIDGE_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("BRIDGE_PORT", "8765"))

MAX_EVENTS = 500
MAX_EVENT_SIZE = 32_000
MAX_FILE_SIZE = 512_000
MAX_TREE_ENTRIES = 2_000

DEFAULT_MASK_SECRETS = os.environ.get("MASK_SECRETS", "true").strip().lower() not in (
    "0",
    "false",
    "no",
)
DEFAULT_SNAPSHOT_BYTE_BUDGET = 65_536
MAX_SNAPSHOT_BYTE_BUDGET = 262_144
DEFAULT_EVENTS_BYTE_BUDGET = 32_768
MAX_EVENTS_BYTE_BUDGET = 131_072


# ============================================================================
# UTILITIES
# ============================================================================


def utc_now() -> str:
    return datetime_module.datetime.now(datetime_module.timezone.utc).isoformat()


def json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
    ).encode("utf-8")


def resolve_path(value: str) -> Path:
    if not value:
        raise ValueError("path is required")

    expanded = os.path.expandvars(os.path.expanduser(value))

    return Path(expanded).resolve()


def parse_bounded_int(
    val: Any,
    default: int,
    min_val: int = 1,
    max_val: int | None = None,
) -> int:
    if val is None:
        return default
    try:
        res = int(val)
        if max_val is not None:
            return min(max(min_val, res), max_val)
        return max(min_val, res)
    except ValueError:
        return default


# ============================================================================
# EVENT CLASSIFICATION & SECRET REDACTION
# ============================================================================


class EventCategory:
    STDOUT = "stdout"
    STDERR = "stderr"
    COMMAND = "command"
    LIFECYCLE = "lifecycle"
    PROMPT = "prompt"
    TELEMETRY = "telemetry"


def _classify_output_str(text: str) -> str:
    stripped = text.strip()
    if stripped.endswith(">") and (
        ":" in stripped or "\\" in stripped or "/" in stripped
    ):
        return EventCategory.PROMPT
    lower = stripped.lower()
    if (
        lower.startswith("error:")
        or lower.startswith("fatal:")
        or "traceback (most recent call last):" in lower
    ):
        return EventCategory.STDERR
    return EventCategory.STDOUT


def classify_event(event_type: str, data: Any) -> str:
    if event_type in ("shell_started", "shell_exited", "bridge_started"):
        return EventCategory.LIFECYCLE
    if event_type == "terminal_input":
        return EventCategory.COMMAND
    if event_type in ("shell_error", "error"):
        return EventCategory.STDERR
    if event_type == "background_tick":
        return EventCategory.TELEMETRY
    if event_type == "terminal_output":
        return (
            _classify_output_str(data)
            if isinstance(data, str)
            else EventCategory.STDOUT
        )
    return EventCategory.TELEMETRY


class SecretRedactor:
    """Masks credentials, API keys, tokens, and private keys from output."""

    _PATTERNS: list[tuple[re.Pattern[str], str]] = [
        (re.compile(r"\b(sk-[a-zA-Z0-9_-]{20,})\b"), "[REDACTED_API_KEY]"),
        (re.compile(r"\b(hf_[a-zA-Z0-9]{20,})\b"), "[REDACTED_API_KEY]"),
        (re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{20,})\b"), "[REDACTED_GITHUB_TOKEN]"),
        (re.compile(r"\b(github_pat_[A-Za-z0-9_]{30,})\b"), "[REDACTED_GITHUB_TOKEN]"),
        (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "[REDACTED_AWS_KEY]"),
        (
            re.compile(r"(?i)\b(bearer\s+)([a-zA-Z0-9_\-\.]{20,})\b"),
            r"\1[REDACTED_BEARER_TOKEN]",
        ),
        (
            re.compile(
                r"(?i)\b([a-z0-9_]*(?:token|secret|password|passwd|api[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?)(?!\[REDACTED)([^\s'\"]{8,})(['\"]?)"
            ),
            r"\1[REDACTED_SECRET]\3",
        ),
        (
            re.compile(
                r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
            ),
            "[REDACTED_PRIVATE_KEY_BLOCK]",
        ),
    ]

    @classmethod
    def mask(cls, text: str) -> str:
        if not text:
            return text
        masked = text
        for pattern, replacement in cls._PATTERNS:
            masked = pattern.sub(replacement, masked)
        return masked

    @classmethod
    def redact_text(cls, text: str) -> str:
        return cls.mask(text)

    @classmethod
    def redact_data(cls, data: Any) -> Any:
        if isinstance(data, str):
            return cls.mask(data)
        if isinstance(data, dict):
            return {k: cls.redact_data(v) for k, v in data.items()}
        if isinstance(data, list):
            return [cls.redact_data(item) for item in data]
        return data


# ============================================================================
# EVENT STORE
# ============================================================================


class EventStore:
    """Bounded event buffer with redaction, classification, and budgeting."""

    def __init__(
        self,
        maximum: int = MAX_EVENTS,
        mask_secrets: bool = DEFAULT_MASK_SECRETS,
        max_events: int | None = None,
    ):
        capacity = max_events if max_events is not None else maximum
        self.events: deque[dict[str, Any]] = deque(maxlen=capacity)
        self.lock = threading.RLock()
        self.condition = threading.Condition(self.lock)
        self.sequence = 0
        self.mask_secrets = mask_secrets
        self.on_event_callback: Any = None

    def _sanitize_data(self, data: Any) -> Any:
        if not self.mask_secrets:
            if isinstance(data, str):
                encoded = data.encode("utf-8", errors="replace")
                if len(encoded) > MAX_EVENT_SIZE:
                    data = data[:MAX_EVENT_SIZE] + "\n...[TRUNCATED]"
            return data

        sanitized = SecretRedactor.redact_data(data)
        if isinstance(sanitized, str):
            encoded = sanitized.encode("utf-8", errors="replace")
            if len(encoded) > MAX_EVENT_SIZE:
                sanitized = sanitized[:MAX_EVENT_SIZE] + "\n...[TRUNCATED]"
        return sanitized

    def add(
        self,
        event_type: str,
        data: Any,
        source: str = "bridge",
        category: str | None = None,
    ) -> dict[str, Any]:
        data = self._sanitize_data(data)
        resolved_category = category or classify_event(event_type, data)

        with self.condition:
            self.sequence += 1
            event = {
                "id": self.sequence,
                "timestamp": utc_now(),
                "type": event_type,
                "category": resolved_category,
                "source": source,
                "data": data,
            }
            self.events.append(event)
            self.condition.notify_all()
            if self.on_event_callback:
                try:
                    self.on_event_callback(event)
                except Exception as exc:
                    logger.debug("Event callback error: %s", exc)
            return event

    def check_gap(self, client_cursor: int) -> tuple[bool, int | None]:
        with self.lock:
            if not self.events:
                return False, None
            oldest_id = self.events[0]["id"]
            if client_cursor > 0 and client_cursor < (oldest_id - 1):
                return True, oldest_id
            return False, oldest_id

    def _filter_matching_events(
        self,
        event_id: int,
        categories: set[str] | None,
    ) -> list[dict[str, Any]]:
        matched: list[dict[str, Any]] = []
        for event in self.events:
            if event["id"] <= event_id:
                continue
            if categories and event.get("category") not in categories:
                continue
            matched.append(event)
        return matched

    def _apply_byte_budget(
        self,
        events: list[dict[str, Any]],
        max_bytes: int,
    ) -> list[dict[str, Any]]:
        budgeted: list[dict[str, Any]] = []
        current_bytes = 0
        for event in events:
            event_bytes = len(json.dumps(event, ensure_ascii=False).encode("utf-8"))
            if budgeted and (current_bytes + event_bytes > max_bytes):
                break
            budgeted.append(event)
            current_bytes += event_bytes
        return budgeted

    def get_since(
        self,
        event_id: int = 0,
        limit: int = 100,
        categories: set[str] | list[str] | None = None,
        max_bytes: int | None = None,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(limit, MAX_EVENTS))
        cat_filter = set(categories) if categories else None

        with self.lock:
            matched = self._filter_matching_events(event_id, cat_filter)
            result = matched[-limit:]
            if max_bytes is not None and max_bytes > 0:
                return self._apply_byte_budget(result, max_bytes)
            return result

    def clear(self) -> None:
        with self.condition:
            self.events.clear()
            self.condition.notify_all()

    def count(self) -> int:
        with self.lock:
            return len(self.events)


# ============================================================================
# SHELL SESSION
# ============================================================================


_PROMPT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^\s*PS\s+([A-Za-z]:\\[^>]+)>\s*$"),
    re.compile(r"^\s*([A-Za-z]:\\[^>]+)>\s*$"),
    re.compile(r"^\s*PS\s+(/[^>]+)>\s*$"),
]


def _detect_cwd_from_prompt(line: str) -> Path | None:
    for pattern in _PROMPT_PATTERNS:
        match = pattern.match(line)
        if match:
            candidate = match.group(1).strip()
            try:
                p = Path(candidate)
                if p.is_dir():
                    return p
            except OSError as exc:
                logger.debug(
                    "Path inspection failed for candidate '%s': %s", candidate, exc
                )
    return None


class ShellSession:
    """
    Captures a PowerShell or CMD session.

    This intentionally does not attempt to emulate a full terminal/PTY.

    It is designed for normal commands whose stdout/stderr can be captured.
    """

    def __init__(
        self,
        store: EventStore,
        shell: str = "powershell",
    ):
        self.store = store
        self.shell = shell
        self.cwd: Path = Path.cwd()

        self.process: subprocess.Popen[str] | None = None
        self.reader_thread: threading.Thread | None = None

        self.started_at: float | None = None

        self.lock = threading.RLock()
        self._stop_reason: str | None = None

    # ---------------------------------------------------------------------

    def command_line(self) -> list[str]:

        if self.shell == "cmd":
            return [
                "cmd.exe",
                "/Q",
            ]

        return [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
        ]

    # ---------------------------------------------------------------------

    def running(self) -> bool:

        return self.process is not None and self.process.poll() is None

    # ---------------------------------------------------------------------

    def start(self) -> None:

        with self.lock:
            if self.running():
                return

            creation_flags = 0

            if os.name == "nt":
                creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP

            self.process = subprocess.Popen(
                self.command_line(),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=creation_flags,
            )

            self.started_at = time.time()

            self.store.add(
                "shell_started",
                {
                    "shell": self.shell,
                    "pid": self.process.pid,
                },
                "shell",
            )

            self.reader_thread = threading.Thread(
                target=self._reader,
                name="terminal-bridge-reader",
                daemon=True,
            )

            self.reader_thread.start()

    # ---------------------------------------------------------------------

    def _handle_line_read(self, line: str) -> None:
        cleaned = line.rstrip("\r\n")
        new_cwd = _detect_cwd_from_prompt(cleaned)
        if new_cwd and new_cwd != self.cwd:
            old_cwd = self.cwd
            self.cwd = new_cwd
            self.store.add(
                "cwd_changed",
                {"old_cwd": str(old_cwd), "new_cwd": str(new_cwd)},
                "shell",
                category=EventCategory.LIFECYCLE,
            )
        self.store.add(
            "terminal_output",
            cleaned,
            "shell",
        )

    def _reader(self) -> None:
        process = self.process
        if process is None:
            return

        stdout = process.stdout
        if stdout is None:
            return

        try:
            for line in iter(
                stdout.readline,
                "",
            ):
                self._handle_line_read(line)

        except (OSError, ValueError, UnicodeDecodeError) as exc:
            self.store.add(
                "shell_error",
                repr(exc),
                "shell",
            )

        finally:
            try:
                return_code = process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                return_code = process.poll()

            exit_reason = self._stop_reason or (
                "exited" if return_code == 0 else "terminated"
            )
            self._stop_reason = None

            self.store.add(
                "shell_exited",
                {
                    "returncode": return_code,
                    "exit_reason": exit_reason,
                },
                "shell",
            )

    # ---------------------------------------------------------------------

    def send(self, command: str) -> None:

        if not command.strip():
            raise ValueError("command cannot be empty")

        with self.lock:
            if not self.running():
                raise RuntimeError("shell is not running")

            if self.process is None:
                raise RuntimeError("shell process unavailable")

            if self.process.stdin is None:
                raise RuntimeError("shell stdin unavailable")

            self.store.add(
                "terminal_input",
                command,
                "user",
            )

            self.process.stdin.write(command.rstrip("\r\n") + "\n")

            self.process.stdin.flush()

    # ---------------------------------------------------------------------

    def stop(self) -> None:

        with self.lock:
            if self.process and self.running():
                process = self.process

                self.store.add(
                    "shell_stopped",
                    None,
                    "bridge",
                )

                self._stop_reason = "terminated"

                try:
                    process.terminate()
                    try:
                        process.wait(timeout=1.0)
                    except subprocess.TimeoutExpired:
                        self._stop_reason = "forced"
                        process.kill()
                        process.wait(timeout=1.0)
                except OSError as exc:
                    logger.debug("Shell process terminate/kill: %s", exc)

            self.process = None
            self.started_at = None

    # ---------------------------------------------------------------------

    def status(self) -> dict[str, Any]:

        process = self.process

        return {
            "running": self.running(),
            "pid": (process.pid if process else None),
            "shell": self.shell,
            "cwd": str(self.cwd),
            "started_at": (
                datetime_module.datetime.fromtimestamp(
                    self.started_at,
                    tz=datetime_module.timezone.utc,
                ).isoformat()
                if self.started_at
                else None
            ),
        }


# ============================================================================
# SYSTEM INFORMATION
# ============================================================================


def _get_processes_windows() -> list[dict[str, Any]]:
    command = [
        "powershell.exe",
        "-NoProfile",
        "-Command",
        (
            "Get-Process | "
            "Select-Object Id,ProcessName,CPU,WS | "
            "ConvertTo-Json -Compress"
        ),
    ]
    try:
        output = subprocess.check_output(
            command,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
        if not output.strip():
            return []
        parsed = json.loads(output)
        if isinstance(parsed, dict):
            return [parsed]
        return parsed
    except (
        subprocess.SubprocessError,
        OSError,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ) as exc:
        return [{"error": repr(exc)}]


def _get_processes_posix() -> list[dict[str, Any]]:
    command = [
        "ps",
        "-eo",
        "pid,comm,%cpu,%mem",
    ]
    try:
        output = subprocess.check_output(
            command,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
        return [{"raw": line} for line in output.splitlines()]
    except (
        subprocess.SubprocessError,
        OSError,
        UnicodeDecodeError,
    ) as exc:
        return [{"error": repr(exc)}]


def get_processes() -> list[dict[str, Any]]:
    if os.name == "nt":
        return _get_processes_windows()
    return _get_processes_posix()


# ============================================================================
# FILESYSTEM
# ============================================================================


def read_file(
    path: Path,
    maximum: int = MAX_FILE_SIZE,
) -> dict[str, Any]:

    if not path.exists():
        raise FileNotFoundError(str(path))

    if not path.is_file():
        raise ValueError(f"not a file: {path}")

    size = path.stat().st_size

    with path.open("rb") as file:
        raw = file.read(maximum + 1)

    truncated = len(raw) > maximum

    raw = raw[:maximum]

    text = raw.decode(
        "utf-8",
        errors="replace",
    )

    return {
        "path": str(path),
        "size": size,
        "truncated": truncated,
        "content": text,
    }


def _build_tree_item(child: Path) -> tuple[dict[str, Any], bool] | None:
    try:
        directory = child.is_dir()
        item: dict[str, Any] = {
            "name": child.name,
            "path": str(child),
            "directory": directory,
        }
        if not directory:
            try:
                item["size"] = child.stat().st_size
            except OSError:
                item["size"] = None
        return item, directory
    except OSError as exc:
        logger.debug("Directory entry access error: %s", exc)
        return None


def _iter_directory_entries(directory: Path) -> list[Path]:
    try:
        return sorted(
            directory.iterdir(),
            key=lambda item: (
                not item.is_dir(),
                item.name.lower(),
            ),
        )
    except (PermissionError, OSError) as exc:
        logger.debug("Failed listing directory %s: %s", directory, exc)
        return []


def _traverse_tree(root: Path, maximum: int) -> tuple[list[dict[str, Any]], bool]:
    results: list[dict[str, Any]] = []
    stack = [root]

    while stack and len(results) < maximum:
        current = stack.pop()
        for child in _iter_directory_entries(current):
            if len(results) >= maximum:
                break

            built = _build_tree_item(child)
            if built is not None:
                item, is_dir = built
                results.append(item)
                if is_dir:
                    stack.append(child)

    return results, bool(stack)


def filesystem_tree(
    root: Path,
    maximum: int = MAX_TREE_ENTRIES,
) -> dict[str, Any]:

    if not root.exists():
        raise FileNotFoundError(str(root))

    if not root.is_dir():
        raise ValueError(f"not a directory: {root}")

    results, truncated = _traverse_tree(root, maximum)
    return {
        "root": str(root),
        "entries": results,
        "count": len(results),
        "truncated": truncated,
    }


# ============================================================================
# BRIDGE STATE
# ============================================================================


class BridgeState:
    def __init__(
        self,
        allow_control: bool,
        token: str | None,
        shell: str,
        mask_secrets: bool = DEFAULT_MASK_SECRETS,
    ):
        self.started = time.time()
        self.allow_control = allow_control
        self.token = token
        self.mask_secrets = mask_secrets
        self.events = EventStore(mask_secrets=mask_secrets)
        self.failure_tracker = FailureContextTracker()
        self.events.on_event_callback = self._on_event_added
        self.shell = ShellSession(
            self.events,
            shell=shell,
        )

    def _on_event_added(self, event: dict[str, Any]) -> None:
        cat = event.get("category")
        ev_type = event.get("type")
        if cat == EventCategory.STDERR or ev_type in ("shell_error", "error"):
            data = event.get("data")
            msg = str(data) if data is not None else ""
            self.failure_tracker.record_error(
                event_type=str(ev_type or "error"),
                message=msg,
                source=str(event.get("source") or "shell"),
            )

    def status(self) -> dict[str, Any]:
        return {
            "name": APP_NAME,
            "version": VERSION,
            "platform": sys.platform,
            "python": sys.version.split()[0],
            "pid": os.getpid(),
            "started_at": (
                datetime_module.datetime.fromtimestamp(
                    self.started,
                    tz=datetime_module.timezone.utc,
                ).isoformat()
                if self.started
                else None
            ),
            "uptime_seconds": round(
                time.time() - self.started,
                2,
            ),
            "control_enabled": self.allow_control,
            "shell": self.shell.status(),
            "event_count": self.events.count(),
            "has_error": self.failure_tracker.has_error(),
        }


def _calc_payload_bytes(payload: Any) -> int:
    return len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))


def _trim_entries_to_budget(
    workspace: dict[str, Any], snapshot: dict[str, Any], max_bytes: int
) -> None:
    entries = workspace.get("entries")
    if isinstance(entries, list):
        while entries and _calc_payload_bytes(snapshot) > max_bytes:
            entries.pop()
            workspace["count"] = len(entries)
            workspace["truncated"] = True


def _trim_list_to_budget(
    items: list[Any], snapshot: dict[str, Any], max_bytes: int, pop_index: int
) -> None:
    while len(items) > 5 and _calc_payload_bytes(snapshot) > max_bytes:
        items.pop(pop_index)


def _trim_snapshot_to_budget(snapshot: dict[str, Any], max_bytes: int) -> bool:
    if _calc_payload_bytes(snapshot) <= max_bytes:
        return False
    workspace = snapshot.get("workspace")
    if isinstance(workspace, dict):
        _trim_entries_to_budget(workspace, snapshot, max_bytes)
    events = snapshot.get("recent_events")
    if isinstance(events, list):
        _trim_list_to_budget(events, snapshot, max_bytes, 0)
    procs = snapshot.get("processes")
    if isinstance(procs, list):
        _trim_list_to_budget(procs, snapshot, max_bytes, -1)
    return True


def _resolve_snapshot_processes(procs_limit: int) -> list[dict[str, Any]]:
    try:
        all_procs = get_processes()
        return all_procs[:procs_limit] if isinstance(all_procs, list) else []
    except (OSError, RuntimeError) as exc:
        return [{"error": str(exc)}]


def _resolve_snapshot_workspace(target_path: Path, tree_limit: int) -> dict[str, Any]:
    try:
        return filesystem_tree(target_path, maximum=tree_limit)
    except (OSError, ValueError) as exc:
        return {
            "root": str(target_path),
            "error": str(exc),
            "entries": [],
            "count": 0,
            "truncated": False,
        }


def _build_snapshot_payload(
    state: BridgeState,
    workspace: dict[str, Any],
    processes: list[dict[str, Any]],
    recent_events: list[dict[str, Any]],
) -> dict[str, Any]:
    """Construct the initial snapshot payload dictionary."""
    last_err_summary = (
        state.failure_tracker.get_last_error(include_snippets=False)
        if hasattr(state, "failure_tracker")
        else None
    )
    return {
        "timestamp": utc_now(),
        "latest_event_id": state.events.sequence,
        "bridge": state.status(),
        "capabilities": {
            "read_files": True,
            "list_processes": True,
            "filesystem_tree": True,
            "terminal_control": state.allow_control,
        },
        "shell": state.shell.status(),
        "workspace": workspace,
        "processes": processes,
        "recent_events": recent_events,
        "last_error": last_err_summary,
    }


def build_context_snapshot(
    state: BridgeState,
    limits: dict[str, int] | None = None,
    root_path: Path | None = None,
) -> dict[str, Any]:
    """Unified atomic snapshot of bridge, shell, workspace, processes, and recent events."""
    limits = limits or {}
    events_limit = min(max(1, limits.get("events", 50)), 200)
    procs_limit = min(max(1, limits.get("procs", 30)), 100)
    tree_limit = min(max(1, limits.get("tree", 50)), 200)
    max_bytes = min(
        max(1024, limits.get("max_bytes", DEFAULT_SNAPSHOT_BYTE_BUDGET)),
        MAX_SNAPSHOT_BYTE_BUDGET,
    )

    since = max(0, state.events.sequence - events_limit)
    recent_events = state.events.get_since(since, events_limit)
    processes = _resolve_snapshot_processes(procs_limit)
    target_path = (
        root_path
        if root_path is not None
        else (getattr(state.shell, "cwd", None) or Path.cwd())
    )
    workspace = _resolve_snapshot_workspace(target_path, tree_limit)

    snapshot = _build_snapshot_payload(state, workspace, processes, recent_events)
    truncated = _trim_snapshot_to_budget(snapshot, max_bytes)
    snapshot["budget"] = {
        "allocated_bytes": max_bytes,
        "used_bytes": _calc_payload_bytes(snapshot),
        "truncated": truncated,
    }
    return snapshot


# ============================================================================
# FILESYSTEM SECURITY POLICY
# ============================================================================


class FilesystemPolicy:
    """Security policy guardrails for automated AI file inspection."""

    EXCLUDED_FILE_NAMES = frozenset(
        {
            ".env",
            "id_rsa",
            "id_ed25519",
            "id_ecdsa",
            "id_dsa",
            ".gitconfig",
            ".bash_history",
        }
    )

    @classmethod
    def check_file_read(cls, path: Path) -> str | None:
        """Return an error message if the file read is denied by policy, else None."""
        name_lower = path.name.lower()
        if (
            name_lower in cls.EXCLUDED_FILE_NAMES
            or name_lower.startswith(".env")
            or name_lower.endswith((".pem", ".key", ".pfx"))
        ):
            return (
                f"Access denied: access to sensitive configuration/credential file "
                f"'{path.name}' is blocked by filesystem policy."
            )
        return None


# ============================================================================
# STRUCTURED FAILURE CONTEXT
# ============================================================================


_TRACEBACK_LINE_RE = re.compile(r'File "([^"]+)", line (\d+)')
_GENERIC_LOC_RE = re.compile(
    r"\b([a-zA-Z0-9_\-/\\]+\.(?:py|js|ts|json|txt|md|rs|go|c|cpp|h)):(\d+)\b"
)


def _read_snippet_window(path: Path, target_line: int, window: int = 4) -> list[str]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        start = max(0, target_line - window - 1)
        end = min(len(lines), target_line + window)
        return [f"{i + 1:4d} | {lines[i].rstrip()}" for i in range(start, end)]
    except OSError:
        return []


def _resolve_snippet_for_location(
    raw_path: str, raw_line: str, include_snippets: bool
) -> dict[str, Any]:
    try:
        line_num = int(raw_line)
        resolved = resolve_path(raw_path)
    except ValueError:
        return {
            "raw_path": raw_path,
            "line": raw_line,
            "error": "Invalid path or line",
        }

    policy_err = FilesystemPolicy.check_file_read(resolved)
    if policy_err:
        return {
            "path": str(resolved),
            "line": line_num,
            "policy_blocked": True,
        }

    if not resolved.is_file():
        return {"path": str(resolved), "line": line_num, "not_found": True}

    entry: dict[str, Any] = {"path": str(resolved), "line": line_num}
    if include_snippets:
        entry["snippet"] = _read_snippet_window(resolved, line_num)
    return entry


def _extract_traceback_locations(text: str) -> list[tuple[str, str]]:
    locations: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for match in _TRACEBACK_LINE_RE.finditer(text):
        item = (match.group(1), match.group(2))
        if item not in seen:
            seen.add(item)
            locations.append(item)
    for match in _GENERIC_LOC_RE.finditer(text):
        item = (match.group(1), match.group(2))
        if item not in seen:
            seen.add(item)
            locations.append(item)
    return locations


class FailureContextTracker:
    """Maintains structured last-error context with policy-gated source file snippets."""

    def __init__(self, max_files: int = 5):
        self.max_files = max_files
        self.lock = threading.RLock()
        self._last_error: dict[str, Any] | None = None

    def record_error(
        self,
        event_type: str,
        message: str,
        source: str = "shell",
        command: str | None = None,
    ) -> None:
        with self.lock:
            locations = _extract_traceback_locations(message)[: self.max_files]
            self._last_error = {
                "timestamp": utc_now(),
                "event_type": event_type,
                "source": source,
                "command": command,
                "message": message,
                "locations": locations,
            }

    def has_error(self) -> bool:
        with self.lock:
            return self._last_error is not None

    def get_last_error(self, include_snippets: bool = True) -> dict[str, Any] | None:
        with self.lock:
            if self._last_error is None:
                return None
            result = dict(self._last_error)
            locations = self._last_error.get("locations", [])
            resolved_files = [
                _resolve_snippet_for_location(p, ln, include_snippets)
                for p, ln in locations
            ]
            result["related_files"] = resolved_files
            return result


# ============================================================================
# MCP (MODEL CONTEXT PROTOCOL) - SPEC 2026-07-28
# ============================================================================


class MCPProtocol:
    """JSON-RPC 2.0 protocol parser, validator, and response constructor."""

    PROTOCOL_VERSION = "2026-07-28"

    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603

    @staticmethod
    def parse_request(
        raw_text: str,
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """Parse raw text into a JSON-RPC request dictionary.

        Returns (request_dict, error_response_dict).
        """
        try:
            payload = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            return None, MCPProtocol.error_response(
                None,
                MCPProtocol.PARSE_ERROR,
                f"Parse error: {exc}",
            )

        if not isinstance(payload, dict):
            return None, MCPProtocol.error_response(
                None,
                MCPProtocol.INVALID_REQUEST,
                "Invalid Request: payload must be a JSON object",
            )

        if payload.get("jsonrpc") != "2.0":
            return None, MCPProtocol.error_response(
                payload.get("id"),
                MCPProtocol.INVALID_REQUEST,
                "Invalid Request: jsonrpc field must be '2.0'",
            )

        if "method" not in payload or not isinstance(payload["method"], str):
            return None, MCPProtocol.error_response(
                payload.get("id"),
                MCPProtocol.INVALID_REQUEST,
                "Invalid Request: 'method' must be a string",
            )

        return payload, None

    @staticmethod
    def success_response(req_id: Any, result: Any) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": result,
        }

    @staticmethod
    def error_response(
        req_id: Any,
        code: int,
        message: str,
        data: Any = None,
    ) -> dict[str, Any]:
        err: dict[str, Any] = {
            "code": code,
            "message": message,
        }
        if data is not None:
            err["data"] = data
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": err,
        }


CORE_MCP_TOOLS: list[dict[str, Any]] = [
    {
        "name": "get_context_snapshot",
        "description": (
            "Establish baseline state: unified atomic snapshot of bridge status, "
            "shell state, workspace summary, process list, and bounded recent events."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "events_limit": {
                    "type": "integer",
                    "description": "Maximum recent events to include (1-200, default 50)",
                },
                "procs_limit": {
                    "type": "integer",
                    "description": "Maximum processes to include (1-100, default 30)",
                },
                "tree_limit": {
                    "type": "integer",
                    "description": "Maximum workspace entries to include (1-200, default 50)",
                },
                "path": {
                    "type": "string",
                    "description": "Root path for workspace tree (default current working directory)",
                },
                "max_bytes": {
                    "type": "integer",
                    "description": "Maximum payload byte budget (default 65536, max 262144)",
                },
            },
        },
    },
    {
        "name": "get_events",
        "description": (
            "Catch-up / delta historical retrieval: returns bounded terminal events "
            "since a given sequence cursor. (For live continuous telemetry, use native SSE stream)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "since": {
                    "type": "integer",
                    "description": "Retrieve events strictly after this sequence number (default 0)",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum events to return (default 50, max 500)",
                },
                "max_bytes": {
                    "type": "integer",
                    "description": "Maximum byte budget for returned events (default 32768, max 131072)",
                },
                "categories": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional category filters: stdout, stderr, command, lifecycle, prompt, telemetry",
                },
            },
        },
    },
    {
        "name": "read_file",
        "description": "Read bounded text file content from the local filesystem.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute or relative file path to read",
                },
                "max_bytes": {
                    "type": "integer",
                    "description": "Maximum bytes to read (default 32768, max 512000)",
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "list_directory",
        "description": "List bounded filesystem entries from a directory tree.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory path to list (default current working directory)",
                },
                "max_entries": {
                    "type": "integer",
                    "description": "Maximum entries to inspect (default 100, max 2000)",
                },
            },
        },
    },
    {
        "name": "get_last_error",
        "description": (
            "Retrieve structured context for the most recent failure or traceback, "
            "including timestamp, error category, and policy-gated local file snippets."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "include_snippets": {
                    "type": "boolean",
                    "description": (
                        "Whether to include source code preview snippets around failure lines. "
                        "Default: true"
                    ),
                }
            },
        },
    },
]

CONTROL_MCP_TOOLS: list[dict[str, Any]] = [
    {
        "name": "execute_command",
        "description": (
            "Execute a command in the active managed shell session. "
            "Requires control mode (--allow-control)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Command line string to send to the managed shell",
                }
            },
            "required": ["command"],
        },
    }
]


class MCPToolRegistry:
    """Registry of MCP tools and operational handlers against BridgeCore."""

    def __init__(self, state: BridgeState):
        self.state = state

    def get_tools(self) -> list[dict[str, Any]]:
        tools = list(CORE_MCP_TOOLS)
        if self.state.allow_control:
            tools.extend(CONTROL_MCP_TOOLS)
        return tools

    def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        auth_ok: bool = True,
    ) -> dict[str, Any]:
        if name == "get_context_snapshot":
            return self._call_get_context_snapshot(arguments)
        elif name == "get_events":
            return self._call_get_events(arguments)
        elif name == "get_last_error":
            return self._call_get_last_error(arguments)
        elif name == "read_file":
            return self._call_read_file(arguments)
        elif name == "list_directory":
            return self._call_list_directory(arguments)
        elif name == "execute_command":
            return self._call_execute_command(arguments, auth_ok=auth_ok)
        else:
            return {
                "content": [{"type": "text", "text": f"Unknown tool: '{name}'"}],
                "isError": True,
            }

    def _call_get_last_error(self, arguments: dict[str, Any]) -> dict[str, Any]:
        include_snippets = arguments.get("include_snippets", True)
        if not isinstance(include_snippets, bool):
            include_snippets = True
        err_ctx = self.state.failure_tracker.get_last_error(
            include_snippets=include_snippets
        )
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        err_ctx or {"status": "no_errors_recorded"},
                        indent=2,
                    ),
                }
            ],
            "isError": False,
        }

    def _call_get_context_snapshot(self, arguments: dict[str, Any]) -> dict[str, Any]:
        limits = {
            "events": parse_bounded_int(
                arguments.get("events_limit"), default=50, min_val=1, max_val=MAX_EVENTS
            ),
            "procs": parse_bounded_int(
                arguments.get("procs_limit"), default=30, min_val=1, max_val=100
            ),
            "tree": parse_bounded_int(
                arguments.get("tree_limit"),
                default=50,
                min_val=1,
                max_val=MAX_TREE_ENTRIES,
            ),
            "max_bytes": parse_bounded_int(
                arguments.get("max_bytes"),
                default=DEFAULT_SNAPSHOT_BYTE_BUDGET,
                min_val=1024,
                max_val=MAX_SNAPSHOT_BYTE_BUDGET,
            ),
        }
        raw_path = arguments.get("path")
        root_path = resolve_path(raw_path) if raw_path else Path.cwd()

        snapshot = build_context_snapshot(
            state=self.state,
            limits=limits,
            root_path=root_path,
        )
        return {
            "content": [{"type": "text", "text": json.dumps(snapshot, indent=2)}],
            "isError": False,
        }

    def _call_get_events(self, arguments: dict[str, Any]) -> dict[str, Any]:
        since = parse_bounded_int(arguments.get("since"), default=0, min_val=0)
        limit = parse_bounded_int(
            arguments.get("limit"), default=50, min_val=1, max_val=MAX_EVENTS
        )
        categories_arg = arguments.get("categories")
        categories = (
            [str(c).strip().lower() for c in categories_arg]
            if isinstance(categories_arg, list)
            else None
        )
        max_bytes = parse_bounded_int(
            arguments.get("max_bytes"),
            default=DEFAULT_EVENTS_BYTE_BUDGET,
            min_val=512,
            max_val=MAX_EVENTS_BYTE_BUDGET,
        )
        gap_detected, oldest_id = self.state.events.check_gap(since)
        events = self.state.events.get_since(
            since, limit, categories=categories, max_bytes=max_bytes
        )
        payload = {
            "events": events,
            "latest_id": self.state.events.sequence,
            "oldest_available": oldest_id,
            "gap_detected": gap_detected,
            "count": len(events),
            "categories_filter": categories,
        }
        if gap_detected:
            payload["recommended_action"] = "get_context_snapshot"
        return {
            "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
            "isError": False,
        }

    @staticmethod
    def _validate_file_path(raw_path: Any) -> tuple[Path | None, str | None]:
        if not raw_path or not isinstance(raw_path, str):
            return None, "Missing required argument 'path'"

        try:
            resolved = resolve_path(raw_path)
        except (ValueError, OSError, RuntimeError) as exc:
            return None, f"Invalid path '{raw_path}': {exc}"

        policy_err = FilesystemPolicy.check_file_read(resolved)
        if policy_err:
            return None, policy_err

        if not resolved.exists():
            return None, f"File not found: {resolved}"

        if not resolved.is_file():
            return None, f"Path is not a regular file: {resolved}"

        return resolved, None

    def _call_read_file(self, arguments: dict[str, Any]) -> dict[str, Any]:
        resolved, path_err = self._validate_file_path(arguments.get("path"))
        if path_err is not None or resolved is None:
            return {
                "content": [{"type": "text", "text": path_err or "Invalid path"}],
                "isError": True,
            }

        max_bytes = parse_bounded_int(
            arguments.get("max_bytes"), default=32_768, min_val=1, max_val=MAX_FILE_SIZE
        )

        try:
            file_data = read_file(resolved, maximum=max_bytes)
            return {
                "content": [{"type": "text", "text": json.dumps(file_data, indent=2)}],
                "isError": False,
            }
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            return {
                "content": [{"type": "text", "text": f"Failed reading file: {exc}"}],
                "isError": True,
            }

    def _call_list_directory(self, arguments: dict[str, Any]) -> dict[str, Any]:
        raw_path = arguments.get("path")
        target = resolve_path(raw_path) if raw_path else Path.cwd()

        if not target.exists():
            return {
                "content": [{"type": "text", "text": f"Directory not found: {target}"}],
                "isError": True,
            }

        if not target.is_dir():
            return {
                "content": [
                    {"type": "text", "text": f"Path is not a directory: {target}"}
                ],
                "isError": True,
            }

        max_entries = parse_bounded_int(
            arguments.get("max_entries"),
            default=100,
            min_val=1,
            max_val=MAX_TREE_ENTRIES,
        )

        try:
            tree_data = filesystem_tree(target, maximum=max_entries)
            return {
                "content": [{"type": "text", "text": json.dumps(tree_data, indent=2)}],
                "isError": False,
            }
        except (OSError, ValueError) as exc:
            return {
                "content": [
                    {"type": "text", "text": f"Failed listing directory: {exc}"}
                ],
                "isError": True,
            }

    def _validate_command_execution(
        self,
        arguments: dict[str, Any],
        auth_ok: bool,
    ) -> tuple[str | None, dict[str, Any] | None]:
        if not self.state.allow_control:
            return None, {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "Permission denied: shell control is disabled on this bridge. "
                            "Start the bridge with --allow-control to enable command execution."
                        ),
                    }
                ],
                "isError": True,
            }

        if not auth_ok:
            return None, {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "Authorization failed: execute_command requires a valid Bearer token via Authorization header."
                        ),
                    }
                ],
                "isError": True,
            }

        command = arguments.get("command")
        if not command or not isinstance(command, str) or not command.strip():
            return None, {
                "content": [
                    {
                        "type": "text",
                        "text": "Invalid argument: 'command' must be a non-empty string.",
                    }
                ],
                "isError": True,
            }

        return command, None

    def _wait_for_command_output(self, seq_before: int) -> list[str]:
        deadline = time.time() + 0.4
        while time.time() < deadline:
            with self.state.events.condition:
                self.state.events.condition.wait(
                    timeout=max(0.05, deadline - time.time())
                )
                if self.state.events.sequence > seq_before:
                    break

        new_events = self.state.events.get_since(seq_before, limit=50)
        return [
            str(e["data"])
            for e in new_events
            if e["type"] in ("terminal_output", "shell_error", "shell_exited")
        ]

    def _dispatch_shell_command(
        self, command: str
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        if not self.state.shell.running():
            self.state.shell.start()
            time.sleep(0.1)

        seq_before = self.state.events.sequence
        start_time = time.perf_counter()
        try:
            self.state.shell.send(command)
        except (RuntimeError, ValueError, OSError) as exc:
            self.state.failure_tracker.record_error(
                event_type="command_dispatch_error",
                message=str(exc),
                source="bridge",
                command=command,
            )
            return None, {
                "content": [
                    {
                        "type": "text",
                        "text": f"Failed sending command to shell: {exc}",
                    }
                ],
                "isError": True,
            }

        output_lines = self._wait_for_command_output(seq_before)
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        self.state.events.add(
            "terminal_command_completed",
            {
                "command": command,
                "duration_ms": duration_ms,
                "output_lines_count": len(output_lines),
            },
            source="bridge",
            category=EventCategory.COMMAND,
        )
        return {
            "status": "executed",
            "command": command,
            "duration_ms": duration_ms,
            "shell": self.state.shell.status(),
            "latest_event_id": self.state.events.sequence,
            "initial_output": output_lines,
        }, None

    def _call_execute_command(
        self,
        arguments: dict[str, Any],
        auth_ok: bool = True,
    ) -> dict[str, Any]:
        command, err = self._validate_command_execution(arguments, auth_ok)
        if err is not None:
            return err
        if command is None:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "Invalid argument: 'command' must be a non-empty string.",
                    }
                ],
                "isError": True,
            }

        payload, exec_err = self._dispatch_shell_command(command)
        if exec_err is not None or payload is None:
            return exec_err or {
                "content": [{"type": "text", "text": "Execution failed"}],
                "isError": True,
            }

        return {
            "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
            "isError": False,
        }


class MCPServer:
    """Dispatches MCP JSON-RPC requests to protocol methods and tool handlers."""

    def __init__(self, registry: MCPToolRegistry):
        self.registry = registry

    def _dispatch_tools_call(
        self,
        req_id: Any,
        params: Any,
        auth_ok: bool,
    ) -> dict[str, Any]:
        if not isinstance(params, dict):
            return MCPProtocol.error_response(
                req_id,
                MCPProtocol.INVALID_PARAMS,
                "Invalid params: must be an object",
            )
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not name or not isinstance(name, str):
            return MCPProtocol.error_response(
                req_id,
                MCPProtocol.INVALID_PARAMS,
                "Invalid params: 'name' is required and must be a string",
            )
        if not isinstance(arguments, dict):
            return MCPProtocol.error_response(
                req_id,
                MCPProtocol.INVALID_PARAMS,
                "Invalid params: 'arguments' must be an object",
            )
        result = self.tools_call(name, arguments, auth_ok=auth_ok)
        return MCPProtocol.success_response(req_id, result)

    def _execute_mcp_method(
        self,
        method: str,
        params: Any,
        auth_ok: bool,
        req_id: Any,
    ) -> dict[str, Any]:
        dict_params = params if isinstance(params, dict) else {}
        if method in ("server/discover", "initialize"):
            return MCPProtocol.success_response(
                req_id, self.server_discover(dict_params)
            )
        if method == "ping":
            return MCPProtocol.success_response(req_id, {})
        if method == "tools/list":
            return MCPProtocol.success_response(req_id, self.tools_list(dict_params))
        if method == "tools/call":
            return self._dispatch_tools_call(req_id, params, auth_ok)
        return MCPProtocol.error_response(
            req_id,
            MCPProtocol.METHOD_NOT_FOUND,
            f"Method not found: {method}",
        )

    def handle_message(
        self,
        raw_message: str,
        auth_ok: bool = True,
    ) -> dict[str, Any] | None:
        req, err = MCPProtocol.parse_request(raw_message)
        if err is not None:
            return err
        if req is None:
            return None

        req_id = req.get("id")
        method = req["method"]
        params = req.get("params") or {}
        is_notification = req_id is None

        if method == "notifications/initialized":
            return None

        try:
            resp = self._execute_mcp_method(method, params, auth_ok, req_id)
            return None if is_notification else resp
        except Exception as exc:
            if is_notification:
                return None
            return MCPProtocol.error_response(
                req_id,
                MCPProtocol.INTERNAL_ERROR,
                f"Internal error: {exc}",
            )

    def server_discover(self, params: dict[str, Any]) -> dict[str, Any]:
        return {
            "protocolVersion": MCPProtocol.PROTOCOL_VERSION,
            "serverInfo": {
                "name": APP_NAME,
                "version": VERSION,
            },
            "capabilities": {
                "tools": {
                    "listChanged": False,
                },
            },
        }

    def tools_list(self, params: dict[str, Any]) -> dict[str, Any]:
        return {
            "tools": self.registry.get_tools(),
        }

    def tools_call(
        self,
        name: str,
        arguments: dict[str, Any],
        auth_ok: bool = True,
    ) -> dict[str, Any]:
        return self.registry.call_tool(name, arguments, auth_ok=auth_ok)


def run_stdio(server: MCPServer) -> int:
    """Run MCP server over standard input / output.

    stdout is reserved exclusively for protocol JSON-RPC messages.
    All logging and diagnostic outputs are redirected to stderr.
    """

    sys.stderr.write(f"[{APP_NAME} {VERSION}] Starting MCP stdio transport...\n")
    sys.stderr.write(f"[{APP_NAME}] Protocol Version: {MCPProtocol.PROTOCOL_VERSION}\n")
    control_str = "ENABLED" if (STATE and STATE.allow_control) else "DISABLED"
    sys.stderr.write(f"[{APP_NAME}] Control mode: {control_str}\n")
    sys.stderr.flush()

    try:
        for line in sys.stdin:
            line_str = line.strip()
            if not line_str:
                continue
            response = server.handle_message(line_str)
            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
    except KeyboardInterrupt:
        sys.stderr.write(f"\n[{APP_NAME}] Stdio transport interrupted. Exiting.\n")
        sys.stderr.flush()
    finally:
        if STATE is not None:
            STATE.shell.stop()
    return 0


MCP_REGISTRY: MCPToolRegistry | None = None
MCP_SERVER: MCPServer | None = None


def get_mcp_server() -> MCPServer:
    global MCP_REGISTRY, MCP_SERVER
    if STATE is None:
        raise RuntimeError("bridge state unavailable")
    if MCP_SERVER is None or MCP_REGISTRY is None or MCP_REGISTRY.state is not STATE:
        MCP_REGISTRY = MCPToolRegistry(STATE)
        MCP_SERVER = MCPServer(MCP_REGISTRY)
    return MCP_SERVER


STATE: BridgeState | None = None


# ============================================================================
# AUTHENTICATION
# ============================================================================


def valid_control_token(
    handler: BaseHTTPRequestHandler,
) -> bool:
    if STATE is None or not STATE.allow_control or not STATE.token:
        return False

    supplied = handler.headers.get("Authorization", "").strip()
    if not supplied.startswith("Bearer "):
        return False

    token_part = strip_quotes(supplied[7:].strip())
    return secrets.compare_digest(token_part, STATE.token)


def generate_token() -> str:

    return secrets.token_urlsafe(32)


# ============================================================================
# WEB DASHBOARD
# ============================================================================

DASHBOARD = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Terminal Bridge</title>
<style>
body {
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    max-width: 1200px;
    margin: 0 auto;
    padding: 24px;
    background: #f8fafc;
    color: #1e293b;
}

h1 { margin-bottom: 4px; }
h2 { margin-top: 0; margin-bottom: 12px; font-size: 1.2rem; }
p.subtitle { color: #64748b; margin-top: 0; margin-bottom: 20px; }

.card {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 10px;
    padding: 16px;
    margin: 16px 0;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
}

.row {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    align-items: center;
}

input, button {
    font: inherit;
    padding: 8px 12px;
    border-radius: 6px;
    border: 1px solid #cbd5e1;
}

input {
    flex: 1;
    background: #fff;
}

button {
    cursor: pointer;
    background: #f1f5f9;
}
button:hover { background: #e2e8f0; }

button.primary {
    background: #2563eb;
    color: #fff;
    border: none;
}
button.primary:hover { background: #1d4ed8; }

.badge {
    font-weight: 600;
    font-size: 0.95rem;
    display: inline-flex;
    align-items: center;
    gap: 6px;
}
.badge.ok { color: #16a34a; }
.badge.warn { color: #d97706; }
.badge.err { color: #dc2626; }
.badge.neutral { color: #64748b; }

pre {
    background: #0f172a;
    color: #f8fafc;
    padding: 16px;
    border-radius: 8px;
    overflow: auto;
    white-space: pre-wrap;
    max-height: 400px;
    font-size: 0.85rem;
    line-height: 1.4;
}

.status {
    white-space: pre-wrap;
    font-family: monospace;
    background: #f1f5f9;
    padding: 12px;
    border-radius: 6px;
    font-size: 0.85rem;
}
</style>
</head>
<body>

<h1>Terminal Bridge</h1>
<p class="subtitle">Local computer bridge for AI clients. No AI provider is contacted by this dashboard.</p>

<div class="card">
<h2>Control</h2>
<hr style="border: 0; border-top: 1px solid #e2e8f0; margin: 8px 0 16px 0;">
<div id="controlAuthSection">
    <div id="controlStatusBadge" class="badge warn" style="margin-bottom: 12px;">
        ○ Not authenticated
    </div>
    <form id="authForm" class="row" onsubmit="event.preventDefault(); authenticate();">
        <input
            id="tokenInput"
            type="password"
            placeholder="Enter control token"
            autocomplete="off"
        />
        <button type="submit" class="primary">Authenticate</button>
    </form>
    <div id="authActiveSection" style="display: none;">
        <button onclick="deauthenticate()">Forget Token</button>
    </div>
</div>
</div>

<div class="card">
<h2>Shell</h2>
<div id="shellStatusBadge" class="badge neutral" style="margin-bottom: 12px;">
    ● Stopped
</div>
<div class="row">
<button id="btnStartShell" class="primary" onclick="startShell()">Launch Shell</button>
<button id="btnStopShell" onclick="stopShell()">Stop Shell</button>
<button onclick="refresh()">Refresh</button>
</div>

<br>

<form onsubmit="sendCommand(event)">
<div class="row">
<input
    id="command"
    autocomplete="off"
    placeholder="Send command to shell..."
/>
<button class="primary">Send</button>
</div>
</form>
</div>

<div class="card">
<h2>Events</h2>
<pre id="events"></pre>
</div>

<div class="card">
<h2>Status</h2>
<div id="status" class="status">Loading...</div>
</div>

<script>
let lastEventId = 0;
const TOKEN_KEY = "terminal_bridge_token";

function getToken() {
    return sessionStorage.getItem(TOKEN_KEY) || "";
}

function updateControlUI(serverControlEnabled) {
    const badge = document.getElementById("controlStatusBadge");
    const authForm = document.getElementById("authForm");
    const authActive = document.getElementById("authActiveSection");
    const token = getToken();

    if (!serverControlEnabled) {
        badge.className = "badge err";
        badge.textContent = "✕ Control disabled on server (launch bridge with --allow-control or CONTROL_TOKEN)";
        authForm.style.display = "none";
        authActive.style.display = "none";
        return;
    }

    if (token) {
        badge.className = "badge ok";
        badge.textContent = "✓ Authenticated";
        authForm.style.display = "none";
        authActive.style.display = "inline-block";
    } else {
        badge.className = "badge warn";
        badge.textContent = "○ Not authenticated";
        authForm.style.display = "flex";
        authActive.style.display = "none";
    }
}

async function authenticate() {
    const input = document.getElementById("tokenInput");
    let val = input.value.trim();
    if (!val) {
        alert("Please enter a control token.");
        return;
    }
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1).trim();
    }
    try {
        const resp = await fetch("/api/auth/verify", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${val}`
            }
        });
        const data = await resp.json();
        if (!resp.ok || !data.authenticated) {
            alert("Authentication failed: " + (data.error || "control disabled or invalid token"));
            return;
        }
        sessionStorage.setItem(TOKEN_KEY, val);
        input.value = "";
        updateControlUI(true);
        refresh();
    } catch (err) {
        alert("Verification error: " + err.message);
    }
}

function deauthenticate() {
    sessionStorage.removeItem(TOKEN_KEY);
    updateControlUI(true);
}

async function api(path, options = {}) {
    options.headers = options.headers || {};
    const token = getToken();
    if (token) {
        options.headers["Authorization"] = `Bearer ${token}`;
    }

    const response = await fetch(path, options);
    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.error || response.statusText);
    }

    return data;
}

async function refresh() {
    try {
        const status = await api("/api/status");
        document.getElementById("status").textContent = JSON.stringify(status, null, 2);

        updateControlUI(status.control_enabled);
        await loadEvents();

        const shellBadge = document.getElementById("shellStatusBadge");
        const btnStart = document.getElementById("btnStartShell");
        const btnStop = document.getElementById("btnStopShell");

        if (status.shell && status.shell.running) {
            shellBadge.className = "badge ok";
            shellBadge.textContent = `● Running (${status.shell.shell}, PID ${status.shell.pid})`;
            btnStart.disabled = true;
            btnStop.disabled = false;
        } else {
            shellBadge.className = "badge neutral";
            shellBadge.textContent = "● Stopped";
            btnStart.disabled = false;
            btnStop.disabled = true;
        }
    } catch (error) {
        document.getElementById("status").textContent = String(error);
    }
}

let eventSource = null;

function appendEvent(event) {
    const output = document.getElementById("events");
    const data = typeof event.data === "string" ? event.data : JSON.stringify(event.data);
    output.textContent += `[${event.timestamp}] ${event.type}: ${data}\n`;
    lastEventId = event.id;
    output.scrollTop = output.scrollHeight;
}

async function loadEvents() {
    try {
        const res = await api(`/api/events?since=${lastEventId}`);
        if (res && res.events && Array.isArray(res.events)) {
            for (const ev of res.events) {
                if (ev.id > lastEventId) {
                    appendEvent(ev);
                }
            }
        }
    } catch (err) {}
}

function initSSE() {
    if (eventSource) {
        eventSource.close();
    }
    eventSource = new EventSource(`/api/events/stream?since=${lastEventId}`);

    function onEvent(e) {
        try {
            const event = JSON.parse(e.data);
            appendEvent(event);
        } catch (err) {}
    }

    eventSource.onmessage = onEvent;

    const eventTypes = [
        "terminal_output",
        "terminal_input",
        "shell_started",
        "shell_stopped",
        "shell_exited",
        "shell_error"
    ];
    for (const t of eventTypes) {
        eventSource.addEventListener(t, onEvent);
    }

    eventSource.addEventListener("stream_gap", function(e) {
        try {
            const gap = JSON.parse(e.data);
            const output = document.getElementById("events");
            output.textContent += `[STREAM GAP] Buffer rollover: requested since ${gap.requested_since}, oldest available is ${gap.oldest_available}\n`;
        } catch (err) {}
    });
    eventSource.onerror = function() {
        // Reconnection is automatically handled by browser EventSource
    };
}

async function startShell() {
    if (!getToken()) {
        alert("Please enter your control token and authenticate first.");
        const input = document.getElementById("tokenInput");
        if (input) input.focus();
        return;
    }
    try {
        await api("/api/shell/start", { method: "POST" });
        refresh();
    } catch (error) {
        alert("Failed to start shell: " + error.message);
    }
}

async function stopShell() {
    if (!getToken()) {
        alert("Please enter your control token and authenticate first.");
        return;
    }
    try {
        await api("/api/shell/stop", { method: "POST" });
        refresh();
    } catch (error) {
        alert("Failed to stop shell: " + error.message);
    }
}

async function sendCommand(event) {
    event.preventDefault();
    if (!getToken()) {
        alert("Please enter your control token and authenticate first.");
        const input = document.getElementById("tokenInput");
        if (input) input.focus();
        return;
    }

    const input = document.getElementById("command");
    const command = input.value;
    if (!command.trim()) return;

    try {
        await api("/api/shell/input", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ command })
        });
        input.value = "";
        refresh();
    } catch (error) {
        alert("Command error: " + error.message);
    }
}

refresh();
initSSE();
setInterval(refresh, 2500);
</script>
</body>
</html>
"""


# ============================================================================
# HTTP SERVER
# ============================================================================

CLIENT_DISCONNECT_ERRORS = (
    ConnectionResetError,
    ConnectionAbortedError,
    BrokenPipeError,
    TimeoutError,
    OSError,
)


class BridgeHandler(BaseHTTPRequestHandler):
    server_version = "TerminalBridge/" + VERSION

    def handle(self) -> None:
        try:
            super().handle()
        except CLIENT_DISCONNECT_ERRORS:
            self.close_connection = True

    # ------------------------------------------------------------------

    def log_message(
        self,
        format_string: str,
        *args: Any,
    ) -> None:

        # Don't spam stdout with HTTP access logs.
        return

    # ------------------------------------------------------------------

    def send_json(
        self,
        value: Any,
        status: int = 200,
        extra_headers: dict[str, str] | None = None,
    ) -> None:

        payload = json_bytes(value)

        self.send_response(status)

        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8",
        )

        self.send_header(
            "Content-Length",
            str(len(payload)),
        )

        self.send_header(
            "Cache-Control",
            "no-store",
        )

        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)

        self.end_headers()

        self.wfile.write(payload)

    # ------------------------------------------------------------------

    def send_html(
        self,
        html: str,
    ) -> None:

        payload = html.encode("utf-8")

        self.send_response(HTTPStatus.OK)

        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8",
        )

        self.send_header(
            "Content-Length",
            str(len(payload)),
        )

        self.end_headers()

        self.wfile.write(payload)

    # ------------------------------------------------------------------

    def _send_stream_gap(self, store: EventStore, since: int) -> int:
        gap_detected, oldest_id = store.check_gap(since)
        if gap_detected and oldest_id is not None:
            gap_payload = json.dumps(
                {
                    "type": "stream_gap",
                    "requested_since": since,
                    "oldest_available": oldest_id,
                    "action": "resync_required",
                }
            )
            frame = f"event: stream_gap\ndata: {gap_payload}\n\n"
            self.wfile.write(frame.encode("utf-8"))
            self.wfile.flush()
            return oldest_id - 1
        return since

    @staticmethod
    def _filter_events_for_stream(
        events: deque[dict[str, Any]],
        cursor: int,
        categories: set[str] | None,
    ) -> list[dict[str, Any]]:
        return [
            e
            for e in events
            if e["id"] > cursor and (not categories or e.get("category") in categories)
        ]

    def _collect_stream_events(
        self,
        store: EventStore,
        cursor: int,
        categories: set[str] | None,
        timeout: float,
    ) -> list[dict[str, Any]]:
        with store.condition:
            events = self._filter_events_for_stream(store.events, cursor, categories)
            if not events:
                store.condition.wait(timeout=timeout)
                events = self._filter_events_for_stream(
                    store.events, cursor, categories
                )
            return events

    def _write_stream_events(self, events: list[dict[str, Any]]) -> int:
        last_id = 0
        for ev in events:
            last_id = ev["id"]
            data_json = json.dumps(ev)
            frame = f"id: {ev['id']}\nevent: {ev['type']}\ndata: {data_json}\n\n"
            self.wfile.write(frame.encode("utf-8"))
        self.wfile.flush()
        return last_id

    def _write_stream_heartbeat(self) -> None:
        heartbeat = f": keepalive {utc_now()}\n\n"
        self.wfile.write(heartbeat.encode("utf-8"))
        self.wfile.flush()

    def _stream_loop(
        self,
        store: EventStore,
        cursor: int,
        categories: set[str] | None = None,
        heartbeat_interval: float = 15.0,
    ) -> None:
        while True:
            new_events = self._collect_stream_events(
                store, cursor, categories, heartbeat_interval
            )
            if new_events:
                cursor = self._write_stream_events(new_events)
            else:
                self._write_stream_heartbeat()

    def stream_events(
        self,
        since: int = 0,
        categories: set[str] | None = None,
    ) -> None:
        if STATE is None:
            self.send_json({"error": "bridge state unavailable"}, 500)
            return

        store = STATE.events
        try:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache, no-transform")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            self.wfile.flush()
            cursor = self._send_stream_gap(store, since)
            self._stream_loop(store, cursor, categories=categories)
        except CLIENT_DISCONNECT_ERRORS:
            return

    # ------------------------------------------------------------------

    def request_json(self) -> dict[str, Any]:

        length = int(
            self.headers.get(
                "Content-Length",
                "0",
            )
        )

        if length > 1_000_000:
            raise ValueError("request body too large")

        raw = self.rfile.read(length)

        if not raw:
            return {}

        result = json.loads(raw.decode("utf-8"))

        if not isinstance(
            result,
            dict,
        ):
            raise TypeError("JSON body must be an object")

        return result

    # ------------------------------------------------------------------

    def do_GET(self) -> None:

        try:
            parsed = urllib.parse.urlsplit(self.path)

            query = urllib.parse.parse_qs(parsed.query)

            self.route(
                "GET",
                parsed.path,
                query,
            )

        except Exception as exc:
            self.send_json(
                {
                    "error": str(exc),
                },
                500,
            )

    # ------------------------------------------------------------------

    def do_POST(self) -> None:

        try:
            parsed = urllib.parse.urlsplit(self.path)

            query = urllib.parse.parse_qs(parsed.query)

            self.route(
                "POST",
                parsed.path,
                query,
            )

        except Exception as exc:
            self.send_json(
                {
                    "error": str(exc),
                },
                500,
            )

    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # ROUTE DISPATCHERS
    # ------------------------------------------------------------------

    def _route_dashboard(self) -> None:
        self.send_html(DASHBOARD)

    def _route_status(self) -> None:
        if STATE is None:
            self.send_json({"error": "bridge state unavailable"}, 500)
            return
        self.send_json(STATE.status())

    def _route_snapshot(self, query: dict[str, list[str]]) -> None:
        if STATE is None:
            self.send_json({"error": "bridge state unavailable"}, 500)
            return
        limits = {
            "events": parse_bounded_int(
                query.get("events_limit", ["50"])[0], default=50, min_val=1, max_val=200
            ),
            "procs": parse_bounded_int(
                query.get("procs_limit", ["30"])[0], default=30, min_val=1, max_val=100
            ),
            "tree": parse_bounded_int(
                query.get("tree_limit", ["50"])[0], default=50, min_val=1, max_val=200
            ),
            "max_bytes": parse_bounded_int(
                query.get("max_bytes", ["0"])[0],
                default=DEFAULT_SNAPSHOT_BYTE_BUDGET,
                min_val=1024,
                max_val=MAX_SNAPSHOT_BYTE_BUDGET,
            ),
        }

        raw_path = query.get("path", [str(Path.cwd())])[0]
        try:
            target_root = resolve_path(raw_path)
        except ValueError:
            target_root = Path.cwd()

        snapshot = build_context_snapshot(
            state=STATE,
            limits=limits,
            root_path=target_root,
        )
        self.send_json(snapshot)

    def _route_events(self, query: dict[str, list[str]]) -> None:
        if STATE is None:
            self.send_json({"error": "bridge state unavailable"}, 500)
            return
        since = parse_bounded_int(query.get("since", ["0"])[0], default=0, min_val=0)
        limit = parse_bounded_int(
            query.get("limit", ["100"])[0], default=100, min_val=1, max_val=MAX_EVENTS
        )
        cat_param = query.get("category") or query.get("categories")
        categories = (
            [c.strip().lower() for c in cat_param[0].split(",")] if cat_param else None
        )
        max_bytes = parse_bounded_int(
            query.get("max_bytes", ["0"])[0],
            default=DEFAULT_EVENTS_BYTE_BUDGET,
            min_val=512,
            max_val=MAX_EVENTS_BYTE_BUDGET,
        )
        gap_detected, oldest_id = STATE.events.check_gap(since)
        events = STATE.events.get_since(
            since, limit, categories=categories, max_bytes=max_bytes
        )
        payload = {
            "events": events,
            "latest_id": STATE.events.sequence,
            "oldest_available": oldest_id,
            "gap_detected": gap_detected,
            "count": len(events),
            "categories_filter": categories,
        }
        if gap_detected:
            payload["recommended_action"] = "get_context_snapshot"
        self.send_json(payload)

    def _route_events_stream(self, query: dict[str, list[str]]) -> None:
        since = parse_bounded_int(query.get("since", ["0"])[0], default=0, min_val=0)
        cat_param = query.get("category") or query.get("categories")
        categories = (
            {c.strip().lower() for c in cat_param[0].split(",")} if cat_param else None
        )
        self.stream_events(since=since, categories=categories)

    def _route_processes(self) -> None:
        self.send_json({"processes": get_processes()})

    def _route_tree(self, query: dict[str, list[str]]) -> None:
        raw = query.get("path", [str(Path.cwd())])[0]
        try:
            result = filesystem_tree(resolve_path(raw))
            self.send_json(result)
        except (ValueError, OSError) as exc:
            self.send_json({"error": str(exc)}, 400)

    def _route_file(self, query: dict[str, list[str]]) -> None:
        raw = query.get("path", [""])[0]
        try:
            result = read_file(resolve_path(raw))
            self.send_json(result)
        except (ValueError, OSError, UnicodeDecodeError) as exc:
            self.send_json({"error": str(exc)}, 400)

    def _route_last_error(self, query: dict[str, list[str]]) -> None:
        if STATE is None:
            self.send_json({"error": "bridge state unavailable"}, 500)
            return
        inc_param = query.get("include_snippets", ["true"])[0].lower()
        include_snippets = inc_param not in ("false", "0", "no")
        last_err = STATE.failure_tracker.get_last_error(
            include_snippets=include_snippets
        )
        self.send_json(last_err or {"status": "no_errors_recorded"})

    def _route_mcp_discovery(self) -> None:
        if STATE is None:
            self.send_json({"error": "bridge state unavailable"}, 500)
            return
        mcp_srv = get_mcp_server()
        self.send_json(
            {
                "protocolVersion": MCPProtocol.PROTOCOL_VERSION,
                "serverInfo": {
                    "name": APP_NAME,
                    "version": VERSION,
                },
                "capabilities": {
                    "tools": {
                        "listChanged": False,
                    },
                },
                "tools": mcp_srv.registry.get_tools(),
                "transports": {
                    "stdio": {
                        "command": sys.executable,
                        "args": [
                            str(Path(__file__).resolve()),
                            "--stdio",
                        ]
                        + (["--allow-control"] if STATE.allow_control else []),
                    },
                    "http": {
                        "status": "active",
                        "endpoint": "/api/mcp",
                    },
                },
            }
        )

    def _validate_mcp_headers(self, req: dict[str, Any]) -> str | None:
        header_method = self.headers.get("Mcp-Method")
        if header_method:
            req_method = str(req.get("method", "")).strip()
            if header_method.strip().lower() != req_method.lower():
                return (
                    f"Header Mcp-Method '{header_method}' does not agree with "
                    f"JSON-RPC body method '{req_method}'"
                )

        header_name = self.headers.get("Mcp-Name")
        if header_name and req.get("method") == "tools/call":
            params = req.get("params") or {}
            body_tool_name = params.get("name") if isinstance(params, dict) else None
            if header_name.strip() != str(body_tool_name or "").strip():
                return (
                    f"Header Mcp-Name '{header_name}' does not agree with "
                    f"JSON-RPC tool name '{body_tool_name}'"
                )
        return None

    def _build_mcp_response_headers(self, req: dict[str, Any]) -> dict[str, str]:
        resp_headers = {
            "MCP-Protocol-Version": MCPProtocol.PROTOCOL_VERSION,
        }
        if "method" in req:
            resp_headers["Mcp-Method"] = str(req["method"])
        if req.get("method") == "tools/call":
            params = req.get("params")
            if isinstance(params, dict) and "name" in params:
                resp_headers["Mcp-Name"] = str(params["name"])
        return resp_headers

    def _validate_mcp_post_preconditions(self) -> int | None:
        proto_header = self.headers.get("MCP-Protocol-Version") or self.headers.get(
            "Mcp-Protocol-Version"
        )
        if proto_header and proto_header.strip() not in (
            MCPProtocol.PROTOCOL_VERSION,
            "2026-07-28",
        ):
            self.send_json(
                {
                    "error": (
                        f"Unsupported MCP protocol version '{proto_header}'. "
                        f"Supported: {MCPProtocol.PROTOCOL_VERSION}"
                    )
                },
                status=400,
                extra_headers={"MCP-Protocol-Version": MCPProtocol.PROTOCOL_VERSION},
            )
            return None

        length = int(self.headers.get("Content-Length", "0"))
        if length > 1_000_000:
            self.send_json(
                {"error": "request body too large"},
                status=413,
                extra_headers={"MCP-Protocol-Version": MCPProtocol.PROTOCOL_VERSION},
            )
            return None
        return length

    def _read_and_parse_mcp_payload(
        self, length: int
    ) -> tuple[dict[str, Any] | None, str | None]:
        raw_bytes = self.rfile.read(length)
        try:
            raw_text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            self.send_json(
                MCPProtocol.error_response(
                    None,
                    MCPProtocol.PARSE_ERROR,
                    f"Invalid UTF-8 encoding: {exc}",
                ),
                status=400,
                extra_headers={"MCP-Protocol-Version": MCPProtocol.PROTOCOL_VERSION},
            )
            return None, None

        req, parse_err = MCPProtocol.parse_request(raw_text)
        if parse_err is not None:
            self.send_json(
                parse_err,
                status=400,
                extra_headers={"MCP-Protocol-Version": MCPProtocol.PROTOCOL_VERSION},
            )
            return None, None

        if req is None:
            self.send_json(
                MCPProtocol.error_response(
                    None,
                    MCPProtocol.INVALID_REQUEST,
                    "Empty request",
                ),
                status=400,
                extra_headers={"MCP-Protocol-Version": MCPProtocol.PROTOCOL_VERSION},
            )
            return None, None

        header_err = self._validate_mcp_headers(req)
        if header_err is not None:
            self.send_json(
                {"error": header_err},
                status=400,
                extra_headers={"MCP-Protocol-Version": MCPProtocol.PROTOCOL_VERSION},
            )
            return None, None

        return req, raw_text

    def _read_and_parse_mcp_request(self) -> tuple[dict[str, Any] | None, str | None]:
        length = self._validate_mcp_post_preconditions()
        if length is None:
            return None, None
        return self._read_and_parse_mcp_payload(length)

    def _route_mcp_post(self) -> None:
        req, raw_text = self._read_and_parse_mcp_request()
        if req is None or raw_text is None:
            return

        mcp_srv = get_mcp_server()
        auth_ok = valid_control_token(self)
        response = mcp_srv.handle_message(raw_text, auth_ok=auth_ok)

        if response is None:
            self.send_response(HTTPStatus.NO_CONTENT)
            self.send_header("MCP-Protocol-Version", MCPProtocol.PROTOCOL_VERSION)
            self.end_headers()
            return

        resp_headers = self._build_mcp_response_headers(req)
        status_code = 200
        if response.get("error"):
            err_code = response["error"].get("code")
            if err_code in (MCPProtocol.PARSE_ERROR, MCPProtocol.INVALID_REQUEST):
                status_code = 400

        self.send_json(
            response,
            status=status_code,
            extra_headers=resp_headers,
        )

    def _route_auth_verify(self) -> None:
        if not valid_control_token(self):
            self.send_json(
                {
                    "authenticated": False,
                    "error": "control disabled or invalid token",
                },
                403,
            )
            return
        self.send_json({"authenticated": True})

    def _route_shell_start(self) -> None:
        if not valid_control_token(self):
            self.send_json({"error": "control disabled or invalid token"}, 403)
            return
        if STATE is None:
            self.send_json({"error": "bridge state unavailable"}, 500)
            return
        STATE.shell.start()
        self.send_json(
            {
                "ok": True,
                "shell": STATE.shell.status(),
            }
        )

    def _route_shell_input(self) -> None:
        if not valid_control_token(self):
            self.send_json({"error": "control disabled or invalid token"}, 403)
            return
        if STATE is None:
            self.send_json({"error": "bridge state unavailable"}, 500)
            return
        body = self.request_json()
        command = str(body.get("command", ""))
        if len(command) > 10_000:
            self.send_json({"error": "command too long"}, 400)
            return
        try:
            STATE.shell.send(command)
            self.send_json({"ok": True})
        except (RuntimeError, ValueError, OSError) as exc:
            self.send_json({"error": str(exc)}, 400)

    def _route_shell_stop(self) -> None:
        if not valid_control_token(self):
            self.send_json({"error": "control disabled or invalid token"}, 403)
            return
        if STATE is None:
            self.send_json({"error": "bridge state unavailable"}, 500)
            return
        STATE.shell.stop()
        self.send_json({"ok": True})

    def _route_events_clear(self) -> None:
        if not valid_control_token(self):
            self.send_json({"error": "control disabled or invalid token"}, 403)
            return
        if STATE is None:
            self.send_json({"error": "bridge state unavailable"}, 500)
            return
        STATE.events.clear()
        self.send_json({"ok": True})

    # ------------------------------------------------------------------

    def _dispatch_get(self, path: str, query: dict[str, list[str]]) -> bool:
        get_actions = {
            "/": self._route_dashboard,
            "/api/status": self._route_status,
            "/api/processes": self._route_processes,
            "/api/mcp": self._route_mcp_discovery,
            "/api/auth/verify": self._route_auth_verify,
        }
        action = get_actions.get(path)
        if action is not None:
            action()
            return True

        query_actions = {
            "/api/snapshot": self._route_snapshot,
            "/api/events": self._route_events,
            "/api/events/stream": self._route_events_stream,
            "/api/tree": self._route_tree,
            "/api/file": self._route_file,
            "/api/last_error": self._route_last_error,
        }
        query_action = query_actions.get(path)
        if query_action is not None:
            query_action(query)
            return True

        return False

    def _dispatch_post(self, path: str) -> bool:
        post_actions = {
            "/api/mcp": self._route_mcp_post,
            "/api/auth/verify": self._route_auth_verify,
            "/api/shell/start": self._route_shell_start,
            "/api/shell/input": self._route_shell_input,
            "/api/shell/stop": self._route_shell_stop,
            "/api/events/clear": self._route_events_clear,
        }
        post_action = post_actions.get(path)
        if post_action is not None:
            post_action()
            return True
        return False

    def route(
        self,
        method: str,
        path: str,
        query: dict[str, list[str]],
    ) -> None:
        if STATE is None:
            raise RuntimeError("bridge state unavailable")

        handled = False
        if method == "GET":
            handled = self._dispatch_get(path, query)
        elif method == "POST":
            handled = self._dispatch_post(path)

        if not handled:
            self.send_json(
                {"error": "endpoint not found"},
                404,
            )


# ============================================================================
# CLI
# ============================================================================


def _configure_network_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--env-file",
        default=str(ENV_FILE),
        help=f"Path to .env file to load. Default: {ENV_FILE}",
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help="Interface to bind to. Default: 127.0.0.1",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="HTTP port. Default: 8765",
    )
    parser.add_argument(
        "--shell",
        choices=["powershell", "cmd"],
        default=("powershell" if os.name == "nt" else "cmd"),
    )


def _configure_feature_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--allow-control",
        action="store_true",
        default=False,
        help="Enable command execution and other mutating APIs.",
    )
    parser.add_argument(
        "--no-control",
        action="store_true",
        help="Explicitly disable control APIs even if CONTROL_TOKEN is set.",
    )
    parser.add_argument(
        "--token",
        help="Bearer token for control APIs. If omitted, loaded from CONTROL_TOKEN in .env or generated.",
    )
    parser.add_argument(
        "--stdio",
        action="store_true",
        default=False,
        help="Run Model Context Protocol (MCP) server over standard input/output.",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="Open the dashboard in the browser.",
    )
    parser.add_argument(
        "--no-mask-secrets",
        action="store_true",
        default=False,
        help="Disable automatic heuristic redaction of credentials in event stream.",
    )


def _configure_cli_arguments(parser: argparse.ArgumentParser) -> None:
    _configure_network_arguments(parser)
    _configure_feature_arguments(parser)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=f"{APP_NAME} {VERSION}")
    _configure_cli_arguments(parser)
    return parser.parse_args()


# ============================================================================
# MAIN
# ============================================================================


def resolve_control_settings(args: argparse.Namespace) -> tuple[bool, str | None]:
    token = args.token or os.environ.get("CONTROL_TOKEN")

    if args.no_control:
        allow_control = False
    elif args.allow_control:
        allow_control = True
    elif "ALLOW_CONTROL" in os.environ:
        allow_control = os.environ.get("ALLOW_CONTROL", "").strip().lower() in (
            "1",
            "true",
            "yes",
        )
    else:
        allow_control = bool(token)

    if allow_control and not token:
        token = generate_token()

    return allow_control, token


def print_startup_banner(
    address: str,
    args: argparse.Namespace,
    allow_control: bool,
    token: str | None,
) -> None:
    print()
    print("=" * 60)
    print(f"{APP_NAME} {VERSION}")
    print("=" * 60)
    print()
    print(f"Dashboard : {address}/")
    print(f"API       : {address}/api/status")
    print(f"Snapshot  : {address}/api/snapshot")
    print(f"SSE Stream: {address}/api/events/stream")
    print(f"MCP info  : {address}/api/mcp")
    print()
    print(f"Host      : {args.host}")
    print(f"Port      : {args.port}")
    print(f"Shell     : {args.shell}")
    print("Control   : " + ("ENABLED" if allow_control else "DISABLED"))

    if allow_control:
        print()
        print("CONTROL TOKEN:")
        if args.token:
            print(token)
        elif os.environ.get("CONTROL_TOKEN"):
            print("******** (loaded from .env)")
        else:
            print(token)
        print()
        print("Keep this token private.")

    print()
    print("Press Ctrl+C to stop.")
    print()


def main() -> int:
    global STATE

    args = parse_arguments()

    if args.env_file:
        load_env_file(args.env_file)

    if not (1 <= args.port <= 65535):
        raise SystemExit("Invalid port.")

    allow_control, token = resolve_control_settings(args)

    STATE = BridgeState(
        allow_control=allow_control,
        token=token,
        shell=args.shell,
        mask_secrets=not args.no_mask_secrets,
    )

    if args.stdio:
        mcp_server = get_mcp_server()
        return run_stdio(mcp_server)

    ThreadingHTTPServer.allow_reuse_address = False
    server = ThreadingHTTPServer(
        (
            args.host,
            args.port,
        ),
        BridgeHandler,
    )

    address = f"http://{args.host}:{args.port}"
    print_startup_banner(address, args, allow_control, token)

    if args.open:
        webbrowser.open(address)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
        print("Stopping...")
    finally:
        if STATE is not None:
            STATE.shell.stop()
        server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
