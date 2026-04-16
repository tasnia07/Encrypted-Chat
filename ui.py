"""Console output and input helpers for terminal chat UI."""

from __future__ import annotations

import datetime as dt
import sys
import threading

# prompt_toolkit gives explicit cross-platform cursor editing and input history.
try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import InMemoryHistory
    from prompt_toolkit.patch_stdout import patch_stdout
except ImportError:  # pragma: no cover - exercised only when dependency is missing.
    PromptSession = None
    InMemoryHistory = None
    patch_stdout = None


class _Palette:
    RESET = "\033[0m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    MAGENTA = "\033[35m"
    GRAY = "\033[90m"
    BLACK_ON_WHITE = "\033[30;47m"


def _enable_windows_vt(stream: object) -> bool:
    if sys.platform != "win32":
        return True
    try:
        fileno = stream.fileno()  # type: ignore[attr-defined]
    except (AttributeError, OSError, ValueError):
        return False
    try:
        import ctypes
        import msvcrt
    except ImportError:
        return False
    try:
        handle = msvcrt.get_osfhandle(fileno)
    except OSError:
        return False
    if handle == -1:
        return False
    kernel32 = ctypes.windll.kernel32
    mode = ctypes.c_uint32()
    handle_obj = ctypes.c_void_p(handle)
    if kernel32.GetConsoleMode(handle_obj, ctypes.byref(mode)) == 0:
        return False
    enable_vt = 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    if mode.value & enable_vt:
        return True
    return kernel32.SetConsoleMode(handle_obj, mode.value | enable_vt) != 0


def _clock(ts: int | None = None) -> str:
    if ts is None:
        return dt.datetime.now().strftime("%H:%M:%S")
    return dt.datetime.fromtimestamp(ts).strftime("%H:%M:%S")


class Console:
    def __init__(self, use_color: bool = True):
        color_requested = use_color and sys.stdout.isatty()
        if color_requested and sys.platform == "win32":
            color_requested = _enable_windows_vt(sys.stdout)
        self._use_color = color_requested
        self._lock = threading.Lock()

    @property
    def use_color(self) -> bool:
        return self._use_color

    def _paint(self, text: str, color: str | None) -> str:
        if not self._use_color or not color:
            return text
        return f"{color}{text}{_Palette.RESET}"

    def _emit(
        self,
        prefix: str,
        message: str,
        *,
        color: str | None = None,
        ts: int | None = None,
        color_whole_line: bool = False,
    ) -> None:
        stamp = _clock(ts)
        label = f"{prefix:<10}"
        if self._use_color:
            if color_whole_line and color:
                line = self._paint(f"{stamp} {label} {message}", color)
            else:
                line = f"{self._paint(stamp, _Palette.GRAY)} {self._paint(label, color)} {message}"
        else:
            line = f"{stamp} {label} {message}"
        with self._lock:
            print(line, flush=True)

    def info(self, message: str) -> None:
        self._emit("[INFO]", message, color=_Palette.CYAN)

    def success(self, message: str) -> None:
        self._emit("[OK]", message, color=_Palette.GREEN)

    def warn(self, message: str) -> None:
        self._emit("[WARN]", message, color=_Palette.YELLOW)

    def error(self, message: str) -> None:
        self._emit("[ERR]", message, color=_Palette.RED)

    def system(self, message: str) -> None:
        self._emit("[SYS]", message, color=_Palette.MAGENTA)

    def chat(self, *, incoming: bool, sender: str, text: str, encrypted: bool, ts: int) -> None:
        direction = "IN" if incoming else "OUT"
        label = "SEC" if encrypted else "PLAIN"
        prefix = f"[{direction}-{label}]"
        color = _Palette.BLACK_ON_WHITE
        self._emit(prefix, f"{sender}: {text}", color=color, ts=ts, color_whole_line=True)


class ChatInput:
    def __init__(self, *, prompt: str = "chat> "):
        if PromptSession is None or InMemoryHistory is None or patch_stdout is None:
            raise RuntimeError(
                "Missing dependency: prompt_toolkit. Install with "
                "'python -m pip install prompt_toolkit' for editable chat input."
            )
        self._prompt = prompt
        self._session = PromptSession(history=InMemoryHistory())

    def read_line(self) -> str:
        if not sys.stdin.isatty():
            return input(self._prompt)
        with patch_stdout(raw=True):
            return self._session.prompt(self._prompt)
