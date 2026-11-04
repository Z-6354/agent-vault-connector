"""Exercise the built EXE without credentials: window startup and close-to-tray."""
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import subprocess
import time

user32 = ctypes.WinDLL("user32", use_last_error=True)
callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
user32.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetClientRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
exe = Path(__file__).resolve().parent / "target/release/agent-vault-desktop.exe"
process = subprocess.Popen([str(exe)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
report = {"executable": str(exe), "pid": process.pid}
try:
    windows = []
    @callback_type
    def collect(hwnd, _):
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value == process.pid and user32.IsWindowVisible(hwnd):
            title = ctypes.create_unicode_buffer(512)
            user32.GetWindowTextW(hwnd, title, len(title))
            if title.value == "Agent Vault":
                windows.append(hwnd)
        return True
    deadline = time.monotonic() + 20
    while not windows and process.poll() is None and time.monotonic() < deadline:
        user32.EnumWindows(collect, 0)
        time.sleep(0.1)
    if not windows:
        raise RuntimeError(f"Main window did not appear; exit={process.poll()}")
    hwnd = windows[0]
    rect = wintypes.RECT()
    if not user32.GetClientRect(hwnd, ctypes.byref(rect)):
        raise RuntimeError("Main window rectangle unavailable")
    report.update(main_window_visible=True, client_width=rect.right - rect.left, client_height=rect.bottom - rect.top)
    if not user32.PostMessageW(hwnd, 0x0010, 0, 0):
        raise RuntimeError("Close request failed")
    deadline = time.monotonic() + 5
    while user32.IsWindowVisible(hwnd) and time.monotonic() < deadline:
        time.sleep(0.05)
    report.update(close_hides_window=not bool(user32.IsWindowVisible(hwnd)), process_survives_close=process.poll() is None)
    if not report["close_hides_window"] or not report["process_survives_close"]:
        raise RuntimeError("Close-to-tray check failed")
    report["result"] = "passed"
    print(json.dumps(report))
finally:
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=10)
