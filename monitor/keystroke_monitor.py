import threading
import keyboard
import pyperclip
import time
import win32gui
from utils.logger import log_event
from utils.popups import show_popup
from ai.mistral_analysis import analyze_text
import psutil

_buffer = ""
_buffer_lock = threading.Lock()

def _get_active_window_class():
    hwnd = win32gui.GetForegroundWindow()
    if hwnd == 0:
        return None
    return win32gui.GetClassName(hwnd)

def _is_terminal_window():
    hwnd = win32gui.GetForegroundWindow()
    if hwnd == 0:
        return False
    try:
        GetWindowThreadProcessId = getattr(win32gui, "GetWindowThreadProcessId")
        _, pid = GetWindowThreadProcessId(hwnd)
        exe = psutil.Process(pid).name().lower()
        return exe in ["cmd.exe", "powershell.exe", "wt.exe", "terminal.exe", "bash.exe"]
    except Exception:
        return False


def _process_input(source: str, content: str):
    try:
        result = analyze_text(f"{source}: {content}")
    except Exception:
        show_popup("Guardrail AI Failure", f"AI analysis failed for {source}. Restarting AI service.")
        time.sleep(2)
        try:
            analyze_text("ping")
        except:
            pass
        return

    lower = result.lower()
    if any(k in lower for k in ["danger", "risky", "harm", "breach", "unauthorized"]):
        show_popup(f"Guardrail Alert: Suspicious Input ({source})", result)
        log_event("KEYSTROKE_FLAGGED", f"{source}: {content} | AI_response: {result}")

def _on_key(event):
    global _buffer
    try:
        active_class = _get_active_window_class()
        if active_class and active_class != "ConsoleWindowClass":
            if event.event_type == "down":
                if event.name == "enter":
                    with _buffer_lock:
                        txt = _buffer.strip()
                        _buffer = ""
                    if txt:
                        _process_input("NON-CMD_WINDOW", txt)
                elif event.name == "backspace":
                    with _buffer_lock:
                        _buffer = _buffer[:-1]
                elif event.name == "v" and keyboard.is_pressed("ctrl"):
                    try:
                        clip = pyperclip.paste()
                        with _buffer_lock:
                            _buffer += clip
                    except:
                        pass
                elif len(event.name) == 1:
                    with _buffer_lock:
                        _buffer += event.name
    except Exception as e:
        log_event("KEYSTROKE_MONITOR_ERROR", str(e))

def start_monitor():
    keyboard.hook(_on_key, suppress=False)
    while True:
        time.sleep(1)
