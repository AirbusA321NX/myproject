import threading
import keyboard
import pyperclip
import time
import win32gui
from utils.logger import log_event
from utils.popups import show_popup
from ai.mistral_analysis import analyze_text

_buffer = ""
_buffer_lock = threading.Lock()

def _get_active_window_class():
    hwnd = win32gui.GetForegroundWindow()
    if hwnd == 0:
        return None
    return win32gui.GetClassName(hwnd)

def _process_command(command: str):
    try:
        result = analyze_text(f"CMD: {command}")
    except Exception:
        show_popup("Guardrail AI Failure", "AI analysis failed for command. Restarting AI service.")
        time.sleep(2)
        try:
            # attempt reload by calling analyze_text on a trivial prompt
            analyze_text("ping")
        except:
            pass
        return

    lower = result.lower()
    if any(k in lower for k in ["danger", "delete", "unstable", "harm", "risk", "breach"]):
        # Show the AI explanation
        show_popup("Guardrail Alert: Dangerous CMD Detected", result)
        log_event("CMD_FLAGGED", f"Command: {command} | AI_response: {result}")

def _on_key(event):
    global _buffer
    try:
        active_class = _get_active_window_class()
        # Only buffer when console is active
        if active_class == "ConsoleWindowClass":
            if event.event_type == "down":
                if event.name == "enter":
                    with _buffer_lock:
                        cmd = _buffer.strip()
                        _buffer = ""
                    if cmd:
                        _process_command(cmd)
                elif event.name == "backspace":
                    with _buffer_lock:
                        _buffer = _buffer[:-1]
                elif event.name == "v" and keyboard.is_pressed("ctrl"):
                    # Grab entire clipboard as paste
                    try:
                        clip = pyperclip.paste()
                        with _buffer_lock:
                            _buffer += clip
                    except:
                        pass
                elif len(event.name) == 1:
                    with _buffer_lock:
                        _buffer += event.name
                # ignore other special keys
    except Exception as e:
        # swallow to keep hook alive
        log_event("CMD_MONITOR_ERROR", str(e))

def start_monitor():
    keyboard.hook(_on_key, suppress=False)
    # Keep thread alive indefinitely
    while True:
        time.sleep(1)
