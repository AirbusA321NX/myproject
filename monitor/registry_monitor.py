import threading
import time
import win32api
import win32con
import winreg
import hashlib
from utils.logger import log_event
from utils.popups import show_popup
from ai.mistral_analysis import analyze_text

_SERVICES_PATH = r"SYSTEM\CurrentControlSet\Services"

def _hash_key_values(root, subkey_path):
    """
    Returns a dict: { value_name: sha256_of_value_data } for all values under root\subkey_path.
    """
    result = {}
    try:
        key = winreg.OpenKey(root, subkey_path, 0, winreg.KEY_READ)
    except FileNotFoundError:
        return result
    try:
        i = 0
        while True:
            name, data, _ = winreg.EnumValue(key, i)
            if isinstance(data, str):
                raw = data.encode('utf-16le')
            elif isinstance(data, bytes):
                raw = data
            else:
                raw = str(data).encode()
            h = hashlib.sha256(raw).hexdigest()
            result[name] = h
            i += 1
    except OSError:
        pass
    winreg.CloseKey(key)
    return result

def _snapshot_all_services():
    root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _SERVICES_PATH)
    snapshot = {}
    try:
        i = 0
        while True:
            sub = winreg.EnumKey(root, i)
            full = f"{_SERVICES_PATH}\\{sub}"
            snapshot[full] = _hash_key_values(winreg.HKEY_LOCAL_MACHINE, full)
            i += 1
    except OSError:
        pass
    winreg.CloseKey(root)
    return snapshot

def _monitor_loop():
    prev_snapshot = _snapshot_all_services()
    reg_handle = win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE, _SERVICES_PATH, 0, win32con.KEY_READ)
    while True:
        try:
            # This will block until any subkey/value under Services changes
            win32api.RegNotifyChangeKeyValue(
                reg_handle,
                True,
                win32con.REG_NOTIFY_CHANGE_NAME | win32con.REG_NOTIFY_CHANGE_LAST_SET,
                None,
                False
            )
            time.sleep(0.5)  # brief debounce
            new_snapshot = _snapshot_all_services()
            # Compare
            for key_path, new_vals in new_snapshot.items():
                old_vals = prev_snapshot.get(key_path, {})
                # Check added or modified values
                for name, h in new_vals.items():
                    if name not in old_vals:
                        detail = f"New registry value '{name}' under '{key_path}'"
                        _flag_registry_change(detail)
                    elif old_vals[name] != h:
                        detail = f"Modified registry value '{name}' under '{key_path}'"
                        _flag_registry_change(detail)
                # Check deleted values
                for name in old_vals:
                    if name not in new_vals:
                        detail = f"Deleted registry value '{name}' under '{key_path}'"
                        _flag_registry_change(detail)
            # Check removed service keys
            for key_path in set(prev_snapshot) - set(new_snapshot):
                detail = f"Deleted registry key '{key_path}' under Services"
                _flag_registry_change(detail)
            # Check newly added service keys
            for key_path in set(new_snapshot) - set(prev_snapshot):
                detail = f"New registry key '{key_path}' under Services"
                _flag_registry_change(detail)
            prev_snapshot = new_snapshot
        except Exception as e:
            log_event("REGISTRY_MONITOR_ERROR", str(e))
            time.sleep(1)

def _flag_registry_change(detail: str):
    try:
        result = analyze_text(f"REGISTRY_CHANGE: {detail}")
    except Exception:
        show_popup("Guardrail AI Failure", "AI analysis failed for registry change. Restarting AI service.")
        try:
            analyze_text("ping")
        except:
            pass
        return
    lower = result.lower()
    if any(k in lower for k in ["danger", "disable", "malicious", "unauthorized"]):
        show_popup("Guardrail Alert: Registry Change", result)
        log_event("REGISTRY_FLAGGED", f"{detail} | AI: {result}")

def start_monitor():
    _monitor_loop()
