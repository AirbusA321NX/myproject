import threading
import time
import psutil
import wmi
import hashlib
from utils.logger import log_event
from utils.popups import show_popup
from ai.mistral_analysis import analyze_text

_c = wmi.WMI()

def _compute_sha256(path: str) -> str:
    try:
        hasher = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except:
        return "N/A"

def _monitor_loop():
    process_watcher = _c.Win32_Process.watch_for("creation")
    while True:
        try:
            new_proc = process_watcher()
            pid = int(new_proc.ProcessId)
            parent_pid = int(new_proc.ParentProcessId)
            try:
                proc = psutil.Process(pid)
            except psutil.NoSuchProcess:
                continue

            # Always record full cmdline + sha256 for logs
            cmdline = " ".join(proc.cmdline()) if proc and proc.cmdline() else ""
            exe = proc.exe() if proc else ""
            sha256 = _compute_sha256(exe) if exe else "N/A"

            # Send minimal info to AI: name + pid
            to_ai = f"NewProcess Name: {proc.name() if proc else 'Unknown'} PID: {pid}"

            # If parent is cmd.exe or powershell.exe:
            parent_name = ""
            try:
                parent = psutil.Process(parent_pid)
                parent_name = parent.name().lower()
            except:
                parent_name = ""

            def check_lifetime():
                start_time = time.time()
                while True:
                    if not psutil.pid_exists(pid):
                        duration = time.time() - start_time
                        if duration < 5:
                            try:
                                result = analyze_text(f"SHORT_LIVED from {parent_name}: {to_ai}")
                                lower = result.lower()
                                if any(k in lower for k in ["danger", "malware", "suspicious", "harm"]):
                                    show_popup("Guardrail Alert: Short-lived Process", result)
                                    log_event("SHORT_LIVED_FLAGGED", f"PID: {pid} Parent: {parent_name} Cmd: {cmdline} SHA256: {sha256} | AI: {result}")
                            except Exception:
                                show_popup("Guardrail AI Failure", "AI analysis failed for short-lived process. Restarting AI service.")
                                try:
                                    analyze_text("ping")
                                except:
                                    pass
                        return
                    time.sleep(0.5)

            # Spawn a thread to watch lifetime
            threading.Thread(target=check_lifetime, daemon=True).start()

            # Immediately analyze creation (non-parents flagged too)
            try:
                result = analyze_text(f"PROCESS_CREATION: {to_ai}")
                lower = result.lower()
                if any(k in lower for k in ["danger", "suspicious", "unauthorized"]):
                    show_popup("Guardrail Alert: New Process Flagged", result)
                    log_event("PROCESS_FLAGGED", f"PID: {pid} Parent: {parent_name} Cmd: {cmdline} SHA256: {sha256} | AI: {result}")
            except Exception:
                show_popup("Guardrail AI Failure", "AI analysis failed for process creation. Restarting AI service.")
                try:
                    analyze_text("ping")
                except:
                    pass

        except Exception as e:
            log_event("PROCESS_MONITOR_ERROR", str(e))
            time.sleep(1)

def start_monitor():
    _monitor_loop()
