"""RAM numbers for the dashboard, without extra packages (uses psutil only if installed)."""
import os
import sys

try:
    import psutil
except ImportError:
    psutil = None

MODEL_PROC_NAMES = ("llama-server", "llama_server", "ollama")


def backend_rss_mb():
    if psutil:
        return round(psutil.Process().memory_info().rss / 2**20, 1)
    try:                                           # Linux
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return round(int(line.split()[1]) / 1024, 1)
    except OSError:
        pass
    if sys.platform == "win32":                    # Windows, via the Win32 API
        try:
            import ctypes
            from ctypes import wintypes

            class PMC(ctypes.Structure):
                _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                            ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                            ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
            pmc = PMC()
            pmc.cb = ctypes.sizeof(PMC)
            h = ctypes.windll.kernel32.GetCurrentProcess()
            if ctypes.windll.psapi.GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb):
                return round(pmc.WorkingSetSize / 2**20, 1)
        except Exception:
            return None
    return None


def model_rss_mb():
    """RAM of a llama-server / ollama process on the same machine, if we can see it."""
    if psutil:
        total = 0
        for p in psutil.process_iter(["name", "memory_info"]):
            name = (p.info.get("name") or "").lower()
            if any(k in name for k in MODEL_PROC_NAMES) and p.info.get("memory_info"):
                total += p.info["memory_info"].rss
        return round(total / 2**20, 1) if total else None
    if os.path.isdir("/proc"):
        total = 0
        for pid in filter(str.isdigit, os.listdir("/proc")):
            try:
                with open(f"/proc/{pid}/comm") as f:
                    if not any(k in f.read().lower() for k in MODEL_PROC_NAMES):
                        continue
                with open(f"/proc/{pid}/status") as f:
                    total += next(int(l.split()[1]) for l in f if l.startswith("VmRSS:"))
            except (OSError, StopIteration):
                continue
        return round(total / 1024, 1) if total else None
    return None


def snapshot():
    b, m = backend_rss_mb(), model_rss_mb()
    return {"backend_mb": b, "model_mb": m,
            "total_mb": round((b or 0) + (m or 0), 1) if (b or m) else None, "limit_mb": 4096}