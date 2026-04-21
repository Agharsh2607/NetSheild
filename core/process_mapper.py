import psutil

def get_process_state(pid):
    try:
        p = psutil.Process(pid)
        return {
            "name": p.name(),
            "exe": p.exe(),
            "status": p.status(),
            "cpu": p.cpu_percent(interval=0.1),
            "memory": p.memory_percent()
        }
    except:
        return None
