import time
import threading

try:
    from pynput import keyboard, mouse
    HAS_PYNPUT = True
except ImportError:
    HAS_PYNPUT = False

last_input_time = time.time()
listener_started = False

def on_input(*args):
    global last_input_time
    last_input_time = time.time()

def _start_listeners():
    """Start input listeners in background (best-effort)."""
    global listener_started
    
    if not HAS_PYNPUT:
        return
    
    if listener_started:
        return
    
    def run_listeners():
        try:
            keyboard.Listener(on_press=on_input).start()
            mouse.Listener(on_move=on_input).start()
        except Exception as e:
            pass  # Silently fail - don't crash on headless systems
    
    try:
        thread = threading.Thread(target=run_listeners, daemon=True)
        thread.start()
        listener_started = True
    except:
        pass

# Try to start listeners on import
_start_listeners()

def get_idle_time():
    """Get user idle time in seconds."""
    return time.time() - last_input_time

def get_intent_score():
    """
    Compute intent score based on idle time.
    1.0 = active user, 0.0 = idle user
    """
    idle = get_idle_time()
    
    if idle < 5:
        return 1.0
    elif idle < 30:
        return 0.5
    else:
        return 0.0

