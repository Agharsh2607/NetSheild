"""
Activity Store - SQLite Database for network events
"""

import sqlite3
import threading
import time
from pathlib import Path

# Absolute database path
DB_PATH = Path(__file__).resolve().parent / "ubnad.db"
DB_LOCK = threading.Lock()

def get_connection():
    """Get a SQLite connection to the database."""
    conn = sqlite3.connect(str(DB_PATH), timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize SQLite database with events table."""
    with DB_LOCK:
        try:
            conn = get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                pid INTEGER,
                process_name TEXT,
                dest_ip TEXT,
                dest_port INTEGER,
                intent_score REAL,
                suspicion_score REAL,
                risk_level TEXT
            )
            """)
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"[DB] Init error: {e}")
            return False

def insert_event(event_dict):
    """Insert event into database from dictionary."""
    with DB_LOCK:
        try:
            conn = get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
            INSERT INTO events 
            (timestamp, pid, process_name, dest_ip, dest_port, intent_score, suspicion_score, risk_level)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_dict.get("timestamp"),
                event_dict.get("pid"),
                event_dict.get("process_name"),
                event_dict.get("dest_ip"),
                event_dict.get("dest_port"),
                event_dict.get("intent_score"),
                event_dict.get("suspicion_score"),
                event_dict.get("risk_level")
            ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"[DB] Insert error: {e}")
            return False

def fetch_recent_events(limit=50):
    """Fetch recent events from database."""
    with DB_LOCK:
        try:
            conn = get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
            SELECT * FROM events 
            ORDER BY timestamp DESC 
            LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            return [dict(row) for row in rows]
        except Exception as e:
            print(f"[DB] Fetch error: {e}")
            return []

def get_last_events(limit=50):
    """Get last N events from database."""
    return fetch_recent_events(limit)

def get_alerts(limit=10):
    """Get high/critical risk events."""
    with DB_LOCK:
        try:
            conn = get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
            SELECT * FROM events 
            WHERE risk_level IN ('HIGH', 'CRITICAL')
            ORDER BY timestamp DESC 
            LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            return [dict(row) for row in rows]
        except Exception as e:
            print(f"[DB] Alert fetch error: {e}")
            return []

def get_event_count():
    """Get total event count."""
    with DB_LOCK:
        try:
            conn = get_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM events")
            count = cursor.fetchone()[0]
            conn.close()
            
            return count
        except Exception as e:
            print(f"[DB] Count error: {e}")
            return 0

def clear_old_events(hours=24):
    """Remove events older than N hours."""
    with DB_LOCK:
        try:
            conn = get_connection()
            cursor = conn.cursor()
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB] Clear error: {e}")
