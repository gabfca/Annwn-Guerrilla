import sqlite3
import threading
import time
import traceback
from typing import Callable, List, Optional, Dict

class Pwyll:
    def __init__(self, db_path: str, poll_interval: float = 1.0, async_hooks: bool = False) -> None:
        """
        Initialize Pwyll event watcher.

        Args:
            db_path: Path to SQLite database.
            poll_interval: Time in seconds between polling the DB.
            async_hooks: Whether to run hooks asynchronously.
        """
        self.db_path: str = db_path
        self.poll_interval: float = poll_interval
        self.async_hooks: bool = async_hooks
        self.conn: Optional[sqlite3.Connection] = None
        self.hooks: List[Callable[[Dict], None]] = []
        self._stop_event: threading.Event = threading.Event()
        self._poll_thread: Optional[threading.Thread] = None
        self._last_seen_id: int = 0
        self._connect_db()

    def _connect_db(self) -> None:
        uri = f'file:{self.db_path}?mode=ro'
        try:
            self.conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            cur = self.conn.execute("SELECT MAX(id) as max_id FROM comms_events")
            row = cur.fetchone()
            self._last_seen_id = row["max_id"] if row and row["max_id"] is not None else 0
        except sqlite3.Error as e:
            print(f"Failed to connect to DB: {e}")
            self.conn = None

    def register_hook(self, hook: Callable[[Dict], None]) -> None:
        """Register a new hook."""
        if hook not in self.hooks:
            self.hooks.append(hook)

    def unregister_hook(self, hook: Callable[[Dict], None]) -> None:
        """Unregister an existing hook."""
        if hook in self.hooks:
            self.hooks.remove(hook)

    def get_hooks(self) -> List[Callable[[Dict], None]]:
        """Return the list of currently registered hooks."""
        return self.hooks.copy()

    def start(self) -> None:
        """Start polling the database in a background thread."""
        if self._poll_thread and self._poll_thread.is_alive():
            return
        if not self.conn:
            self._connect_db()
        self._stop_event.clear()
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()

    def stop(self) -> None:
        """Stop polling and wait for the thread to finish."""
        self._stop_event.set()
        if self._poll_thread:
            self._poll_thread.join()

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            self._poll_once()
            time.sleep(self.poll_interval)

    def _poll_once(self) -> None:
        if not self.conn:
            self._connect_db()
            if not self.conn:
                return
        try:
            cur = self.conn.execute(
                "SELECT * FROM comms_events WHERE id > ? ORDER BY id ASC",
                (self._last_seen_id,)
            )
            rows = cur.fetchall()
            for row in rows:
                event = dict(row)
                self._last_seen_id = event["id"]
                self._fire_hooks(event)
        except sqlite3.Error as e:
            print(f"Database polling error: {e}")
            # Attempt to reconnect on error
            self.conn.close()
            self.conn = None

    def _fire_hooks(self, event: Dict) -> None:
        for hook in self.hooks:
            if self.async_hooks:
                threading.Thread(target=self._safe_call_hook, args=(hook, event), daemon=True).start()
            else:
                self._safe_call_hook(hook, event)

    def _safe_call_hook(self, hook: Callable[[Dict], None], event: Dict) -> None:
        try:
            hook(event)
        except Exception:
            print(f"Exception in hook {hook}:")
            traceback.print_exc()

    def close(self) -> None:
        """Stop polling and close DB connection."""
        self.stop()
        if self.conn:
            self.conn.close()
            self.conn = None
