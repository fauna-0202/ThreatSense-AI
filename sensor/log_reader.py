"""Incremental Zeek log reader with rotation tracking and recovery."""

import os
import time
from pathlib import Path
from typing import Generator, Optional
from threatsense.logging import logger


class IncrementalLogReader:
    """Incrementally reads growing Zeek log files, handling rotation and reconnects."""

    def __init__(self, log_path: str, poll_interval: float = 1.0):
        self.log_path = Path(log_path)
        self.poll_interval = poll_interval
        self._last_position = 0
        self._last_inode = None
        self._running = False

    def _get_file_stat(self):
        if not self.log_path.exists():
            return None
        st = self.log_path.stat()
        # In Windows, st_ino may be 0, so track size & mtime as well
        return (getattr(st, "st_ino", 0), st.st_size, st.st_mtime)

    def read_new_lines(self) -> Generator[str, None, None]:
        if not self.log_path.exists():
            return

        stat = self._get_file_stat()
        if not stat:
            return

        current_size = stat[1]

        # Check for rotation or file truncation
        if current_size < self._last_position:
            logger.info(f"Log rotation or truncation detected for {self.log_path}. Resetting position.")
            self._last_position = 0

        try:
            with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._last_position)
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        yield stripped
                self._last_position = f.tell()
        except Exception as e:
            logger.warning(f"Error reading {self.log_path}: {e}")

    def follow(self) -> Generator[str, None, None]:
        """Generator that continuously yields new lines as they arrive."""
        self._running = True
        logger.info(f"Following log file {self.log_path} at {self.poll_interval}s intervals")

        while self._running:
            found_any = False
            for line in self.read_new_lines():
                found_any = True
                yield line

            if not found_any:
                time.sleep(self.poll_interval)

    def stop(self):
        self._running = False
