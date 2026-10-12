"""Offline PCAP / Zeek log replay runner."""

from pathlib import Path
from typing import Generator, List
import time
from threatsense.ingestion.parser import ZeekParser, ParseResult
from threatsense.ingestion.schemas import IngestedEvent
from threatsense.logging import logger


class ReplayEngine:
    """Reads offline Zeek connection logs or sanitized samples deterministically."""

    def __init__(self, sample_file_path: str):
        self.file_path = Path(sample_file_path)
        self.parser = ZeekParser()

    def stream_events(self, delay_seconds: float = 0.0) -> Generator[IngestedEvent, None, None]:
        if not self.file_path.exists():
            logger.error(f"Replay sample file not found: {self.file_path}")
            return

        logger.info(f"Starting offline replay from {self.file_path}")
        with open(self.file_path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                res: ParseResult = self.parser.parse_line(line, data_source="replay")
                if res.success and res.event:
                    yield res.event
                    if delay_seconds > 0:
                        time.sleep(delay_seconds)
                elif res.error and not res.error.startswith("Comment"):
                    logger.debug(f"Line {line_no} skipped: {res.error}")

    def load_all(self) -> List[IngestedEvent]:
        """Loads all valid events in memory."""
        return list(self.stream_events(delay_seconds=0.0))
