"""Zeek log and JSON record parser."""

import json
from typing import Dict, Any, Optional, Tuple
from threatsense.ingestion.schemas import RawNetworkEvent, IngestedEvent
from threatsense.ingestion.normalizer import normalize_event
from threatsense.logging import logger


class ParseResult:
    def __init__(self, success: bool, event: Optional[IngestedEvent] = None, error: Optional[str] = None):
        self.success = success
        self.event = event
        self.error = error


class ZeekParser:
    """Parses Zeek connection records from JSON or TSV lines."""

    def __init__(self):
        self.tsv_fields: Optional[list[str]] = None

    def parse_dict(self, data: Dict[str, Any], data_source: str = "api") -> ParseResult:
        try:
            # Flatten or map nested Zeek id dictionary if present
            d = data.copy()
            if "id" in d and isinstance(d["id"], dict):
                d["id.orig_h"] = d["id"].get("orig_h")
                d["id.orig_p"] = d["id"].get("orig_p")
                d["id.resp_h"] = d["id"].get("resp_h")
                d["id.resp_p"] = d["id"].get("resp_p")

            # Check if fields use standard names without id.
            if "src_ip" in d and "id.orig_h" not in d:
                d["id.orig_h"] = d["src_ip"]
            if "src_port" in d and "id.orig_p" not in d:
                d["id.orig_p"] = d["src_port"]
            if "dst_ip" in d and "id.resp_h" not in d:
                d["id.resp_h"] = d["dst_ip"]
            if "dst_port" in d and "id.resp_p" not in d:
                d["id.resp_p"] = d["dst_port"]

            d["data_source"] = data_source
            raw = RawNetworkEvent(**d)
            ingested = normalize_event(raw)
            return ParseResult(success=True, event=ingested)
        except Exception as e:
            msg = f"Failed to parse event dictionary: {str(e)}"
            logger.warning(msg)
            return ParseResult(success=False, error=msg)

    def parse_line(self, line: str, data_source: str = "zeek") -> ParseResult:
        line = line.strip()
        if not line or line.startswith("#"):
            if line.startswith("#fields"):
                parts = line.split("\t")
                self.tsv_fields = parts[1:]
            return ParseResult(success=False, error="Comment or empty line")

        # Try JSON first
        if line.startswith("{"):
            try:
                data = json.loads(line)
                return self.parse_dict(data, data_source=data_source)
            except json.JSONDecodeError as jde:
                msg = f"Invalid JSON string: {jde.msg} at pos {jde.pos}"
                return ParseResult(success=False, error=msg)

        # Fallback to Zeek TSV if #fields header was encountered
        if self.tsv_fields:
            parts = line.split("\t")
            if len(parts) == len(self.tsv_fields):
                data = dict(zip(self.tsv_fields, parts))
                return self.parse_dict(data, data_source=data_source)

        return ParseResult(success=False, error="Unsupported line format (not valid JSON or TSV)")
