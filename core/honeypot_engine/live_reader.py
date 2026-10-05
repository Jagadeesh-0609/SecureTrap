"""Generic live (follow) JSON Lines reader for SecureTrap.

Polls a JSONL file for newly appended lines and yields one dictionary
per new, valid JSON object. This reader understands JSON Lines
structure only — it has no knowledge of any honeypot's event format,
performs no conversion to AttackEvent, and does no validation.

This is a separate component from the batch reader
(core/honeypot_engine/log_reader.py):

    JsonLogReader      -> reads an existing file from start to end, once
    LiveJsonLogReader  -> follows a file, yielding only new lines as
                          they are appended

For this first version, following is implemented with simple polling,
using the standard library only (no watchdog, asyncio, or threads).
"""

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Optional, Tuple, Union

DEFAULT_POLL_INTERVAL = 1.0


@dataclass
class MalformedLine:
    """A line that was read but could not be parsed as a JSON object.

    Attributes:
        raw_line: The original, unparsed line content.
        error: A human-readable description of why it was rejected.
    """

    raw_line: str
    error: str


class LiveJsonLogReader:
    """Follows a JSONL file, yielding only newly appended JSON objects.

    Reading starts at the file's current end — content already present
    when the reader is created is not replayed; only lines appended
    afterward are yielded. This mirrors standard "tail -f" behavior
    and keeps this reader's responsibility distinct from the batch
    reader.

    Malformed lines and non-object JSON values (arrays, strings,
    numbers, etc.) are skipped rather than yielded. Malformed lines
    are additionally recorded in `malformed_lines` for debugging.

    File replacement (e.g. log rotation) and in-place truncation are
    both handled: replacement is detected via a change in filesystem
    identity (device + inode), which is caught regardless of whether
    the replacement file is smaller, larger, or the same size as the
    previous read position; in-place truncation of the same file is
    detected via the existing size comparison. Either way, reading
    resets to the start of the (new) file instead of crashing or
    getting stuck.
    """

    def __init__(
        self,
        path: Union[str, Path],
        poll_interval: float = DEFAULT_POLL_INTERVAL,
    ) -> None:
        """Create a live reader that follows the file at the given path.

        Args:
            path: Path to the JSONL file to follow. Must already exist.
            poll_interval: Seconds to sleep between polls when no new
                data was found. Configurable; defaults to 1.0.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        self.path = Path(path)
        if not self.path.exists():
            raise FileNotFoundError(f"Log file not found: {self.path}")

        self.poll_interval = poll_interval
        self.malformed_lines: list[MalformedLine] = []

        stat_result = self.path.stat()
        self._position = stat_result.st_size
        self._buffer = ""
        # (device, inode) identifies the underlying file itself, not
        # just its path — a replacement file at the same path gets a
        # different identity, which is what lets rotation/replacement
        # be detected independently of file size.
        self._file_identity: Optional[Tuple[int, int]] = (stat_result.st_dev, stat_result.st_ino)

    def follow(self, max_polls: Optional[int] = None) -> Iterator[dict[str, Any]]:
        """Yield newly appended JSON objects as they appear in the file.

        Polls indefinitely by default, which is the intended production
        behavior. Pass `max_polls` to make it stop deterministically
        after that many poll cycles — intended for tests.

        Args:
            max_polls: If given, stop after this many poll cycles
                (whether or not new data was found in each one). If
                None, follow forever.

        Yields:
            One dict per newly appended, valid JSON object. Blank
            lines, malformed JSON, and syntactically valid JSON that
            is not an object (e.g. a list or a bare number) are all
            skipped, not yielded.
        """
        polls_done = 0
        while True:
            self._reset_on_truncation()

            for raw_line in self._read_new_lines():
                event = self._parse_line(raw_line)
                if event is not None:
                    yield event

            polls_done += 1
            if max_polls is not None and polls_done >= max_polls:
                return

            time.sleep(self.poll_interval)

    def _reset_on_truncation(self) -> None:
        """Detect file replacement/rotation or in-place truncation.

        Replacement (including log rotation) is detected by a change
        in filesystem identity (device + inode) rather than by size
        alone, so it is caught even when the replacement file is
        larger than, or the same size as, the previous read position —
        a case a size-only comparison would miss entirely. When the
        identity changes, reading resets to the start of the new file
        and any partial line buffered from the old file is discarded.

        In-place truncation — the file keeps the same identity but
        shrinks (e.g. via `> file`) — is still detected via the
        existing size comparison.

        A temporarily missing file is left untouched: neither the
        stored identity, position, nor buffer are changed, so reading
        simply resumes once the file reappears.
        """
        try:
            stat_result = self.path.stat()
        except FileNotFoundError:
            return

        current_identity = (stat_result.st_dev, stat_result.st_ino)

        if current_identity != self._file_identity:
            self._file_identity = current_identity
            self._position = 0
            self._buffer = ""
            return

        if stat_result.st_size < self._position:
            self._position = 0
            self._buffer = ""

    def _read_new_lines(self) -> list[str]:
        """Read whatever new, complete lines are available since the last poll."""
        try:
            with self.path.open("r", encoding="utf-8") as log_file:
                log_file.seek(self._position)
                chunk = log_file.read()
                self._position = log_file.tell()
        except FileNotFoundError:
            return []

        if not chunk:
            return []

        self._buffer += chunk
        lines = self._buffer.split("\n")
        self._buffer = lines[-1]
        return lines[:-1]

    def _parse_line(self, raw_line: str) -> Optional[dict[str, Any]]:
        """Parse one line, returning a dict, or None if it should be skipped."""
        stripped = raw_line.strip()
        if not stripped:
            return None

        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as exc:
            self.malformed_lines.append(MalformedLine(raw_line=stripped, error=str(exc)))
            return None

        if not isinstance(parsed, dict):
            return None

        return parsed