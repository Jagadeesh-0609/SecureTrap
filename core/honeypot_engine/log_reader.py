"""Generic JSON Lines (JSONL) log reader for SecureTrap.

Reads a JSONL file and yields one dictionary per valid JSON object.
This reader knows only about JSONL structure and has no knowledge of
any specific honeypot's event format.

Honeypot-specific conversion is handled by the appropriate adapter.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Union


@dataclass
class MalformedLine:
    """Information about a line that could not be parsed as a JSON object.

    Attributes:
        line_number: 1-based line number in the source file.
        raw_line: Original line content after stripping whitespace.
        error: Human-readable description of the parsing error.
    """

    line_number: int
    raw_line: str
    error: str


class JsonLogReader:
    """Read a JSONL file and yield one dictionary per valid JSON object."""

    def __init__(self, path: Union[str, Path]) -> None:
        """Create a JSONL reader.

        Args:
            path: Path to the JSONL file.
        """
        self.path = Path(path)
        self.malformed_lines: list[MalformedLine] = []

    def read_events(self) -> Iterator[dict[str, Any]]:
        """Read the file from beginning to end.

        Blank lines are ignored. Invalid JSON lines and valid JSON
        values that are not objects are recorded and skipped.

        Returns:
            Iterator of dictionaries representing valid JSON objects.

        Raises:
            FileNotFoundError: If the specified file does not exist.
        """
        if not self.path.exists():
            raise FileNotFoundError(f"Log file not found: {self.path}")

        self.malformed_lines = []

        with self.path.open("r", encoding="utf-8") as log_file:
            for line_number, raw_line in enumerate(log_file, start=1):
                stripped = raw_line.strip()

                if not stripped:
                    continue

                try:
                    parsed = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    self.malformed_lines.append(
                        MalformedLine(
                            line_number=line_number,
                            raw_line=stripped,
                            error=str(exc),
                        )
                    )
                    continue

                if not isinstance(parsed, dict):
                    self.malformed_lines.append(
                        MalformedLine(
                            line_number=line_number,
                            raw_line=stripped,
                            error="JSON value is not an object",
                        )
                    )
                    continue

                yield parsed