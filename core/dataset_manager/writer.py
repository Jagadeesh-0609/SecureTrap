"""Stage 4 Dataset Writer for SecureTrap.

Persists DatasetRecord objects to a CSV dataset using only the
standard library's csv module. This is dataset persistence only — no
labeling, no ML, no database.

This module consumes DatasetRecord only. It does not read logs, call
any reader/adapter/ingestion/log-processing component, or know about
any honeypot's raw fields.

Column order always matches DatasetRecord's field order exactly,
derived directly from the dataclass definition so the two can never
silently drift apart.
"""

import csv
from dataclasses import asdict, fields
from pathlib import Path
from typing import Iterable, List, Union

from core.dataset_manager.builder import DatasetRecord

_FIELDNAMES = [field.name for field in fields(DatasetRecord)]


class DatasetWriter:
    """Writes DatasetRecord objects to a CSV file.

    If the destination file does not exist, it is created (along with
    any missing parent directories) with a header row, even if there
    are no records to write yet. If the destination file already
    exists and there are records to append, its existing header is
    read and verified against DatasetRecord's schema before anything
    is appended — a missing or mismatched header raises ValueError
    rather than silently appending misaligned data.

    Passing an empty `records` to an existing file is a no-op: the
    file is left completely untouched (and its header is not checked,
    since nothing is being written).
    """

    def write(self, records: Iterable[DatasetRecord], path: Union[str, Path]) -> None:
        """Write or append DatasetRecord objects to a CSV file.

        Args:
            records: DatasetRecord objects to persist, in order.
            path: Destination CSV path. Parent directories are
                created if they do not exist.

        Raises:
            ValueError: If appending to an existing file whose header
                is missing (empty file) or does not match
                DatasetRecord's schema.
        """
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)

        record_list: List[DatasetRecord] = list(records)

        if not destination.exists():
            self._write_new_file(destination, record_list)
            return

        if record_list:
            self._verify_existing_header(destination)
            self._append_records(destination, record_list)

    @staticmethod
    def _write_new_file(destination: Path, records: List[DatasetRecord]) -> None:
        """Create a new CSV file with a header, then write any records."""
        with destination.open("w", encoding="utf-8", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=_FIELDNAMES)
            writer.writeheader()
            for record in records:
                writer.writerow(asdict(record))

    @staticmethod
    def _verify_existing_header(destination: Path) -> None:
        """Confirm an existing file's header matches DatasetRecord's schema.

        Raises:
            ValueError: If the file is empty (no header row at all),
                or its header row does not exactly match _FIELDNAMES.
        """
        with destination.open("r", encoding="utf-8", newline="") as csv_file:
            header = next(csv.reader(csv_file), None)

        if header is None:
            raise ValueError(
                f"Cannot append to {destination}: the file is empty and has no header."
            )

        if header != _FIELDNAMES:
            raise ValueError(
                f"Cannot append to {destination}: existing header {header!r} does "
                f"not match the expected DatasetRecord schema {_FIELDNAMES!r}."
            )

    @staticmethod
    def _append_records(destination: Path, records: List[DatasetRecord]) -> None:
        """Append records to an existing CSV file without writing a header."""
        with destination.open("a", encoding="utf-8", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=_FIELDNAMES)
            for record in records:
                writer.writerow(asdict(record))