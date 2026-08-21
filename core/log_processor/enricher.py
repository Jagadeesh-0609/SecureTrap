"""Stage 3 Event Enricher for SecureTrap.

Takes an already-processed ProcessedEvent and derives simple,
deterministic, directly observable features from its normalized
command. This layer makes no claim about attacker intent — it only
reports what is literally present in the command text (a URL-like
substring, an IPv4-looking substring, a path-like token, a shell
control character), nothing more.

This module operates only on ProcessedEvent. It does not read logs,
does not know about any honeypot's raw fields, and performs no
machine learning, database, or network access.
"""

import re
from dataclasses import dataclass

from core.log_processor.processor import ProcessedEvent

_URL_PATTERN = re.compile(r"(?:https?|ftp)://\S+", re.IGNORECASE)

_IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

_FILE_PATH_PATTERN = re.compile(r"(?:^|\s)(?:\.{1,2}/|/)\S*")

_SHELL_METACHARACTERS = frozenset(";|&$`><")


@dataclass
class EnrichedEvent:
    """A ProcessedEvent plus simple, directly observable command features.

    Attributes:
        processed_event: The original ProcessedEvent this was derived
            from, preserved unchanged.
        has_command: True when the normalized command is non-empty.
        command_length: Length of the normalized command (0 when
            there is no command).
        has_url: True if the command contains an http(s):// or
            ftp:// -style substring.
        has_ip_address: True if the command contains a substring that
            looks like an IPv4 address.
        has_file_path: True if the command contains an obvious
            Unix-style path token beginning with "/", "./", or "../".
        has_shell_metacharacters: True if the command contains a
            common shell control character (; | & $ ` > <). This is a
            simple observable feature, not a maliciousness classifier.
    """

    processed_event: ProcessedEvent
    has_command: bool
    command_length: int
    has_url: bool
    has_ip_address: bool
    has_file_path: bool
    has_shell_metacharacters: bool


class EventEnricher:
    """Derives observable command features from a ProcessedEvent.

    Every feature here is a direct, deterministic observation about
    the command text — never an inference about what the attacker
    meant to do. The command itself is never modified; features are
    only ever read from ProcessedEvent.normalized_command as-is.
    """

    def enrich(self, processed_event: ProcessedEvent) -> EnrichedEvent:
        """Derive observable features from a ProcessedEvent's command.

        Args:
            processed_event: A ProcessedEvent produced by LogProcessor.

        Returns:
            An EnrichedEvent preserving the original ProcessedEvent
            alongside its derived command features.
        """
        command = processed_event.normalized_command

        return EnrichedEvent(
            processed_event=processed_event,
            has_command=bool(command),
            command_length=len(command),
            has_url=bool(_URL_PATTERN.search(command)),
            has_ip_address=bool(_IPV4_PATTERN.search(command)),
            has_file_path=bool(_FILE_PATH_PATTERN.search(command)),
            has_shell_metacharacters=any(char in _SHELL_METACHARACTERS for char in command),
        )