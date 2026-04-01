"""Logging configuration with console output, optional file output, and audit trail."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

LOG_FORMAT = "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"
AUDIT_LOGGER = "scm_chainguard.audit"


def configure_logging(debug: bool = False, log_file: Path | None = None) -> None:
    """Set up logging for the application.

    Console: INFO (or DEBUG with --debug).
    File (if provided): always DEBUG level.
    """
    root = logging.getLogger("scm_chainguard")
    root.setLevel(logging.DEBUG)
    root.handlers.clear()

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if debug else logging.INFO)
    console.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATEFMT))
    root.addHandler(console)

    if log_file is not None:
        file_handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATEFMT))
        root.addHandler(file_handler)


def get_audit_logger() -> logging.Logger:
    """Return the audit logger for recording administrative actions."""
    return logging.getLogger(AUDIT_LOGGER)
