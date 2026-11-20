"""Logging configuration for the Android Security Scanner."""

from __future__ import annotations

import logging
from pathlib import Path

LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S%z"


def configure_logging(
    log_file: Path | None = None,
    level: int = logging.INFO,
) -> logging.Logger:
    """Configure application logging with file handler and concise console output.

    Args:
        log_file: Optional path to the log file. Defaults to ``logs/device-scan.log``.
        level: File logging level. Defaults to ``logging.INFO``.

    Returns:
        The configured root ``device_scan`` logger.
    """
    target_path = log_file if log_file is not None else Path("logs") / "device-scan.log"
    target_path.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("device_scan")
    logger.setLevel(level)
    logger.propagate = False

    # Clear existing handlers to avoid duplicate log lines across repeated invocations.
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)

    formatter = logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT)

    file_handler = logging.FileHandler(target_path, encoding="utf-8")
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger
