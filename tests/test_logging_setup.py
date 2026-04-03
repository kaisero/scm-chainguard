"""Tests for logging configuration."""

import logging

import pytest
from scm_chainguard.logging_setup import AUDIT_LOGGER, configure_logging, get_audit_logger


@pytest.fixture(autouse=True)
def _clean_logging():
    """Isolate logging state between tests."""
    logger = logging.getLogger("scm_chainguard")
    logger.handlers.clear()
    yield
    logger.handlers.clear()


class TestConfigureLogging:
    def test_creates_console_handler(self):
        configure_logging()
        logger = logging.getLogger("scm_chainguard")
        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0], logging.StreamHandler)

    def test_console_level_info_by_default(self):
        configure_logging()
        handler = logging.getLogger("scm_chainguard").handlers[0]
        assert handler.level == logging.INFO

    def test_debug_sets_console_to_debug(self):
        configure_logging(debug=True)
        handler = logging.getLogger("scm_chainguard").handlers[0]
        assert handler.level == logging.DEBUG

    def test_root_logger_level_always_debug(self):
        configure_logging(debug=False)
        assert logging.getLogger("scm_chainguard").level == logging.DEBUG

    def test_log_file_adds_file_handler(self, tmp_path):
        log_file = tmp_path / "test.log"
        configure_logging(log_file=log_file)
        logger = logging.getLogger("scm_chainguard")
        assert len(logger.handlers) == 2
        file_handlers = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
        assert len(file_handlers) == 1

    def test_file_handler_level_is_debug(self, tmp_path):
        log_file = tmp_path / "test.log"
        configure_logging(log_file=log_file)
        file_handler = [h for h in logging.getLogger("scm_chainguard").handlers if isinstance(h, logging.FileHandler)][0]
        assert file_handler.level == logging.DEBUG

    def test_clears_previous_handlers(self):
        configure_logging()
        configure_logging()
        logger = logging.getLogger("scm_chainguard")
        assert len(logger.handlers) == 1


class TestGetAuditLogger:
    def test_returns_correct_name(self):
        assert get_audit_logger().name == AUDIT_LOGGER

    def test_returns_same_instance(self):
        assert get_audit_logger() is get_audit_logger()

    def test_is_child_of_scm_chainguard(self):
        logger = get_audit_logger()
        assert logger.name.startswith("scm_chainguard.")
