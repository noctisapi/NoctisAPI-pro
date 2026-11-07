"""Shared test isolation hooks."""

import logging

import pytest


@pytest.fixture(autouse=True)
def reset_global_logging_state():
    """Prevent one test's logging configuration from leaking into the next.

    Some tests exercise application-level logging configuration directly.  The
    stdlib logging manager is process-global, so restore the neutral state at
    both boundaries to keep ``assertLogs`` deterministic under the full suite.
    """

    logging.disable(logging.NOTSET)
    for logger in logging.Logger.manager.loggerDict.values():
        if isinstance(logger, logging.Logger):
            logger.disabled = False
    yield
    logging.disable(logging.NOTSET)
    for logger in logging.Logger.manager.loggerDict.values():
        if isinstance(logger, logging.Logger):
            logger.disabled = False
