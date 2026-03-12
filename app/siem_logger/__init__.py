"""
SIEM-compatible security event logger for NoctisAPI.

Usage:
    from app import siem_logger
    siem_logger.configure()   # call once at startup
    siem_logger.emit_event(kind=..., source_ip=..., method=..., endpoint=...,
                           status_code=..., user_agent=..., interaction_id=...,
                           actor_id=..., session_id=...)
"""
from .dispatcher import configure, emit_event, shutdown

__all__ = ["configure", "emit_event", "shutdown"]
