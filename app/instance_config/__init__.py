"""Instance configuration package.

Contains the DB-side models that represent how THIS specific instance
is configured. These are persisted and mutable; the catalog is not.
"""
from app.instance_config.models import (
    EndpointConfig,
    InstanceConfig,
)

__all__ = ["EndpointConfig", "InstanceConfig"]
