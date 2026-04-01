# Built-in catalog definitions shipped with the system.
# These are the "factory defaults" — operators can add custom ones.
from app.catalog.builtin.loader import build_default_registry

__all__ = ["build_default_registry"]
