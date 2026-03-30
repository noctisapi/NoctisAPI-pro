"""
source_integrity.py — Startup integrity check for Pro licensing modules.

Reads expected SHA-256 hashes from app.build_manifest (generated at Docker image
build time by scripts/generate_build_manifest.py).  If a critical file has been
modified — e.g. via a volume-mount shadow — the check fails, a CRITICAL log line
is emitted, and the caller must NOT enable Pro features.

Design notes
------------
- If the build manifest is missing or empty, the check is skipped with an INFO log.
  This is intentional: images built without the manifest step degrade gracefully
  rather than breaking entirely.  The Dockerfile should always run the manifest
  generator as a RUN step so that production images have the check active.
- The check detects the simplest bypass (mount a replacement module in a single
  directory).  A determined attacker with full host access can always patch more
  files; the value here is raising the cost and producing audit log evidence.
- This module checks itself too, so an attacker must patch TWO different locations
  (honey_licensing/ AND app/) to silence both the feature gate and the integrity
  check simultaneously.
"""
from __future__ import annotations

import hashlib
import logging
import os
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

# Root of the repository, resolved from this file's own location at import time.
# Stored as a module-level constant so it cannot be trivially overridden at runtime.
_APP_ROOT: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Files whose integrity is checked, relative to _APP_ROOT.
# Covers the complete Pro feature-gate call chain identified in the security review:
#   has_feature → feature_flags → pro_license → pro_ops → offline_license
# plus this module itself (forces attacker to patch two separate directories).
_CRITICAL_FILES: Tuple[str, ...] = (
    "honey_licensing/feature_flags.py",
    "honey_licensing/offline_license.py",
    "app/pro_license.py",
    "app/pro_ops.py",
    "app/source_integrity.py",
)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_manifest() -> Dict[str, str]:
    """Load expected hashes from app.build_manifest.

    Returns an empty dict when the manifest is absent or contains no entries,
    which causes check() to skip verification rather than fail.
    """
    try:
        from app import build_manifest  # type: ignore[import]
        raw = getattr(build_manifest, "EXPECTED_HASHES", {})
        if not isinstance(raw, dict):
            return {}
        return {str(k): str(v) for k, v in raw.items() if k and v}
    except ImportError:
        return {}
    except Exception as exc:
        logger.warning("source_integrity: failed to load build_manifest: %s", exc)
        return {}


def check() -> Tuple[bool, List[str]]:
    """Verify integrity of critical Pro licensing source files.

    Returns
    -------
    ok : bool
        True when all checks passed or no manifest is available.
        False when one or more files deviate from their expected hash.
    violations : list[str]
        Relative paths of files that failed the check.  Empty when ok=True.

    Side-effects
    ------------
    Logs at DEBUG for each passing file, CRITICAL for each violation.
    """
    manifest = _load_manifest()
    if not manifest:
        logger.info(
            "source_integrity: build manifest not available — skipping integrity check. "
            "Add 'RUN python scripts/generate_build_manifest.py' to the Dockerfile to enable."
        )
        return True, []

    violations: List[str] = []

    for rel_path in _CRITICAL_FILES:
        expected = manifest.get(rel_path)
        if not expected:
            # File not in manifest — new file added after manifest was generated.
            # Log a notice but do not fail; the manifest should be regenerated.
            logger.info(
                "source_integrity: %s not in manifest (regenerate with generate_build_manifest.py)",
                rel_path,
            )
            continue

        abs_path = os.path.join(_APP_ROOT, rel_path)
        try:
            actual = _sha256_file(abs_path)
        except OSError as exc:
            logger.critical(
                "source_integrity: INTEGRITY VIOLATION — cannot read %s: %s",
                rel_path,
                exc,
            )
            violations.append(rel_path)
            continue

        if actual != expected:
            logger.critical(
                "source_integrity: INTEGRITY VIOLATION — %s hash mismatch "
                "(expected=%.16s...  actual=%.16s...)",
                rel_path,
                expected,
                actual,
            )
            violations.append(rel_path)
        else:
            logger.debug("source_integrity: ok %s", rel_path)

    if violations:
        logger.critical(
            "source_integrity: %d file(s) failed integrity check: %s — "
            "Pro features will not be enabled. "
            "If this is a legitimate deployment, rebuild the Docker image to regenerate the manifest.",
            len(violations),
            ", ".join(violations),
        )
        return False, violations

    logger.info("source_integrity: all %d critical files verified ok", len(_CRITICAL_FILES))
    return True, []
