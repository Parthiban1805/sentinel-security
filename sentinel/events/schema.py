"""Validation and construction of events/assets against docs/schemas/*.json.

docs/schemas is the single source of truth. An installed wheel carries a copy in
sentinel/_schemas (pyproject force-include, ADR-0013); a source checkout reads docs/ directly.
"""

import json
import uuid
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


def locate_schemas(bundled: Path, repo: Path) -> Path:
    """The copy inside an installed wheel wins; a source checkout falls back to docs/schemas."""
    return bundled if bundled.is_dir() else repo


SCHEMA_DIR = locate_schemas(
    Path(__file__).resolve().parents[1] / "_schemas",  # inside an installed wheel
    Path(__file__).resolve().parents[2] / "docs" / "schemas",  # source checkout
)


class SchemaError(ValueError):
    """Raised when an event or asset does not conform to its schema."""


@cache
def _validator(name: str) -> Draft202012Validator:
    schema = json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)  # the $id is a valid URI reference (ADR-0006)
    return Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)


def _validate(name: str, record: dict[str, Any]) -> None:
    errors = sorted(_validator(name).iter_errors(record), key=lambda e: list(e.absolute_path))
    if errors:
        # Messages name fields and constraints; they could echo a bad value, so report paths only.
        details = "; ".join(
            f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.validator}" for e in errors
        )
        raise SchemaError(details)


def validate_event(event: dict[str, Any]) -> None:
    _validate("event.schema.json", event)


def validate_asset(asset: dict[str, Any]) -> None:
    _validate("asset.schema.json", asset)


def format_time(moment: datetime) -> str:
    if moment.tzinfo is None:
        raise ValueError("event time must be timezone-aware (UTC)")
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_event(
    *,
    event_type: str,
    source: str,
    asset_id: str,
    time: datetime,
    severity: str,
    confidence: str,
    evidence_ref: str,
    verified: bool = False,
    is_test: bool = False,
    credential_ref: str | None = None,
    identity_ref: str | None = None,
    attributes: dict[str, Any] | None = None,
    event_id: str | None = None,
) -> dict[str, Any]:
    """Build and validate an event. Pass a deterministic `event_id` from collectors so that
    re-collecting the same source record is deduplicated by the store."""
    event: dict[str, Any] = {
        "event_id": event_id or str(uuid.uuid4()),
        "event_type": event_type,
        "source": source,
        "asset_id": asset_id,
        "time": format_time(time),
        "severity": severity,
        "confidence": confidence,
        "verified": verified,
        "evidence_ref": evidence_ref,
        "is_test": is_test,
    }
    if credential_ref is not None:
        event["credential_ref"] = credential_ref
    if identity_ref is not None:
        event["identity_ref"] = identity_ref
    if attributes is not None:
        event["attributes"] = attributes
    validate_event(event)
    return event
