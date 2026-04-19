"""SCM API clients for certificate and security management."""

from __future__ import annotations

import requests


def _format_extras(extras: dict[str, object]) -> str:
    """Format extra error fields as key=value pairs."""
    return ", ".join(f"{k}={v}" for k, v in sorted(extras.items()))


def extract_error_message(resp: requests.Response) -> str:
    """Extract the most detailed error message from an SCM API error response.

    Extraction priority:
    1. ``details.errors[]`` array entries (joined with ``; ``), including extra fields
    2. ``details.message`` scalar, enriched with other detail fields (e.g. ``errorType``)
    3. Top-level ``error.message``
    4. Raw ``resp.text``
    """
    msg = resp.text
    try:
        body = resp.json()
        errors = body.get("_errors", [])
        if errors:
            error = errors[0]
            details = error.get("details", {})
            detail_errors = details.get("errors", []) if isinstance(details, dict) else []

            if detail_errors:
                parts = []
                for d in detail_errors:
                    entry_msg = d.get("msg", "") or d.get("message", "")
                    extras = {k: v for k, v in d.items() if k not in ("msg", "message") and v is not None}
                    if entry_msg and extras:
                        parts.append(f"{entry_msg} ({_format_extras(extras)})")
                    elif entry_msg:
                        parts.append(entry_msg)
                    elif extras:
                        parts.append(_format_extras(extras))
                msg = "; ".join(parts) if parts else error.get("message", msg)
            elif isinstance(details, dict) and details.get("message"):
                detail_msg = details["message"]
                extras = {k: v for k, v in details.items() if k not in ("message", "errors") and v is not None}
                msg = f"{detail_msg} ({_format_extras(extras)})" if extras else detail_msg
            else:
                msg = error.get("message", msg)
    except Exception:
        pass
    return msg
