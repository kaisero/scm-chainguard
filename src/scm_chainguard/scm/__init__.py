"""SCM API clients for certificate and security management."""

from __future__ import annotations

import requests


def extract_error_message(resp: requests.Response) -> str:
    """Extract the most detailed error message from an SCM API error response.

    Extraction priority:
    1. ``details.errors[]`` array entries (joined with ``; ``)
    2. ``details.message`` scalar
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
                msgs = [d.get("msg", "") or d.get("message", "") for d in detail_errors]
                msg = "; ".join(m for m in msgs if m) or error.get("message", msg)
            elif isinstance(details, dict) and details.get("message"):
                msg = details["message"]
            else:
                msg = error.get("message", msg)
    except Exception:
        pass
    return msg
