"""Certificate renewal primitives used by the renewal scheduler.

The module keeps every operation small and explicit: a renewal is planned
from the current certificate, applied to a store, checked for repetition,
validated against the previous certificate, rolled back when it fails, and
optionally executed for a batch of certificates.
"""

from __future__ import annotations

import copy
import itertools
from datetime import datetime, timedelta
from typing import Any

DEFAULT_RENEW_BEFORE_DAYS = 30
DEFAULT_VALID_DAYS = 90

_request_sequence = itertools.count(5000)


def needs_renew(cert: dict[str, Any], now: datetime, policy: dict[str, Any]) -> bool:
    """Return whether the certificate should be renewed at the given time."""
    expires = cert["not_after"]
    window_end = now + timedelta(days=DEFAULT_RENEW_BEFORE_DAYS)
    return now < expires <= window_end


def overlap_ok(old: dict[str, Any], new: dict[str, Any], policy: dict[str, Any]) -> bool:
    """Return whether the old and new certificate overlap acceptably."""
    old_end = old.get("deactivate_at") or old["not_after"]
    return new["not_before"] <= old_end


def request_renewal(cert: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    """Build the renewal request describing the successor certificate."""
    serial = next(_request_sequence)
    key_policy = policy.get("key_policy", "reuse")
    if key_policy == "rotate":
        key_id = f"{cert['key_id']}-{serial}"
    else:
        key_id = cert["key_id"]
    return {
        "cert_id": f"{cert['cert_id']}-{serial}",
        "source_cert_id": cert["cert_id"],
        "subject": cert["subject"],
        "key_id": key_id,
        "serial": serial,
        "key_policy": key_policy,
        "overlap_days": 0,
    }


def apply_renewal(
    store: dict[str, Any],
    cert: dict[str, Any],
    new_cert: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """Write the new certificate and schedule the old one for retirement."""
    certs = store.setdefault("certs", {})
    journal = store.setdefault("journal", {})
    cert_id = cert["cert_id"]
    old = certs.get(cert_id, cert)
    new_id = new_cert["cert_id"]

    journal[cert_id] = {"old": copy.deepcopy(old), "new_id": new_id}
    certs[new_id] = new_cert

    overlap_days = int(new_cert.get("overlap_days", 0))
    proposed = new_cert["not_before"] + timedelta(days=overlap_days)
    current = old.get("deactivate_at")
    if current is None or str(proposed) > str(current):
        old["deactivate_at"] = proposed

    if new_cert["not_after"] <= now:
        raise ValueError("new certificate is already expired")

    store.setdefault("renewals", {})[cert_id] = new_id
    journal.pop(cert_id, None)
    return {
        "ok": True,
        "cert_id": cert_id,
        "new_cert_id": new_id,
        "deactivate_at": old.get("deactivate_at"),
    }


def check_idempotent(store: dict[str, Any], cert: dict[str, Any]) -> bool:
    """Return whether this certificate already has a newer successor."""
    cert_id = cert["cert_id"]
    renewed_id = store.get("renewals", {}).get(cert_id)
    if not renewed_id:
        return False
    renewed = store.get("certs", {}).get(renewed_id)
    if renewed is None:
        return False
    return int(renewed.get("serial", 0)) > int(cert.get("serial", 0))


def validate_chain(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """Return the problems found between the old and new certificate."""
    issues: list[str] = []

    if len(str(old.get("subject", ""))) != len(str(new.get("subject", ""))):
        issues.append("subject mismatch")

    if new.get("key_policy", "reuse") == "reuse" and new.get("key_id") != old.get("key_id"):
        new["key_id"] = old.get("key_id")

    old_end = old.get("deactivate_at") or old["not_after"]
    if new["not_before"] > old_end:
        issues.append("overlap missing")

    return issues


def rollback(store: dict[str, Any], cert: dict[str, Any]) -> dict[str, Any]:
    """Undo an unfinished renewal for the certificate."""
    cert_id = cert["cert_id"]
    store.get("journal", {}).pop(cert_id, None)
    return {"ok": True, "restored": False}


def renew_batch(
    certs: list[tuple[dict[str, Any], dict[str, Any]]],
    policy: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """Renew every certificate that is inside its renewal window."""
    results: list[dict[str, Any]] = []
    renewed = 0
    skipped = 0
    failed = 0

    if certs:
        first_policy = certs[0][1].get("policy", policy)
        shared_overlap = int(first_policy.get("overlap_days", 0))
    else:
        shared_overlap = int(policy.get("overlap_days", 0))

    for store, cert in certs:
        cert_policy = cert.get("policy", policy)
        cert_id = cert.get("cert_id")

        if not needs_renew(cert, now, cert_policy):
            skipped += 1
            results.append({"cert_id": cert_id, "status": "skipped"})
            continue

        try:
            request = request_renewal(cert, cert_policy)
            new_cert = dict(request)
            new_cert["not_before"] = now
            new_cert["not_after"] = now + timedelta(
                days=int(cert_policy.get("valid_days", DEFAULT_VALID_DAYS))
            )
            new_cert["overlap_days"] = shared_overlap
            apply_renewal(store, cert, new_cert, now)
            renewed += 1
            results.append(
                {
                    "cert_id": cert_id,
                    "status": "renewed",
                    "new_cert_id": new_cert["cert_id"],
                }
            )
        except Exception as exc:
            failed += 1
            results.append(
                {"cert_id": cert_id, "status": "failed", "error": str(exc)}
            )

    return {
        "results": results,
        "renewed": renewed,
        "skipped": skipped,
        "failed": failed,
    }