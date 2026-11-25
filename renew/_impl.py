"""Certificate renewal primitives used by the renewal scheduler.

The module keeps every operation small and explicit: a renewal is planned
from the current certificate, applied to a store, checked for repetition,
validated against the previous certificate, rolled back when it fails, and
optionally executed for a batch of certificates.

Design rules enforced here:

* A renewal is only due inside the policy window before ``not_after``.
* The old certificate stays valid for ``overlap_days`` after the successor
  becomes valid, so both certificates verify during the overlap.
* Requests are deterministic: repeating a request for the same certificate
  produces the same successor (same id, serial and key choice).
* Applying a renewal is atomic: validation happens before anything is
  written, so a failed renewal never touches the existing certificate.
* Every certificate in a batch is handled with its own policy; one failure
  does not leak into the other certificates.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta
from typing import Any

DEFAULT_RENEW_BEFORE_DAYS = 30
DEFAULT_VALID_DAYS = 90


def _policy_days(policy: dict[str, Any] | None, key: str, default: int) -> int:
    """Read a non-negative day count from a policy with a safe default."""
    value = (policy or {}).get(key, default)
    try:
        return max(int(value), 0)
    except (TypeError, ValueError):
        return default


def needs_renew(cert: dict[str, Any], now: datetime, policy: dict[str, Any]) -> bool:
    """Return whether the certificate should be renewed at the given time.

    Renewal is due once ``now`` enters the policy window that starts
    ``renew_before_days`` before the certificate expires.  A certificate that
    has already expired is not considered due (it is inside no future window).
    """
    renew_before = _policy_days(policy, "renew_before_days", DEFAULT_RENEW_BEFORE_DAYS)
    expires = cert["not_after"]
    return expires - timedelta(days=renew_before) <= now < expires


def overlap_ok(old: dict[str, Any], new: dict[str, Any], policy: dict[str, Any]) -> bool:
    """Return whether the old and new certificate overlap acceptably.

    The old certificate must remain valid for the whole policy overlap,
    counted from the moment the successor becomes valid.
    """
    overlap_days = _policy_days(policy, "overlap_days", 0)
    old_end = old.get("deactivate_at") or old["not_after"]
    required_end = new["not_before"] + timedelta(days=overlap_days)
    return old_end >= required_end


def request_renewal(cert: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    """Build the renewal request describing the successor certificate.

    The request is a pure function of the source certificate and the policy:
    the same certificate always yields the same successor, which makes
    repeated renewal requests idempotent.
    """
    serial = int(cert.get("serial", 0)) + 1
    key_policy = (policy or {}).get("key_policy", "reuse")
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
        "overlap_days": _policy_days(policy, "overlap_days", 0),
    }


def _validate_renewal(
    old: dict[str, Any], new_cert: dict[str, Any], now: datetime
) -> None:
    """Raise ``ValueError`` if the successor is not a valid renewal.

    Runs before the store is touched so a rejected renewal cannot alter the
    existing certificate.
    """
    if new_cert["not_before"] > new_cert["not_after"]:
        raise ValueError("invalid validity period")
    if new_cert["not_after"] <= now:
        raise ValueError("new certificate is already expired")
    if new_cert["cert_id"] == old["cert_id"]:
        raise ValueError("new certificate reuses the old certificate id")

    if str(new_cert.get("subject", "")) != str(old.get("subject", "")):
        raise ValueError("subject mismatch")

    key_policy = new_cert.get("key_policy", "reuse")
    if key_policy == "rotate":
        if new_cert.get("key_id") == old.get("key_id"):
            raise ValueError("key rotation required but key was reused")
    elif new_cert.get("key_id") != old.get("key_id"):
        raise ValueError("key reuse required but key was rotated")


def apply_renewal(
    store: dict[str, Any],
    cert: dict[str, Any],
    new_cert: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """Write the new certificate and schedule the old one for retirement.

    The renewal is transactional: it is validated first, then committed as a
    unit.  If committing fails the store is restored, so the existing
    certificate is never left in a half-renewed state.  Re-applying an
    already-applied renewal returns the existing successor instead of
    issuing another one.
    """
    certs = store.get("certs") or {}
    renewals = store.get("renewals") or {}
    journal = store.get("journal") or {}
    cert_id = cert["cert_id"]
    old = certs.get(cert_id, cert)

    # Idempotent replay: the certificate already has a successor.  Return the
    # same result without writing anything else.
    existing_id = renewals.get(cert_id)
    if existing_id and existing_id in certs:
        return {
            "ok": True,
            "cert_id": cert_id,
            "new_cert_id": existing_id,
            "deactivate_at": old.get("deactivate_at"),
            "idempotent": True,
        }

    # Validate everything before mutating any state, including the store's
    # own containers.
    _validate_renewal(old, new_cert, now)
    new_id = new_cert["cert_id"]

    certs = store.setdefault("certs", {})
    renewals = store.setdefault("renewals", {})
    journal = store.setdefault("journal", {})
    if existing_id:
        # A dangling pointer from an unfinished renewal: drop it and proceed.
        renewals.pop(cert_id, None)
    old = certs.get(cert_id, cert)

    overlap_days = _policy_days({"overlap_days": new_cert.get("overlap_days", 0)}, "overlap_days", 0)
    proposed = new_cert["not_before"] + timedelta(days=overlap_days)
    current = old.get("deactivate_at")
    deactivate_at = proposed if current is None or proposed > current else current

    snapshot = copy.deepcopy(old)
    journal[cert_id] = {"old": snapshot, "new_id": new_id}
    try:
        certs[new_id] = new_cert
        old["deactivate_at"] = deactivate_at
        renewals[cert_id] = new_id
    except Exception:
        certs.pop(new_id, None)
        renewals.pop(cert_id, None)
        old.clear()
        old.update(copy.deepcopy(snapshot))
        journal.pop(cert_id, None)
        raise
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
    try:
        return int(renewed.get("serial", -1)) > int(cert.get("serial", 0))
    except (TypeError, ValueError):
        return True


def validate_chain(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """Return the problems found between the old and new certificate.

    Pure inspection: the certificates are never modified.
    """
    issues: list[str] = []

    if str(old.get("subject", "")) != str(new.get("subject", "")):
        issues.append("subject mismatch")

    key_policy = new.get("key_policy", "reuse")
    if key_policy == "rotate":
        if new.get("key_id") == old.get("key_id"):
            issues.append("key not rotated")
    elif new.get("key_id") != old.get("key_id"):
        issues.append("key mismatch")

    old_end = old.get("deactivate_at") or old.get("not_after")
    new_before = new.get("not_before")
    if old_end is None or new_before is None:
        issues.append("missing validity period")
        return issues
    overlap_days = _policy_days({"overlap_days": new.get("overlap_days", 0)}, "overlap_days", 0)
    if new_before > old_end:
        issues.append("overlap missing")
    elif old_end < new_before + timedelta(days=overlap_days):
        issues.append("overlap too short")

    return issues


def rollback(store: dict[str, Any], cert: dict[str, Any]) -> dict[str, Any]:
    """Undo an unfinished renewal for the certificate.

    Restores the journaled pre-renewal state of the old certificate, removes
    the not-yet-committed successor and clears the renewal pointer.  When
    there is nothing journaled (because the renewal was rejected before it
    touched the store) the call is a harmless no-op.
    """
    cert_id = cert["cert_id"]
    journal = store.get("journal", {})
    entry = journal.pop(cert_id, None)
    if not entry:
        return {"ok": True, "restored": False}

    certs = store.setdefault("certs", {})
    renewals = store.setdefault("renewals", {})
    new_id = entry.get("new_id")
    snapshot = entry.get("old")

    if new_id is not None:
        certs.pop(new_id, None)
        if renewals.get(cert_id) == new_id:
            renewals.pop(cert_id, None)

    if snapshot is not None:
        current = certs.get(cert_id)
        if current is None:
            certs[cert_id] = copy.deepcopy(snapshot)
        else:
            current.clear()
            current.update(copy.deepcopy(snapshot))

    return {"ok": True, "restored": True}


def renew_batch(
    certs: list[tuple[dict[str, Any], dict[str, Any]]],
    policy: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """Renew every certificate that is inside its renewal window.

    Each certificate is evaluated with its own policy (falling back to the
    batch policy) and committed independently: a failure for one certificate
    leaves the others untouched, and re-running the batch does not issue a
    second successor for an already-renewed certificate.
    """
    results: list[dict[str, Any]] = []
    renewed = 0
    skipped = 0
    failed = 0

    for store, cert in certs:
        cert_policy = cert.get("policy") or policy
        cert_id = cert.get("cert_id")

        if not needs_renew(cert, now, cert_policy):
            skipped += 1
            results.append({"cert_id": cert_id, "status": "skipped"})
            continue

        existing_id = store.get("renewals", {}).get(cert_id)
        if existing_id and existing_id in store.get("certs", {}):
            renewed += 1
            results.append(
                {
                    "cert_id": cert_id,
                    "status": "renewed",
                    "new_cert_id": existing_id,
                    "idempotent": True,
                }
            )
            continue

        try:
            request = request_renewal(cert, cert_policy)
            new_cert = dict(request)
            new_cert["not_before"] = now
            new_cert["not_after"] = now + timedelta(
                days=_policy_days(cert_policy, "valid_days", DEFAULT_VALID_DAYS)
            )
            new_cert["overlap_days"] = _policy_days(cert_policy, "overlap_days", 0)
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
            # One certificate's failure must not abort or mutate the others.
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
