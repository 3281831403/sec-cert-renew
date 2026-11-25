"""Public acceptance tests for the certificate renewal service."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from renew import (
    apply_renewal,
    check_idempotent,
    needs_renew,
    renew_batch,
    request_renewal,
    rollback,
)

NOW = datetime(2026, 11, 25, 9, 0, tzinfo=timezone.utc)

POLICY = {
    "renew_before_days": 30,
    "overlap_days": 7,
    "key_policy": "reuse",
    "valid_days": 90,
}


def make_cert(
    cert_id="cert-a",
    subject="CN=alpha.example,O=Example",
    key_id="key-a",
    serial=100,
    not_after=None,
    policy=None,
):
    cert = {
        "cert_id": cert_id,
        "subject": subject,
        "key_id": key_id,
        "serial": serial,
        "not_before": NOW - timedelta(days=300),
        "not_after": not_after if not_after is not None else NOW + timedelta(days=20),
        "deactivate_at": None,
        "revoked_at": None,
        "active": True,
    }
    if policy is not None:
        cert["policy"] = policy
    return cert


def make_store(*certs):
    return {
        "certs": {cert["cert_id"]: cert for cert in certs},
        "journal": {},
        "renewals": {},
    }


def issue(request, not_before, not_after):
    new_cert = dict(request)
    new_cert["not_before"] = not_before
    new_cert["not_after"] = not_after
    return new_cert


def is_valid(cert, when):
    if not cert.get("active", True):
        return False
    if cert.get("revoked_at") is not None:
        return False
    if when < cert["not_before"]:
        return False
    valid_until = cert.get("deactivate_at") or cert["not_after"]
    return when <= valid_until


def test_renewal_window_follows_policy():
    cert = make_cert(not_after=NOW + timedelta(days=40))
    policy = dict(POLICY, renew_before_days=45)
    assert needs_renew(cert, NOW, policy) is True


def test_overlap_keeps_old_and_new_valid():
    old = make_cert(not_after=NOW + timedelta(days=20))
    store = make_store(old)
    request = request_renewal(old, POLICY)
    new = issue(request, NOW, NOW + timedelta(days=100))

    apply_renewal(store, old, new, NOW)

    during_overlap = NOW + timedelta(days=3)
    assert is_valid(old, during_overlap) is True
    assert is_valid(new, during_overlap) is True


def test_repeated_renewal_is_idempotent():
    old = make_cert()
    store = make_store(old)
    first = request_renewal(old, POLICY)
    second = request_renewal(old, POLICY)
    assert first["cert_id"] == second["cert_id"]
    assert first["serial"] == second["serial"]

    for request in (first, second):
        new = issue(request, NOW, NOW + timedelta(days=100))
        apply_renewal(store, old, new, NOW)

    successors = [cert_id for cert_id in store["certs"] if cert_id != old["cert_id"]]
    assert len(successors) == 1
    assert check_idempotent(store, old) is True


def test_failed_renewal_keeps_existing_cert():
    old = make_cert()
    store = make_store(old)
    request = request_renewal(old, POLICY)
    expired = issue(request, NOW - timedelta(days=10), NOW - timedelta(days=1))

    with pytest.raises(ValueError):
        apply_renewal(store, old, expired, NOW)
    rollback(store, old)

    persisted = store["certs"][old["cert_id"]]
    assert persisted["deactivate_at"] is None
    assert expired["cert_id"] not in store["certs"]


def test_batch_renewal_keeps_certificates_independent():
    policy_a = dict(POLICY, overlap_days=21)
    policy_b = dict(POLICY, overlap_days=3)
    old_a = make_cert(
        cert_id="cert-a",
        policy=policy_a,
        not_after=NOW + timedelta(days=10),
    )
    old_b = make_cert(
        cert_id="cert-b",
        subject="CN=bravo.example,O=Example",
        key_id="key-b",
        serial=200,
        policy=policy_b,
        not_after=NOW + timedelta(days=10),
    )
    store_a = make_store(old_a)
    store_b = make_store(old_b)

    result = renew_batch([(store_a, old_a), (store_b, old_b)], POLICY, NOW)

    assert result["renewed"] == 2
    assert store_a["certs"]["cert-a"]["deactivate_at"] == NOW + timedelta(days=21)
    assert store_b["certs"]["cert-b"]["deactivate_at"] == NOW + timedelta(days=3)