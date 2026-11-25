"""Invariant and policy tests beyond the public acceptance suite."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from renew import (
    apply_renewal,
    check_idempotent,
    needs_renew,
    overlap_ok,
    renew_batch,
    request_renewal,
    rollback,
    validate_chain,
)

NOW = datetime(2026, 11, 25, 9, 0, tzinfo=timezone.utc)
POLICY = {
    "renew_before_days": 30,
    "overlap_days": 7,
    "key_policy": "reuse",
    "valid_days": 90,
}


def make_cert(cert_id="cert-a", subject="CN=alpha.example", key_id="key-a",
              serial=100, not_after=None, policy=None, **extra):
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
    cert.update(extra)
    return cert


def make_store(*certs):
    return {
        "certs": {c["cert_id"]: c for c in certs},
        "journal": {},
        "renewals": {},
    }


def issue(request, not_before, not_after):
    new = dict(request)
    new["not_before"] = not_before
    new["not_after"] = not_after
    return new


def is_valid(cert, when):
    if not cert.get("active", True):
        return False
    if cert.get("revoked_at") is not None:
        return False
    if when < cert["not_before"]:
        return False
    return when <= (cert.get("deactivate_at") or cert["not_after"])


# --- window policy -------------------------------------------------------

def test_window_boundaries():
    policy = dict(POLICY, renew_before_days=30)
    assert needs_renew(make_cert(not_after=NOW + timedelta(days=30)), NOW, policy) is True
    assert needs_renew(make_cert(not_after=NOW + timedelta(days=31)), NOW, policy) is False
    # Outside the window (well before) -> no renewal.
    assert needs_renew(make_cert(not_after=NOW + timedelta(days=90)), NOW, policy) is False


def test_window_respects_custom_policy():
    policy = dict(POLICY, renew_before_days=5)
    assert needs_renew(make_cert(not_after=NOW + timedelta(days=10)), NOW, policy) is False
    assert needs_renew(make_cert(not_after=NOW + timedelta(days=5)), NOW, policy) is True


# --- overlap invariant ---------------------------------------------------

def test_overlap_honours_policy_length():
    old = make_cert(not_after=NOW + timedelta(days=40))
    request = request_renewal(old, dict(POLICY, overlap_days=7))
    new = issue(request, NOW, NOW + timedelta(days=90))
    store = make_store(old)
    apply_renewal(store, old, new, NOW)

    assert old["deactivate_at"] == NOW + timedelta(days=7)
    assert is_valid(old, NOW + timedelta(days=6)) is True
    assert is_valid(new, NOW + timedelta(days=6)) is True
    assert overlap_ok(old, new, dict(POLICY, overlap_days=7)) is True
    assert overlap_ok(old, new, dict(POLICY, overlap_days=8)) is False


def test_old_cert_not_revoked_on_renewal():
    old = make_cert(not_after=NOW + timedelta(days=20))
    store = make_store(old)
    apply_renewal(store, old, issue(request_renewal(old, POLICY), NOW, NOW + timedelta(days=90)), NOW)
    assert old["revoked_at"] is None
    assert old["active"] is True


# --- idempotency invariant ----------------------------------------------

def test_repeated_request_is_deterministic():
    cert = make_cert()
    a = request_renewal(cert, POLICY)
    b = request_renewal(cert, POLICY)
    assert a == b


def test_repeated_apply_yields_single_successor():
    old = make_cert(not_after=NOW + timedelta(days=20))
    store = make_store(old)
    request = request_renewal(old, POLICY)
    first = apply_renewal(store, old, issue(request, NOW, NOW + timedelta(days=90)), NOW)
    second = apply_renewal(store, old, issue(request, NOW, NOW + timedelta(days=90)), NOW)

    successors = [cid for cid in store["certs"] if cid != old["cert_id"]]
    assert len(successors) == 1
    assert first["new_cert_id"] == second["new_cert_id"]
    assert second.get("idempotent") is True
    assert check_idempotent(store, old) is True


def test_batch_is_idempotent_across_runs():
    old = make_cert(not_after=NOW + timedelta(days=10))
    store = make_store(old)
    renew_batch([(store, old)], POLICY, NOW)
    renew_batch([(store, old)], POLICY, NOW)
    assert len([cid for cid in store["certs"] if cid != old["cert_id"]]) == 1


# --- key policy ----------------------------------------------------------

def test_reuse_policy_keeps_key():
    cert = make_cert()
    request = request_renewal(cert, POLICY)
    assert request["key_id"] == cert["key_id"]
    assert validate_chain(cert, issue(request, NOW, NOW + timedelta(days=90))) == []


def test_rotate_policy_changes_key_and_validates():
    cert = make_cert()
    policy = dict(POLICY, key_policy="rotate")
    request = request_renewal(cert, policy)
    assert request["key_id"] != cert["key_id"]
    new = issue(request, NOW, NOW + timedelta(days=90))
    assert validate_chain(cert, new) == []
    store = make_store(cert)
    apply_renewal(store, cert, new, NOW)
    assert store["certs"][new["cert_id"]]["key_id"] == request["key_id"]


def test_validate_chain_does_not_mutate():
    old = make_cert()
    new = dict(request_renewal(old, POLICY))
    new["key_id"] = "different"
    before = dict(new)
    validate_chain(old, new)
    assert new == before
    assert "key mismatch" in validate_chain(old, new)


# --- failure isolation ---------------------------------------------------

def test_failed_apply_leaves_old_untouched():
    old = make_cert(not_after=NOW + timedelta(days=20))
    store = make_store(old)
    request = request_renewal(old, POLICY)
    expired = issue(request, NOW - timedelta(days=10), NOW - timedelta(days=1))

    with pytest.raises(ValueError):
        apply_renewal(store, old, expired, NOW)

    assert old["deactivate_at"] is None
    assert expired["cert_id"] not in store["certs"]
    assert store["renewals"] == {}
    assert check_idempotent(store, old) is False


def test_rollback_restores_journaled_state():
    old = make_cert(not_after=NOW + timedelta(days=20))
    store = make_store(old)
    # Simulate an unfinished renewal that was written but not committed.
    store["journal"][old["cert_id"]] = {"old": dict(old), "new_id": "cert-a-101"}
    store["certs"]["cert-a-101"] = {"cert_id": "cert-a-101", "serial": 101}
    store["renewals"][old["cert_id"]] = "cert-a-101"
    old["deactivate_at"] = NOW + timedelta(days=7)

    result = rollback(store, old)

    assert result["restored"] is True
    assert store["certs"][old["cert_id"]]["deactivate_at"] is None
    assert "cert-a-101" not in store["certs"]
    assert old["cert_id"] not in store["renewals"]


def test_batch_failure_does_not_affect_other_certs():
    good = make_cert(cert_id="good", not_after=NOW + timedelta(days=10))
    bad = make_cert(
        cert_id="bad",
        subject="CN=bad.example",
        key_id="key-b",
        serial=200,
        policy=dict(POLICY, valid_days=0),
        not_after=NOW + timedelta(days=10),
    )
    store_good = make_store(good)
    store_bad = make_store(bad)

    result = renew_batch([(store_good, good), (store_bad, bad)], POLICY, NOW)

    assert result["results"][0]["status"] == "renewed"
    assert result["results"][1]["status"] == "failed"
    assert store_good["certs"][good["cert_id"]]["deactivate_at"] == NOW + timedelta(days=7)
    assert store_bad["certs"][bad["cert_id"]]["deactivate_at"] is None
    assert bad["cert_id"] not in store_bad["renewals"]


def test_batch_uses_each_cert_policy():
    a = make_cert(cert_id="a", policy=dict(POLICY, overlap_days=21, renew_before_days=30),
                  not_after=NOW + timedelta(days=10))
    b = make_cert(cert_id="b", subject="CN=b", key_id="key-b", serial=200,
                  policy=dict(POLICY, overlap_days=3), not_after=NOW + timedelta(days=10))
    sa, sb = make_store(a), make_store(b)
    renew_batch([(sa, a), (sb, b)], POLICY, NOW)
    assert sa["certs"]["a"]["deactivate_at"] == NOW + timedelta(days=21)
    assert sb["certs"]["b"]["deactivate_at"] == NOW + timedelta(days=3)


def test_batch_skips_cert_outside_its_window():
    inside = make_cert(cert_id="in", not_after=NOW + timedelta(days=5))
    outside = make_cert(cert_id="out", subject="CN=out", key_id="k2", serial=2,
                        policy=dict(POLICY, renew_before_days=1),
                        not_after=NOW + timedelta(days=60))
    s1, s2 = make_store(inside), make_store(outside)
    result = renew_batch([(s1, inside), (s2, outside)], POLICY, NOW)
    assert result["renewed"] == 1
    assert result["skipped"] == 1
    assert s2["renewals"] == {}
