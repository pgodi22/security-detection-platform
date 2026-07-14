from app.models import Customer, Detection, DetectionStatus, Signature
from app.routes.incidents import _find_best_signature


# --- signature matching ------------------------------------------------------


def test_exact_match():
    sig = Signature(id=1, name="ssh-brute-force", priority=5, fields={"event_type": "auth_failure"})
    assert _find_best_signature([sig], {"event_type": "auth_failure"}) is sig


def test_no_match_returns_none():
    sig = Signature(id=1, name="ssh-brute-force", priority=5, fields={"event_type": "auth_failure"})
    assert _find_best_signature([sig], {"event_type": "port_scan"}) is None


def test_highest_priority_wins_on_multiple_matches():
    low = Signature(id=1, name="low", priority=3, fields={"event_type": "auth_failure"})
    high = Signature(id=2, name="high", priority=9, fields={"event_type": "auth_failure"})
    assert _find_best_signature([low, high], {"event_type": "auth_failure"}) is high


# --- priority calculation -----------------------------------------------------


def test_priority_is_importance_times_signature_priority(client, db_session):
    customer = Customer(name="Acme", importance_level=4)
    signature = Signature(name="ssh-brute-force", priority=5, fields={"event_type": "auth_failure"})
    db_session.add_all([customer, signature])
    db_session.commit()

    response = client.post(
        "/incidents/ingest",
        json={"customer_id": customer.id, "fields": {"event_type": "auth_failure"}},
    )

    assert response.status_code == 200
    assert response.json()["priority"] == 20


# --- role enforcement ----------------------------------------------------------


def test_readonly_forbidden_from_creating_customer(client, login_as):
    cookies = login_as("readonly")
    response = client.post("/customers", json={"name": "Acme", "importance_level": 5}, cookies=cookies)
    assert response.status_code == 403


def test_analyst_forbidden_from_creating_customer(client, login_as):
    cookies = login_as("analyst")
    response = client.post("/customers", json={"name": "Acme", "importance_level": 5}, cookies=cookies)
    assert response.status_code == 403


def test_admin_can_create_customer(client, login_as):
    cookies = login_as("admin")
    response = client.post(
        "/customers",
        json={"name": "Acme", "importance_level": 5},
        cookies=cookies,
        follow_redirects=False,
    )
    assert response.status_code == 303


# --- claim conflict (race condition) --------------------------------------------


def test_second_claim_on_same_detection_is_rejected(client, login_as, db_session):
    customer = Customer(name="Acme", importance_level=5)
    signature = Signature(name="ssh-brute-force", priority=3, fields={"event_type": "auth_failure"})
    db_session.add_all([customer, signature])
    db_session.commit()
    detection = Detection(
        signature_id=signature.id,
        customer_id=customer.id,
        priority=15,
        status=DetectionStatus.open,
    )
    db_session.add(detection)
    db_session.commit()

    cookies = login_as("analyst")
    # stands in for two concurrent claims: whichever request reaches the row lock
    # second always finds it already claimed, so the outcome is the same either way
    first = client.post(f"/detections/queue/claim/{detection.id}", cookies=cookies, follow_redirects=False)
    second = client.post(f"/detections/queue/claim/{detection.id}", cookies=cookies, follow_redirects=False)

    assert first.status_code == 303
    assert second.status_code == 409
    assert second.json()["detail"] == "Detection already claimed by another analyst"
