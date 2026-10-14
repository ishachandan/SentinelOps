"""Manual live-server verification of the five Flask confirmation gates."""
import json
import requests

BASE_URL = "http://localhost:5000"


def seed(session, token, ip):
    response = session.post(
        f"{BASE_URL}/debug/seed_token",
        json={
            "token": token,
            "action_type": "block_ip",
            "ip": ip,
            "reason": "Manual security gate verification",
        },
        timeout=5,
    )
    assert response.status_code == 200, response.text
    assert response.json()["token"] == token


def main():
    first_session = requests.Session()
    other_session = requests.Session()
    first_session.get(BASE_URL, timeout=5)
    other_session.get(BASE_URL, timeout=5)

    seed(first_session, "a1100001", "192.168.1.5")
    valid = first_session.post(f"{BASE_URL}/confirm/a1100001", timeout=15)
    assert valid.status_code == 200, valid.text
    assert valid.json()["success"] is True
    print("PASS: valid token for its owning session executes")

    fake = first_session.post(f"{BASE_URL}/confirm/fake0001", timeout=5)
    assert fake.status_code == 404
    print("PASS: fake token returns 404")

    reused = first_session.post(f"{BASE_URL}/confirm/a1100001", timeout=5)
    assert reused.status_code == 400
    print("PASS: reused token returns 400")

    seed(first_session, "a1100002", "10.0.0.100")
    cross_session = other_session.post(
        f"{BASE_URL}/confirm/a1100002", timeout=5
    )
    assert cross_session.status_code == 403
    print("PASS: cross-session confirmation returns 403")

    seed(first_session, "a1100003", "203.0.113.10")
    declined = first_session.post(f"{BASE_URL}/decline/a1100003", timeout=5)
    assert declined.status_code == 200
    assert declined.json()["success"] is True
    with open("data/pending_actions.json", encoding="utf-8") as actions_file:
        actions = json.load(actions_file)
    assert actions["a1100003"]["status"] == "declined"
    assert actions["a1100003"]["status"] != "executed"
    print("PASS: declined action remains unexecuted")
    print("PASS: all five live-server confirmation-gate checks passed")


if __name__ == "__main__":
    main()
