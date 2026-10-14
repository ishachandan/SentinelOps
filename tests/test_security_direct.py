"""Manual live-server confirmation-gate checks using the debug seeding route."""
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
            "reason": "Direct security gate verification",
        },
        timeout=5,
    )
    assert response.status_code == 200, response.text
    return response.json()


def main():
    owner = requests.Session()
    stranger = requests.Session()
    owner.get(BASE_URL, timeout=5)
    stranger.get(BASE_URL, timeout=5)

    seeded = seed(owner, "d1ec7001", "10.0.0.100")
    assert seeded["status"] == "pending"
    confirmed = owner.post(f"{BASE_URL}/confirm/d1ec7001", timeout=15)
    assert confirmed.status_code == 200 and confirmed.json()["success"]
    print("PASS: owning session confirmed and executed a seeded action")

    fake = owner.post(f"{BASE_URL}/confirm/fake70001", timeout=5)
    assert fake.status_code == 404
    print("PASS: unknown action rejected")

    reused = owner.post(f"{BASE_URL}/confirm/d1ec7001", timeout=5)
    assert reused.status_code == 400
    print("PASS: reused action rejected")

    seed(owner, "d1ec7002", "192.168.1.5")
    cross_session = stranger.post(f"{BASE_URL}/confirm/d1ec7002", timeout=5)
    assert cross_session.status_code == 403
    print("PASS: cross-session action rejected")

    seed(owner, "d1ec7003", "203.0.113.10")
    declined = owner.post(f"{BASE_URL}/decline/d1ec7003", timeout=5)
    assert declined.status_code == 200
    with open("data/pending_actions.json", encoding="utf-8") as actions_file:
        actions = json.load(actions_file)
    assert actions["d1ec7003"]["status"] == "declined"
    print("PASS: declined action was not executed")
    print("PASS: all direct security checks passed without Groq/API calls")


if __name__ == "__main__":
    main()
