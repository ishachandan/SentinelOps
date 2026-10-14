"""Manual check that the debug seeding endpoint works when explicitly enabled."""
import requests

BASE_URL = "http://localhost:5000"


def main():
    response = requests.post(
        f"{BASE_URL}/debug/seed_token",
        json={
            "token": "d06b6001",
            "action_type": "block_ip",
            "ip": "192.168.1.5",
            "reason": "Debug endpoint gate verification",
        },
        timeout=5,
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["success"] is True
    assert result["token"] == "d06b6001"
    print("PASS: explicitly enabled debug seeding endpoint returned HTTP 200")
    print("NOTE: the disabled/404 behavior is covered by test_client tests.")


if __name__ == "__main__":
    main()
