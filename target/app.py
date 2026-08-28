import json
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request

app = Flask(__name__)

LAB_USERNAME = "labadmin"
LAB_PASSWORD = "BlueTeam!2026"

BASE_DIR = Path(__file__).parent.parent
LOG_FILE = BASE_DIR / "logs" / "auth.log"
BLOCK_FILE = BASE_DIR / "logs" / "blocked_clients.json"

LOG_FILE.parent.mkdir(exist_ok=True)


def get_client_id():
    if request.remote_addr != "127.0.0.1":
        return "untrusted-client"

    client_id = request.headers.get("X-Lab-Agent-ID", "manual-client")
    return client_id[:50]


def get_blocked_clients():
    if not BLOCK_FILE.exists():
        return []

    try:
        data = json.loads(BLOCK_FILE.read_text(encoding="utf-8"))
        return data.get("blocked_clients", [])
    except (json.JSONDecodeError, OSError):
        return []


def record_attempt(username, outcome, client_id):
    timestamp = datetime.now(timezone.utc).isoformat()

    with LOG_FILE.open("a", encoding="utf-8") as log:
        log.write(
            f"{timestamp} source={request.remote_addr} "
            f"client={client_id!r} username={username!r} "
            f"outcome={outcome}\n"
        )


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))
    client_id = get_client_id()

    if client_id in get_blocked_clients():
        record_attempt(username, "BLOCKED", client_id)
        return jsonify(message="Client blocked by blue team"), 403

    successful = username == LAB_USERNAME and password == LAB_PASSWORD
    outcome = "SUCCESS" if successful else "FAILED"
    record_attempt(username, outcome, client_id)

    if successful:
        return jsonify(message="Authentication successful"), 200

    return jsonify(message="Invalid credentials"), 401


@app.get("/health")
def health():
    return jsonify(status="healthy"), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)