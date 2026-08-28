import json
import socket
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
RED_AGENT = BASE_DIR / "agents" / "red_cowrie_agent.py"
LOCAL_REPORT_DIR = BASE_DIR / "reports"
LOCAL_REPORT = LOCAL_REPORT_DIR / "cowrie_blue_report.json"

UBUNTU_HOST = "192.168.8.121"
UBUNTU_SSH_PORT = 22
COWRIE_PORT = 2222
BLUE_USER = "blue-reader"
SSH_KEY = Path.home() / ".ssh" / "cowrie_blue_ed25519"

REMOTE_PYTHON = "/home/blue-reader/blue-env/bin/python"
REMOTE_AGENT = "/home/blue-reader/cowrie_blue_agent.py"
REMOTE_REPORT = "/home/blue-reader/reports/cowrie_blue_report.json"


def require_file(path, description):
    if not path.is_file():
        raise FileNotFoundError(
            f"Missing {description}: {path}"
        )


def require_port(host, port, description):
    try:
        with socket.create_connection(
            (host, port),
            timeout=5,
        ):
            return
    except OSError as error:
        raise ConnectionError(
            f"{description} is unreachable at "
            f"{host}:{port}: {error}"
        ) from error


def run_command(command, description):
    print(f"\n{description}")
    print("=" * len(description))

    result = subprocess.run(
        command,
        cwd=BASE_DIR,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"{description} failed with exit code "
            f"{result.returncode}."
        )


def remote_ssh_arguments():
    return [
        "-i",
        str(SSH_KEY),
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "StrictHostKeyChecking=yes",
    ]


def print_combined_summary():
    report = json.loads(
        LOCAL_REPORT.read_text(encoding="utf-8")
    )

    summary = report["summary"]
    investigation = report["investigation"]
    response = report["response"]
    usage = report["api_usage"]

    print("\nDISTRIBUTED COWRIE LAB COMPLETE")
    print("================================")
    print(f"Source analyzed: {summary['source_ip']}")
    print(
        f"Login events: "
        f"{summary['total_login_events']}"
    )
    print(
        f"Failed logins: {summary['failed_logins']}"
    )
    print(
        f"Successful logins: "
        f"{summary['successful_logins']}"
    )
    print(f"Pattern: {investigation['pattern']}")
    print(f"Severity: {investigation['severity']}")
    print(f"Recommended action: {response['action']}")
    print(
        f"Blue analysis time: "
        f"{report['analysis_seconds']} seconds"
    )
    print(f"Blue API calls: {usage['calls']}")
    print(f"Blue tokens: {usage['total_tokens']}")
    print("Passwords shared with blue AI: NO")
    print(f"Local report: {LOCAL_REPORT}")


def main():
    print("\nDISTRIBUTED AI RED VS BLUE COWRIE LAB")
    print("======================================")
    print(f"Windows coordinator: {BASE_DIR}")
    print(f"Locked Ubuntu host: {UBUNTU_HOST}")
    print(f"Locked Cowrie port: {COWRIE_PORT}")
    print(f"Read-only blue identity: {BLUE_USER}")

    require_file(RED_AGENT, "Cowrie red agent")
    require_file(SSH_KEY, "dedicated blue-reader SSH key")

    print("\nChecking isolated lab services...")
    require_port(
        UBUNTU_HOST,
        UBUNTU_SSH_PORT,
        "Ubuntu SSH service",
    )
    require_port(
        UBUNTU_HOST,
        COWRIE_PORT,
        "Cowrie honeypot",
    )
    print("Ubuntu SSH: reachable")
    print("Cowrie SSH: reachable")

    run_command(
        [sys.executable, str(RED_AGENT)],
        "PHASE 1: WINDOWS AI RED AGENT",
    )

    print("\nWaiting for Cowrie to flush JSON telemetry...")
    time.sleep(2)

    remote_command = (
        f"{REMOTE_PYTHON} {REMOTE_AGENT}"
    )

    run_command(
        [
            "ssh",
            *remote_ssh_arguments(),
            f"{BLUE_USER}@{UBUNTU_HOST}",
            remote_command,
        ],
        "PHASE 2: UBUNTU AI BLUE AGENTS",
    )

    LOCAL_REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    run_command(
        [
            "scp",
            *remote_ssh_arguments(),
            (
                f"{BLUE_USER}@{UBUNTU_HOST}:"
                f"{REMOTE_REPORT}"
            ),
            str(LOCAL_REPORT),
        ],
        "PHASE 3: RETRIEVE SANITIZED REPORT",
    )

    print_combined_summary()


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        print(f"\nLAB ERROR: {error}")
        raise SystemExit(1)
