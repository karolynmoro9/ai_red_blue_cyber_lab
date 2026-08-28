import json
import os
import time

import requests
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
client = OpenAI()

TARGET = "http://127.0.0.1:5000/login"
CLIENT_ID = "red-agent-01"
SCENARIO = os.getenv("RED_SCENARIO", "ai").strip().lower()

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

SCENARIOS = {
    "benign": [
        {
            "username": "admin",
            "password": "password",
            "reason": "Simulates one ordinary mistyped login.",
        },
    ],
    "brute_force": [
        {
            "username": "admin",
            "password": "password",
            "reason": "Begins controlled password guessing.",
        },
        {
            "username": "admin",
            "password": "password123",
            "reason": "Tests a second common password.",
        },
        {
            "username": "admin",
            "password": "admin123",
            "reason": "Continues the controlled guessing pattern.",
        },
        {
            "username": "administrator",
            "password": "password",
            "reason": "Tests another administrative username.",
        },
        {
            "username": "root",
            "password": "password123",
            "reason": "Checks whether containment has taken effect.",
        },
    ],
    "compromise": [
        {
            "username": "admin",
            "password": "password",
            "reason": "Begins controlled credential testing against a privileged account.",
        },
        {
            "username": "administrator",
            "password": "admin123",
            "reason": "Creates a second privileged-account failure and triggers an initial alert.",
        },
        {
            "username": "labadmin",
            "password": "BlueTeam!2026",
            "reason": "Simulates a successful privileged login after repeated credential testing.",
        },
    ],
}

ALLOWED_SCENARIOS = {"ai", *SCENARIOS}
history = []


def choose_ai_credentials():
    prompt = f"""
You are the reasoning component of a red-team agent operating in an
authorized local cybersecurity lab.

Target: a login service restricted to 127.0.0.1.
Your goal is to test credential security while minimizing attempts.

Allowed usernames: {USERNAMES}
Allowed passwords: {PASSWORDS}
Previous results: {history}

Choose one username/password combination that has not already been tried.

Return only valid JSON in this format:
{{"username":"value","password":"value","reason":"short explanation"}}
"""

    response = client.responses.create(
        model="gpt-5.6-luna",
        input=prompt,
        reasoning={"effort": "low"},
    )

    text = response.output_text.strip()

    if text.startswith("```"):
        text = (
            text.replace("```json", "")
            .replace("```", "")
            .strip()
        )

    return json.loads(text)


def validate_decision(decision):
    if decision["username"] not in USERNAMES:
        raise ValueError("Agent selected a disallowed username")

    if decision["password"] not in PASSWORDS:
        raise ValueError("Agent selected a disallowed password")


def attempt_login(decision):
    if not TARGET.startswith("http://127.0.0.1:5000/"):
        raise RuntimeError(
            "Safety boundary violation: target is not local"
        )

    response = requests.post(
        TARGET,
        headers={
            "X-Lab-Agent-ID": CLIENT_ID,
        },
        json={
            "username": decision["username"],
            "password": decision["password"],
        },
        timeout=5,
    )

    return response.status_code, response.json()


if SCENARIO not in ALLOWED_SCENARIOS:
    raise ValueError(
        f"Unknown RED_SCENARIO '{SCENARIO}'. "
        f"Choose from {sorted(ALLOWED_SCENARIOS)}."
    )

if SCENARIO == "ai":
    decisions = None
    maximum_attempts = 5
else:
    decisions = SCENARIOS[SCENARIO]
    maximum_attempts = len(decisions)

print("RED AGENT STARTED")
print(f"Identity: {CLIENT_ID}")
print(f"Safety boundary: {TARGET}")
print(f"Scenario: {SCENARIO}")
print(f"Maximum attempts: {maximum_attempts}\n")

for attempt_number in range(1, maximum_attempts + 1):
    if SCENARIO == "ai":
        decision = choose_ai_credentials()
    else:
        decision = decisions[attempt_number - 1]

    validate_decision(decision)

    print(f"Attempt {attempt_number}")
    print(f"Reasoning: {decision['reason']}")
    print(f"Selected username: {decision['username']}")
    print("Selected password: [hidden]")

    status, result = attempt_login(decision)

    if status == 403:
        print(f"Result: {status} - {result['message']}")
        print("RED AGENT detected that the blue team blocked it.")
        break

    successful = status == 200

    print(f"Result: {status} - {result['message']}\n")

    history.append(
        {
            "username": decision["username"],
            "password": decision["password"],
            "result": "success" if successful else "failed",
        }
    )

    if successful:
        print("RED AGENT achieved its lab objective.")
        break

    if attempt_number < maximum_attempts:
        time.sleep(8)
else:
    print("RED AGENT stopped after reaching its attempt limit.")
