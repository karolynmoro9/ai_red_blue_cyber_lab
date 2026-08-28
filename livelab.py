import json
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
client = OpenAI()

BASE_DIR = Path(__file__).parent
LOG_FILE = BASE_DIR / "logs" / "auth.log"
BLOCK_FILE = BASE_DIR / "logs" / "blocked_clients.json"
REPORT_FILE = BASE_DIR / "logs" / "live_blue_report.json"
EVALUATION_FILE = BASE_DIR / "logs" / "evaluation.json"
RED_AGENT = BASE_DIR / "agents" / "red_agent.py"

POLL_INTERVAL = 0.5
INITIAL_FAILURE_THRESHOLD = 2
ESCALATED_FAILURE_THRESHOLD = 4
MAX_BLUE_ACTIVATIONS = 4

PROTECTED_CLIENTS = {
    "manual-client",
    "blue-team",
    "health-monitor",
    "untrusted-client",
}


def clean_json(text):
    text = text.strip()

    if text.startswith("```"):
        text = (
            text.replace("```json", "")
            .replace("```", "")
            .strip()
        )

    return json.loads(text)


def call_agent(role, instructions, evidence):
    prompt = f"""
You are the {role} in an authorized local cybersecurity lab.

Analyze the behavior as though it occurred in a real environment.
Do not judge a client based on its name.
Judge only the observed authentication behavior and prior findings.

Instructions:
{instructions}

Evidence:
{json.dumps(evidence, indent=2)}

Return only valid JSON without Markdown.
"""

    response = client.responses.create(
        model="gpt-5.6-luna",
        input=prompt,
        reasoning={"effort": "low"},
    )

    return clean_json(response.output_text)


def read_log_lines():
    if not LOG_FILE.exists():
        return []

    return LOG_FILE.read_text(
        encoding="utf-8"
    ).splitlines()


def parse_event(line):
    client_match = re.search(
        r"client='([^']+)'",
        line,
    )
    username_match = re.search(
        r"username='([^']*)'",
        line,
    )
    outcome_match = re.search(
        r"outcome=([A-Z]+)",
        line,
    )

    if not client_match or not outcome_match:
        return None

    return {
        "timestamp": line.split(" ", 1)[0],
        "client": client_match.group(1),
        "username": (
            username_match.group(1)
            if username_match
            else ""
        ),
        "outcome": outcome_match.group(1),
        "raw": line,
    }


def parse_new_events(starting_line):
    lines = read_log_lines()[starting_line:]
    events = []

    for line in lines:
        event = parse_event(line)

        if event:
            events.append(event)

    return events


def events_for_client(events, client_id):
    return [
        event
        for event in events
        if event["client"] == client_id
    ]


def failure_counts(events):
    counts = Counter()

    for event in events:
        if event["outcome"] == "FAILED":
            counts[event["client"]] += 1

    return counts


def has_failure_then_success(events, client_id):
    failure_seen = False

    for event in events_for_client(
        events,
        client_id,
    ):
        if event["outcome"] == "FAILED":
            failure_seen = True

        elif (
            event["outcome"] == "SUCCESS"
            and failure_seen
        ):
            return True

    return False


def load_blocked_clients():
    if not BLOCK_FILE.exists():
        return []

    try:
        data = json.loads(
            BLOCK_FILE.read_text(encoding="utf-8")
        )
        return data.get("blocked_clients", [])
    except (json.JSONDecodeError, OSError):
        return []


def block_client(client_id):
    blocked = set(load_blocked_clients())
    blocked.add(client_id)

    BLOCK_FILE.write_text(
        json.dumps(
            {"blocked_clients": sorted(blocked)},
            indent=2,
        ),
        encoding="utf-8",
    )


def client_reports(reports, client_id):
    return [
        report
        for report in reports
        if report["trigger_client"] == client_id
    ]


def find_trigger(events, completed_stages):
    counts = failure_counts(events)

    clients = sorted(
        {
            event["client"]
            for event in events
        }
    )

    for client_id in clients:
        if client_id in PROTECTED_CLIENTS:
            continue

        failures = counts.get(client_id, 0)

        compromise_stage = (
            client_id,
            "failure_then_success",
        )
        escalated_stage = (
            client_id,
            "four_failures",
        )
        initial_stage = (
            client_id,
            "two_failures",
        )

        if (
            has_failure_then_success(
                events,
                client_id,
            )
            and compromise_stage
            not in completed_stages
        ):
            return (
                client_id,
                "failure followed by success",
                failures,
                compromise_stage,
            )

        if (
            failures
            >= ESCALATED_FAILURE_THRESHOLD
            and escalated_stage
            not in completed_stages
        ):
            return (
                client_id,
                "continued attempts after alert",
                failures,
                escalated_stage,
            )

        if (
            failures
            >= INITIAL_FAILURE_THRESHOLD
            and initial_stage
            not in completed_stages
        ):
            return (
                client_id,
                "initial repeated failures",
                failures,
                initial_stage,
            )

    return None, None, 0, None


# Reset only the application-level blocklist.
BLOCK_FILE.write_text(
    json.dumps(
        {"blocked_clients": []},
        indent=2,
    ),
    encoding="utf-8",
)

starting_line = len(read_log_lines())
completed_stages = set()
reports = []
activation_count = 0
lab_start_time = time.perf_counter()
first_detection_time = None
containment_time = None

print("\nADAPTIVE LIVE RED VS BLUE LAB")
print("Previous authentication logs preserved.")
print("Application blocklist reset.")
print("Blue team has no preselected attacker.")
print("\nEscalation policy:")
print("- 2 failures: initial assessment")
print("- 4 failures: escalated reassessment")
print("- Failure then success: compromise assessment\n")

red_process = subprocess.Popen(
    [sys.executable, str(RED_AGENT)],
    cwd=str(BASE_DIR),
)

while True:
    events = parse_new_events(starting_line)

    (
        trigger_client,
        trigger_reason,
        trigger_failures,
        trigger_stage,
    ) = find_trigger(
        events,
        completed_stages,
    )

    if trigger_client:
        completed_stages.add(trigger_stage)
        activation_count += 1

        current_events = events_for_client(
            events,
            trigger_client,
        )
        prior_reports = client_reports(
            reports,
            trigger_client,
        )

        print("\nBLUE SENSOR: New risk stage reached.")
        print(f"Observed client: {trigger_client}")
        print(f"Trigger: {trigger_reason}")
        print(
            f"Total failures: "
            f"{trigger_failures}"
        )
        print(
            f"Prior assessments: "
            f"{len(prior_reports)}"
        )
        print("Activating blue AI agents...\n")

        investigation = call_agent(
            role="Detection and Investigation Agent",
            instructions="""
Investigate the authentication events and prior assessments.

Determine whether the behavior is:
- a likely user mistake,
- suspicious password guessing,
- continued hostile behavior after an alert, or
- a likely account compromise.

Return exactly:
{
  "suspicious": true or false,
  "pattern": "short pattern name",
  "suspected_client": "client identity or NONE",
  "findings": "short explanation",
  "escalation_reason": "what changed since the prior assessment"
}
""",
            evidence={
                "trigger": trigger_reason,
                "current_events": current_events,
                "prior_assessments": prior_reports,
            },
        )

        rule_confirmed_compromise = has_failure_then_success(
            events,
            trigger_client,
        )
        detection_supported = (
            investigation["suspicious"] is True
            or rule_confirmed_compromise
        )

        if (
            detection_supported
            and first_detection_time is None
        ):
            first_detection_time = time.perf_counter()

        print("DETECTION/INVESTIGATION AGENT")
        print(
            f"Pattern: "
            f"{investigation['pattern']}"
        )
        print(
            f"Suspicious: "
            f"{investigation['suspicious']}"
        )
        print(
            f"Suspected client: "
            f"{investigation['suspected_client']}"
        )
        print(
            f"Findings: "
            f"{investigation['findings']}"
        )
        print(
            f"Escalation: "
            f"{investigation['escalation_reason']}\n"
        )

        if (
            investigation["suspicious"] is not True
            and rule_confirmed_compromise
        ):
            print(
                "COORDINATOR NOTE: Deterministic sensor "
                "confirmed failure followed by success.\n"
            )

        response = call_agent(
            role="Risk and Response Agent",
            instructions="""
Choose one response:
MONITOR, ALERT, or BLOCK_CLIENT.

Policy:
- Two isolated failures may justify ALERT.
- Continued attempts reaching four failures provide
  stronger evidence of intentional password guessing.
- Failure followed by success from the same client is evidence of likely account compromise.
- For likely account compromise, choose HIGH severity and BLOCK_CLIENT using the observed client identity.
- Consider prior assessments when escalating a response.
- Use BLOCK_CLIENT only when supported by specific evidence.

Return exactly:
{
  "severity": "LOW, MEDIUM, HIGH, or CRITICAL",
  "action": "MONITOR, ALERT, or BLOCK_CLIENT",
  "target_client": "client identity or NONE",
  "reason": "short explanation"
}
""",
            evidence={
                "trigger": trigger_reason,
                "failures": trigger_failures,
                "current_events": current_events,
                "prior_assessments": prior_reports,
                "investigation": investigation,
            },
        )

        print("RISK/RESPONSE AGENT")
        print(
            f"Severity: {response['severity']}"
        )
        print(f"Action: {response['action']}")
        print(
            f"Target: {response['target_client']}"
        )
        print(f"Reason: {response['reason']}\n")

        confirmed_behavior = (
            trigger_failures
            >= ESCALATED_FAILURE_THRESHOLD
            or rule_confirmed_compromise
        )

        approved_action = "ALERT"

        # Non-AI safety coordinator.
        if (
            detection_supported
            and response["action"] == "BLOCK_CLIENT"
            and response["target_client"]
            == trigger_client
            and trigger_client not in PROTECTED_CLIENTS
            and confirmed_behavior
        ):
            approved_action = "BLOCK_CLIENT"
            block_client(trigger_client)
            containment_time = time.perf_counter()

            print(
                "DEFENSIVE ACTUATOR: Blocked "
                f"{trigger_client}"
            )
        else:
            print(
                "COORDINATOR: No block executed."
            )

        report = {
            "trigger_client": trigger_client,
            "trigger_reason": trigger_reason,
            "failure_count": trigger_failures,
            "events": current_events,
            "prior_assessment_count": len(
                prior_reports
            ),
            "investigation": investigation,
            "rule_confirmed_compromise": (
                rule_confirmed_compromise
            ),
            "response": response,
            "approved_action": approved_action,
        }

        reports.append(report)

        REPORT_FILE.write_text(
            json.dumps(reports, indent=2),
            encoding="utf-8",
        )

    # Final scan occurs before exiting.
    if red_process.poll() is not None:
        break

    if activation_count >= MAX_BLUE_ACTIVATIONS:
        print(
            "Coordinator reached the blue-agent "
            "activation limit."
        )
        break

    time.sleep(POLL_INTERVAL)

red_process.wait()

investigated_clients = sorted(
    {
        report["trigger_client"]
        for report in reports
    }
)

print("\nADAPTIVE LIVE LAB COMPLETE")
print(
    f"Clients investigated: "
    f"{investigated_clients}"
)
print(
    f"Assessments performed: {len(reports)}"
)
print(
    f"Blocked clients: "
    f"{load_blocked_clients()}"
)

final_events = parse_new_events(starting_line)
blocked_clients = load_blocked_clients()

if blocked_clients:
    final_outcome = "BLOCKED"
elif reports:
    final_outcome = "DETECTED_ONLY"
else:
    final_outcome = "MISSED"

evaluation = {
    "final_outcome": final_outcome,
    "time_to_detection_seconds": (
        round(first_detection_time - lab_start_time, 2)
        if first_detection_time is not None
        else None
    ),
    "time_to_containment_seconds": (
        round(containment_time - lab_start_time, 2)
        if containment_time is not None
        else None
    ),
    "attempts_before_containment": len(
        [
            event
            for event in final_events
            if event["outcome"] != "BLOCKED"
        ]
    ),
    "blue_investigations": len(reports),
    "blocked_clients": blocked_clients,
}

EVALUATION_FILE.write_text(
    json.dumps(evaluation, indent=2),
    encoding="utf-8",
)

print("\nEVALUATION METRICS")
print(json.dumps(evaluation, indent=2))
print(f"Saved to: {EVALUATION_FILE}")