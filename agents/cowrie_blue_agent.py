import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

LOG_FILE = Path(
    "/home/cowrie/my-honeypot/var/log/cowrie/cowrie.json"
)
REPORT_DIR = Path.home() / "reports"
REPORT_FILE = REPORT_DIR / "cowrie_blue_report.json"
HISTORY_FILE = REPORT_DIR / "cowrie_run_history.jsonl"
LOOKBACK_LINES = 500
ANALYSIS_WINDOW_MINUTES = 10

load_dotenv(Path.home() / ".env")
client = OpenAI()

api_usage = {
    "calls": 0,
    "input_tokens": 0,
    "output_tokens": 0,
    "total_tokens": 0,
    "call_details": [],
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
You are the {role} in an authorized private cybersecurity lab.

Analyze only the supplied Cowrie SSH honeypot evidence.
Passwords have been removed before analysis.
Do not judge a source based on its IP address alone.

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

    api_usage["calls"] += 1

    input_tokens = 0
    output_tokens = 0
    total_tokens = 0

    if response.usage is not None:
        input_tokens = response.usage.input_tokens or 0
        output_tokens = response.usage.output_tokens or 0
        total_tokens = response.usage.total_tokens or 0

        api_usage["input_tokens"] += input_tokens
        api_usage["output_tokens"] += output_tokens
        api_usage["total_tokens"] += total_tokens

    api_usage["call_details"].append(
        {
            "agent": role,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": total_tokens,
        }
    )

    return clean_json(response.output_text)


def parse_timestamp(value):
    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )


def read_recent_login_events():
    if not LOG_FILE.exists():
        raise FileNotFoundError(
            f"Cowrie log not found: {LOG_FILE}"
        )

    lines = LOG_FILE.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines()[-LOOKBACK_LINES:]

    events = []

    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if event.get("eventid") not in {
            "cowrie.login.failed",
            "cowrie.login.success",
        }:
            continue

        timestamp = event.get("timestamp")
        source_ip = event.get("src_ip")

        if not timestamp or not source_ip:
            continue

        # Intentionally exclude password and raw message fields.
        events.append(
            {
                "timestamp": timestamp,
                "source_ip": source_ip,
                "source_port": event.get("src_port"),
                "destination_ip": event.get("dst_ip"),
                "destination_port": event.get("dst_port"),
                "username": event.get("username", ""),
                "outcome": (
                    "SUCCESS"
                    if event["eventid"]
                    == "cowrie.login.success"
                    else "FAILED"
                ),
                "session": event.get("session", ""),
                "sensor": event.get("sensor", ""),
            }
        )

    return events


def has_failure_then_success(events):
    failure_seen = False

    for event in sorted(
        events,
        key=lambda item: item["timestamp"],
    ):
        if event["outcome"] == "FAILED":
            failure_seen = True
        elif event["outcome"] == "SUCCESS" and failure_seen:
            return True

    return False


analysis_start = time.perf_counter()
all_events = read_recent_login_events()

if not all_events:
    print("No Cowrie login events were found.")
    raise SystemExit(0)

latest_time = max(
    parse_timestamp(event["timestamp"])
    for event in all_events
)
window_start = latest_time - timedelta(
    minutes=ANALYSIS_WINDOW_MINUTES
)

window_events = [
    event
    for event in all_events
    if parse_timestamp(event["timestamp"])
    >= window_start
]

events_by_source = defaultdict(list)

for event in window_events:
    events_by_source[event["source_ip"]].append(event)

selected_source = max(
    events_by_source,
    key=lambda source: (
        len(events_by_source[source]),
        max(
            event["timestamp"]
            for event in events_by_source[source]
        ),
    ),
)

selected_events = events_by_source[selected_source]
outcome_counts = Counter(
    event["outcome"]
    for event in selected_events
)
username_counts = Counter(
    event["username"]
    for event in selected_events
)

summary = {
    "source_ip": selected_source,
    "analysis_window_minutes": ANALYSIS_WINDOW_MINUTES,
    "first_event": min(
        event["timestamp"]
        for event in selected_events
    ),
    "last_event": max(
        event["timestamp"]
        for event in selected_events
    ),
    "total_login_events": len(selected_events),
    "failed_logins": outcome_counts.get("FAILED", 0),
    "successful_logins": outcome_counts.get("SUCCESS", 0),
    "usernames_targeted": dict(username_counts),
    "unique_sessions": len(
        {
            event["session"]
            for event in selected_events
            if event["session"]
        }
    ),
    "failure_then_success": has_failure_then_success(
        selected_events
    ),
}

print("\nCOWRIE BLUE AGENT STARTED")
print(f"Read-only log: {LOG_FILE}")
print(f"Selected source: {selected_source}")
print(f"Login events: {len(selected_events)}")
print(f"Failed logins: {summary['failed_logins']}")
print(f"Successful logins: {summary['successful_logins']}")
print("Captured passwords sent to AI: NO\n")

investigation = call_agent(
    role="Cowrie Detection and Investigation Agent",
    instructions="""
Determine whether the SSH behavior is a likely user mistake,
password guessing, username spraying, continued hostile activity,
or likely account compromise.

Return exactly:
{
  "suspicious": true or false,
  "pattern": "short pattern name",
  "severity": "LOW, MEDIUM, HIGH, or CRITICAL",
  "findings": "concise evidence-based explanation"
}
""",
    evidence={
        "summary": summary,
        "sanitized_events": selected_events,
    },
)

response = call_agent(
    role="Cowrie Risk and Response Agent",
    instructions="""
Choose MONITOR, ALERT, or RECOMMEND_BLOCK.

Policy:
- One isolated failed login normally warrants MONITOR.
- Repeated failures or multiple targeted usernames warrant ALERT.
- Four or more rapid failures may warrant RECOMMEND_BLOCK.
- Failure followed by success may indicate compromise and may
  warrant RECOMMEND_BLOCK.
- This agent recommends action only. It must not claim that a
  firewall or host block was executed.

Return exactly:
{
  "action": "MONITOR, ALERT, or RECOMMEND_BLOCK",
  "target_ip": "source IP or NONE",
  "reason": "concise evidence-based explanation"
}
""",
    evidence={
        "summary": summary,
        "investigation": investigation,
    },
)

analysis_seconds = round(
    time.perf_counter() - analysis_start,
    2,
)

report = {
    "generated_at": datetime.now().astimezone().isoformat(),
    "mode": "read_only_recommendation",
    "passwords_shared_with_ai": False,
    "summary": summary,
    "investigation": investigation,
    "response": response,
    "analysis_seconds": analysis_seconds,
    "api_usage": api_usage,
}

REPORT_DIR.mkdir(parents=True, exist_ok=True)
REPORT_FILE.write_text(
    json.dumps(report, indent=2),
    encoding="utf-8",
)

with HISTORY_FILE.open("a", encoding="utf-8") as history_file:
    history_file.write(
        json.dumps(report, separators=(",", ":"))
        + "\n"
    )

print("COWRIE DETECTION/INVESTIGATION AGENT")
print(f"Pattern: {investigation['pattern']}")
print(f"Suspicious: {investigation['suspicious']}")
print(f"Severity: {investigation['severity']}")
print(f"Findings: {investigation['findings']}\n")

print("COWRIE RISK/RESPONSE AGENT")
print(f"Action: {response['action']}")
print(f"Target: {response['target_ip']}")
print(f"Reason: {response['reason']}\n")

print("COWRIE BLUE ANALYSIS COMPLETE")
print(f"Analysis time: {analysis_seconds} seconds")
print(f"API calls: {api_usage['calls']}")
print(f"Total tokens: {api_usage['total_tokens']}")

for call_detail in api_usage["call_details"]:
    print(
        f"- {call_detail['agent']}: "
        f"{call_detail['input_tokens']} input + "
        f"{call_detail['output_tokens']} output = "
        f"{call_detail['total_tokens']} tokens"
    )

print(f"Report saved to: {REPORT_FILE}")
print(f"Run appended to: {HISTORY_FILE}")
