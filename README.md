# AI Red vs. Blue Cybersecurity Lab

An automated cybersecurity lab that simulates interaction between offensive and defensive agents. The Red Agent generates realistic authentication activity, while the Blue Agent monitors events, detects suspicious behavior, and responds according to predefined security thresholds.

## Project Objective

The purpose of this project was to build a controlled environment for practicing:

- Red and Blue Team concepts
- Authentication-log analysis
- Brute-force detection
- Automated alerting and containment
- Python security automation
- Agent-based cybersecurity workflows

## How It Works

1. The Red Agent performs simulated login attempts against the local target service.
2. The target records successful and failed authentication events.
3. The Blue Agent analyzes the activity for suspicious patterns.
4. Repeated failures trigger alerts and escalation.
5. The Blue Agent can block the simulated client after the containment threshold is reached.

## Detection Logic

The Blue Agent evaluates several patterns:

- **Initial assessment:** Triggered after 2 failed login attempts
- **Escalated alert:** Triggered after 4 failed attempts
- **Possible compromise:** Triggered when failed attempts are followed by a successful login
- **Containment:** Blocks the simulated client when the configured threshold is reached

## Test Scenarios

### Benign Activity

A single login attempt used to confirm that ordinary activity does not generate unnecessary alerts.

### Brute-Force Activity

Multiple failed login attempts used to test detection, escalation, and automated blocking.

### Compromise Simulation

A sequence of failed attempts followed by a successful login, representing a potentially compromised account.

## Project Structure

```text
ai_red_blue_cyber_lab/
├── agents/                 # Red and Blue Agent logic
├── reports/                # Generated security reports and results
├── target/                 # Local target service
├── cowrie_coordinator.py   # Coordinates Cowrie-based lab activity
├── livelab.py              # Runs the live lab workflow
├── requirements.txt        # Python dependencies
├── .env.example            # Example environment configuration
└── README.md               # Project documentation
