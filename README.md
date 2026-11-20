# SentinelProxy

**Real-Time LLM Tool-Call Firewall & Prompt Injection Sandbox**

SentinelProxy is a sub-5ms security middleware layer that sits between autonomous AI agents and local system tools. It inspects incoming prompts for direct/obfuscated jailbreaks and validates outgoing tool-call arguments against path traversal, command injection, and unauthorized data exfiltration.

## Architecture

~~~mermaid
flowchart LR
    A[User / External Doc] -->|Raw Prompt| B[SentinelProxy Ingress]
    B -->|Regex + Base64 Scanner| C{Risk >= 70?}
    C -->|Yes: 403 BLOCK| D[(SQLite WAL Audit DB)]
    C -->|No: 200 ALLOW| E[LLM Agent Runtime]
    E -->|Tool Call JSON| F[SentinelProxy Tool Sandbox]
    F -->|Allowlist + Path/Shell Guard| G{Safe Args?}
    G -->|No: 403 BLOCK| D
    G -->|Yes: Execute| H[Local Tool / API]
    D --> I[Rich Live CLI Dashboard]
~~~

## Quickstart

~~~bash
git clone https://github.com/itsmerbk/sentinel-proxy.git
cd sentinel-proxy
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 1. Start the Firewall API (Terminal 1)
uvicorn sentinel.app:app --reload --port 8080

# 2. Launch the Live Telemetry Dashboard (Terminal 2)
python -m sentinel.cli_dashboard

# 3. Run the Red-Team Adversarial Benchmark (Terminal 3)
python -m red_team_benchmarks.run_benchmarks
~~~
