import base64
import json
import re
from dataclasses import dataclass

PROMPT_SIGNATURES: list[tuple[str, str, int]] = [
    (
        "instruction_override",
        r"(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)",
        90,
    ),
    (
        "safety_bypass",
        r"(ignore|bypass|override)\s+(all\s+)?(safety|security|ethical|guardrail)\s+(guidelines?|filters?|protocols?|rules?)",
        95,
    ),
    (
        "role_delimiter_spoof",
        r"(<\|im_start\|>|<\|system\|>|\[INST\]|###\s*SYSTEM\s*:|you\s+are\s+now\s+(dan|unrestricted|developer\s+mode))",
        85,
    ),
    (
        "system_prompt_exfiltration",
        r"(repeat|print|reveal|output)\s+(the\s+)?(text|instructions?|system\s+prompt)\s+(above|verbatim|before)",
        80,
    ),
    (
        "indirect_tool_hijack",
        r"(note\s+to\s+assistant|system\s+alert)\s*:\s*.*(execute|call|send|upload|curl)",
        90,
    ),
]

DANGEROUS_TOOL_PATTERNS: list[tuple[str, str, int]] = [
    ("path_traversal", r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|~/.ssh|\.aws/credentials)", 95),
    ("destructive_shell", r"\b(rm\s+-rf|mkfs|dd\s+if=|chmod\s+777|shutdown|reboot)\b", 100),
    ("remote_code_exec", r"(curl|wget)\s+https?://.*\|\s*(sh|bash|zsh|python)", 100),
    ("reverse_shell", r"\b(nc\s+-e|/dev/tcp/|bash\s+-i)\b", 100),
    ("untrusted_exfiltration_sink", r"(webhook\.site|pastebin\.com|ngrok\.io|requestbin)", 85),
]

ALLOWED_TOOLS = {"read_workspace_file", "search_docs", "run_safe_sql", "send_internal_alert"}
BLOCK_THRESHOLD = 70


@dataclass
class InspectionResult:
    decision: str
    risk_score: int
    matched_rules: list[str]


def _decode_base64_segments(text: str) -> str:
    decoded_chunks: list[str] = []
    for candidate in re.findall(r"[A-Za-z0-9+/=]{20,}", text):
        try:
            raw = base64.b64decode(candidate, validate=True).decode("utf-8", errors="ignore")
            if len(raw.strip()) >= 8 and raw.isprintable():
                decoded_chunks.append(raw)
        except Exception:
            continue
    return " ".join(decoded_chunks)


def inspect_prompt(prompt: str) -> InspectionResult:
    matched: list[str] = []
    score = 0

    decoded_hidden = _decode_base64_segments(prompt)
    scan_corpus = f"{prompt}\n{decoded_hidden}".strip()

    if decoded_hidden:
        for rule_name, pattern, weight in PROMPT_SIGNATURES:
            if re.search(pattern, decoded_hidden, re.IGNORECASE):
                matched.append(f"base64_obfuscated:{rule_name}")
                score = max(score, min(100, weight + 10))

    for rule_name, pattern, weight in PROMPT_SIGNATURES:
        if re.search(pattern, scan_corpus, re.IGNORECASE) and rule_name not in matched:
            matched.append(rule_name)
            score = max(score, weight)

    decision = "BLOCK" if score >= BLOCK_THRESHOLD else "ALLOW"
    return InspectionResult(decision=decision, risk_score=score, matched_rules=matched)


def inspect_tool_call(tool_name: str, arguments: dict) -> InspectionResult:
    matched: list[str] = []
    score = 0

    if tool_name not in ALLOWED_TOOLS:
        matched.append(f"unregistered_tool:{tool_name}")
        score = max(score, 85)

    serialized_args = json.dumps(arguments)
    for rule_name, pattern, weight in DANGEROUS_TOOL_PATTERNS:
        if re.search(pattern, serialized_args, re.IGNORECASE):
            matched.append(rule_name)
            score = max(score, weight)

    prompt_check = inspect_prompt(serialized_args)
    if prompt_check.matched_rules:
        matched.extend([f"arg_{r}" for r in prompt_check.matched_rules])
        score = max(score, prompt_check.risk_score)

    decision = "BLOCK" if score >= BLOCK_THRESHOLD else "ALLOW"
    return InspectionResult(decision=decision, risk_score=score, matched_rules=matched)
