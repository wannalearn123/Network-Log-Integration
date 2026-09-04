# LLM-based deep analysis engine.
#
# Calls Llama 3.2 11B Vision Instruct via NVIDIA NIM for contextual
# security analysis when rules/ML flag anomalies.

import os
import json
import re
import sys
import openai


SYSTEM_PROMPT = """You are a network security analyst AI. Analyze the following network log entries and identify security anomalies.

Respond ONLY in this JSON format:
{
  "anomalies": [
    {
      "type": "SCAN | BRUTE_FORCE | FLOOD | EXFILTRATION | UNKNOWN",
      "severity": "LOW | MEDIUM | HIGH | CRITICAL",
      "confidence": 0.0-1.0,
      "description": "Human-readable explanation",
      "affected_ips": ["172.20.0.50"],
      "recommended_action": "Block IP / Monitor / Investigate"
    }
  ],
  "summary": "Brief overall assessment"
}

If no anomalies found, return:
{"anomalies": [], "summary": "Normal traffic pattern"}"""


NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"
NVIDIA_MODEL = "meta/llama-3.2-11b-vision-instruct"
LLM_TIMEOUT = 20.0
LLM_MAX_TOKENS = 1024

_client = None


    # Return a shared OpenAI client (connection reuse).
def get_client():
    global _client
    if _client is None:
        _client = openai.OpenAI(
            base_url=NVIDIA_BASE_URL,
            api_key=os.environ.get("NVIDIA_API_KEY", "") or "unset",
            timeout=LLM_TIMEOUT,
        )
    return _client


    # Format log rows into a readable string for the LLM.
def format_logs_for_llm(rows):
    lines = []
    for row in rows[-30:]:  # last 30 lines to stay within token limits
        ts = row.get("timestamp", "")
        host = row.get("hostname", "")
        event = row.get("event", "N/A")
        line = f"[{ts}] {host} {event}"
        if row.get("src_ip"):
            line += f" src={row['src_ip']}"
        if row.get("dst_ip"):
            line += f" dst={row['dst_ip']}"
        if row.get("dst_port"):
            line += f" port={row['dst_port']}"
        if row.get("proto"):
            line += f" proto={row['proto']}"
        lines.append(line)
    return "\n".join(lines)


    # Remove markdown code fences without crashing on malformed input.
def strip_code_fences(content):
    text = (content or "").strip()
    if not text.startswith("```"):
        return text
    lines = text.split("\n", 1)
    if len(lines) < 2:
        return ""  # bare "```" with no body
    body = lines[1]
    if "```" in body:
        body = body.rsplit("```", 1)[0]
    return body.strip()


    # Return the first {...} JSON block, else the stripped text.
def extract_json_block(text):
    match = re.search(r"\{.*\}", text, re.DOTALL)
    return match.group(0) if match else text.strip()


    # Parse model output, tolerating fences and trailing prose.
def parse_llm_response(content):
    text = extract_json_block(strip_code_fences(content))
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Repair attempt: truncated output missing closing brackets
    for suffix in ("}]}", "]}", "}", "]"):
        try:
            return json.loads(text + suffix)
        except json.JSONDecodeError:
            continue
    raise json.JSONDecodeError("unparseable LLM output", text, 0)


    # Call Llama 3.2 11B via NVIDIA NIM API.
    #
    # Args:
    # rows: list of log row dicts
    # context: dict with rule_hits, ml_score, ml_severity
    #
    # Returns:
    # parsed JSON dict or None on error
def call_llm(rows, context):
    if not os.environ.get("NVIDIA_API_KEY", ""):
        print("[LLM] No NVIDIA_API_KEY found — skipping", file=sys.stderr)
        return None

    user_msg = f"""Anomaly context from local detection:
{json.dumps(context, indent=2)}

Log entries from the same window:
{format_logs_for_llm(rows)}"""

    try:
        response = get_client().chat.completions.create(
            model=NVIDIA_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            temperature=0.3,
            max_tokens=LLM_MAX_TOKENS,
            timeout=LLM_TIMEOUT,
        )
        content = response.choices[0].message.content
        return parse_llm_response(content)
    except json.JSONDecodeError as e:
        print(f"[LLM] Failed to parse JSON response: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[LLM] API error: {e}", file=sys.stderr)
        return None
