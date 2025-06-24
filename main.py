#!/usr/bin/env python3
"""
AInsight — main.py with enhanced auth diagnostics for 401 errors
"""
import argparse
import json
import pathlib
import os
import re
import sys
import logging
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dataclasses import dataclass, asdict
from typing import List, Optional

# ───── Configuration ─────────────────────────────────
DEFAULT_PROJECT = r"C:\Users\uzann\Downloads\Helicopter-Simulation-master\Helicopter-Simulation-master"
DEFAULT_OUTPUT = "summary.json"

# Setup logger
logger = logging.getLogger("AInsight")
handler = logging.StreamHandler()
formatter = logging.Formatter("[%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# OpenRouter API settings
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_KEY = os.getenv("OPENROUTER_API_KEY")
if OPENROUTER_KEY:
    masked = f"{OPENROUTER_KEY[:4]}…{OPENROUTER_KEY[-4:]}"
    logger.debug(f"Loaded API key from env: {masked}")
else:
    key_file = pathlib.Path("openrouter_key.txt")
    if key_file.exists():
        OPENROUTER_KEY = key_file.read_text(encoding="utf-8", errors="ignore").strip()
        masked = f"{OPENROUTER_KEY[:4]}…{OPENROUTER_KEY[-4:]}"
        logger.debug(f"Loaded API key from file: {masked}")
if not OPENROUTER_KEY:
    logger.error("OPENROUTER_API_KEY not set and openrouter_key.txt missing. Exiting.")
    sys.exit(1)

MODEL_NAME = "deepseek/deepseek-chat-v3-0324:free"

# Regex patterns
FUNC_PATTERN = re.compile(
    r"^\s*(?:[a-zA-Z_][\w\s\*\[\]]+?)\s+([a-zA-Z_]\w*)\s*\(([^)]*)\)\s*\{",
    re.MULTILINE
)
INCLUDE_PATTERN = re.compile(r'^\s*#include\s+["<]([^">]+)[">]', re.MULTILINE)
FILE_CALL_PATTERN = re.compile(r'print_message\s*\(\s*"([^"]+)"')

@dataclass
class FunctionInfo:
    file: str
    signature: str
    includes: List[str]
    comment: str
    body: str
    resources: List[str]
    llm_summary: Optional[str] = None

# Call OpenRouter API with retry, timing, and 401 diagnostics
session = requests.Session()
retry_strategy = Retry(
    total=2,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504]
)
session.mount("https://", HTTPAdapter(max_retries=retry_strategy))

def call_openrouter(prompt: str) -> Optional[str]:
    headers = {
        "Authorization": f"Bearer {OPENROUTER_KEY}",
        "Content-Type": "application/json"
    }
    payload = {"model": MODEL_NAME, "messages": [{"role": "user", "content": prompt}]}
    logger.debug(f"Sending LLM request: {prompt[:100]}…")
    t0 = time.monotonic()
    try:
        r = session.post(OPENROUTER_URL, headers=headers, json=payload, timeout=30)
        latency = time.monotonic() - t0
        logger.info(f"LLM call status={r.status_code} latency={latency:.2f}s")
        if r.status_code == 200:
            content = r.json().get('choices', [{}])[0].get('message', {}).get('content', '')
            return content
        if r.status_code == 401:
            logger.error("401 Unauthorized: no auth credentials found.")
            logger.error(f"Auth header sent: {headers.get('Authorization')} ")
            logger.error(f"Payload snippet: {json.dumps(payload)[:200]}…")
            sys.exit(1)
        else:
            logger.error(f"LLM API error {r.status_code}: {r.text}")
    except requests.RequestException as e:
        logger.exception(f"Exception during LLM call: {e}")
    return None

# (Remaining code for scanning, summarizing, and reporting goes here unchanged)
