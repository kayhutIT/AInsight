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

# HTTP session with retry strategy
session = requests.Session()
retry_strategy = Retry(
    total=2,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504]
)
session.mount("https://", HTTPAdapter(max_retries=retry_strategy))

# Call OpenRouter API with retry, timing, and 401 diagnostics

def call_openrouter(prompt: str) -> Optional[str]:
    headers = {
        "Authorization": f"Bearer {OPENROUTER_KEY}",
        "Content-Type": "application/json"
    }
    payload = {"model": MODEL_NAME, "messages": [{"role": "user", "content": prompt}]}
    logger.debug(f"Sending LLM request (first 100 chars): {prompt[:100]}…")
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
            logger.error(f"Auth header sent: {headers.get('Authorization')}")
            logger.error(f"Payload snippet: {json.dumps(payload)[:200]}…")
            sys.exit(1)
        else:
            logger.error(f"LLM API error {r.status_code}: {r.text}")
    except requests.RequestException as e:
        logger.exception(f"Exception during LLM call: {e}")
    return None

# Extract includes from source text
def extract_includes(src: str) -> List[str]:
   return INCLUDE_PATTERN.findall(src)

# Extract function body by matching braces
def extract_body(src: str, start: int) -> str:
   i = start
   while i < len(src) and src[i] != '{':
        i += 1
   if i >= len(src):
       return ''
   brace = 1
   i += 1
   start_body = i
   while i < len(src) and brace:
       if src[i] == '{': brace += 1
       elif src[i] == '}': brace -= 1
       i += 1
   return src[start_body:i-1]

# Read a resource file by relative path
def read_resource(path_str: str, root: pathlib.Path) -> str:
   path = (root / path_str).resolve()
   if path.exists() and path.is_file():
       try:
           return path.read_text(encoding="utf-8", errors="ignore")
       except:
           return ''
   return ''
# Extract functions and resources from a file
def extract_functions_from_file(path: pathlib.Path) -> List[FunctionInfo]:
   try:
       src = path.read_text(encoding="utf-8", errors="ignore")
   except Exception as e:
       logger.warning(f"Cannot read {path}: {e}")
       return []
   includes = extract_includes(src)
   funcs: List[FunctionInfo] = []
   for m in FUNC_PATTERN.finditer(src):
       sig = m.group(0).split('{')[0].strip()
       pre = src[:m.start()].rstrip().splitlines()
       coment: List[str] = []
       for line in reversed(pre):
           s = line.strip()
           if s.startswith('//') or s.startswith('/*'):
               coment.append(s)
           elif s:
               break
       comment = '\n'.join(reversed(coment)).strip()
       body = extract_body(src, m.start())
       resources = FILE_CALL_PATTERN.findall(body)
       funcs.append(FunctionInfo(
           file=str(path), signature=sig,
           includes=includes, comment=comment,
           body=body, resources=resources
       ))
   return funcs

# Recursively scan project directory
def scan_project(root: pathlib.Path) -> List[FunctionInfo]:
    all_funcs: List[FunctionInfo] = []
    for f in root.rglob('*.[ch]'):
        all_funcs.extend(extract_functions_from_file(f))
    return all_funcs

# Generate an executive brief based on all functions
def generate_executive_brief(funcs: List[FunctionInfo]) -> str:
    summary_prompt = (
        "The following functions have been extracted from a C project:\n" +
        "\n".join([f"- {f.signature}" for f in funcs]) +
        "\n\n" +
        "Provide a brief executive summary describing the overall purpose and flow of the codebase based on these functions."
    )
    return call_openrouter(summary_prompt) or ""

# Parse CLI arguments
def parse_args():
    p = argparse.ArgumentParser(description="AInsight: always-running LLM summaries with executive brief")
    p.add_argument('project', nargs='?', help='C project root')
    p.add_argument('-o','--output', default=None, help='Output JSON file')
    p.add_argument('--verbose', action='store_true', help='Enable debug logging')
    return p.parse_args()

# Apply defaults for IDE use
def apply_defaults(args):
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    if not args.project:
        args.project = str(pathlib.Path(DEFAULT_PROJECT))
    if not args.output:
        args.output = DEFAULT_OUTPUT
    return args

# Main execution flow
def run(args):
    root = pathlib.Path(args.project).expanduser().resolve()
    if not root.exists():
        logger.error(f"Project not found: {root}")
        sys.exit(1)
    logger.info(f"Scanning project: {root}")
    funcs = scan_project(root)
    logger.info(f"Found {len(funcs)} functions")

    # Executive brief
    logger.info("Generating executive brief...")
    exec_brief = generate_executive_brief(funcs)

    # Always explain with LLM
    logger.info("Generating detailed LLM summaries for each function...")
    for idx, info in enumerate(funcs, start=1):
        prompt = (
            f"Function: {info.signature}\n"
            f"Comment:\n{info.comment}\n"
            f"Includes: {', '.join(info.includes)}\n"
            f"Implementation snippet:\n{info.body.strip()}\n"
            f"Resources: {', '.join(info.resources)}\n\n"
            f"Describe the purpose and behavior of this function."
        )
        info.llm_summary = call_openrouter(prompt) or ""
        logger.info(f"[{idx}/{len(funcs)}] done")

    # Write JSON output including summaries and exec brief
    out_path = pathlib.Path(args.output)
    out_data = {"executive_brief": exec_brief, "functions": [asdict(f) for f in funcs]}
    out_path.write_text(json.dumps(out_data, indent=2))
    logger.info(f"JSON output written to: {out_path}")

    # Write concise Markdown report
    md = out_path.with_suffix('.md')
    with md.open('w', encoding='utf-8') as fh:
        fh.write(f"# Executive Summary\n\n{exec_brief}\n\n")
        fh.write("---\n\n")
        for info in funcs:
            fh.write(f"## {pathlib.Path(info.file).name} – {info.signature}\n")
            if info.comment:
                fh.write(f"> {info.comment}\n")
            fh.write(f"**Includes:** {', '.join(info.includes)}\n")
            if info.resources:
                fh.write(f"**Resources:** {', '.join(info.resources)}\n")
            fh.write(f"\n**Summary:** {info.llm_summary}\n\n")
    logger.info(f"Markdown report written to: {md}")

if __name__ == '__main__':
    args = parse_args()
    args = apply_defaults(args)
    run(args)
