#!/usr/bin/env python3
"""
AInsight — main.py with enhanced auth diagnostics and full entry point
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
# DEFAULT_PROJECT = r"C:\Users\uzann\Downloads\Helicopter-Simulation-master\Helicopter-Simulation-master"
# DEFAULT_PROJECT = r"C:\Users\uzann\Downloads\fswebcam-master\fswebcam-master"
DEFAULT_PROJECT = r"C:\Users\uzann\Downloads\dsvpn-master\dsvpn-master"
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
    start = time.monotonic()
    try:
        response = session.post(OPENROUTER_URL, headers=headers, json=payload, timeout=30)
        latency = time.monotonic() - start
        logger.info(f"LLM call status={response.status_code} latency={latency:.2f}s")
        if response.status_code == 200:
            return response.json().get('choices', [{}])[0].get('message', {}).get('content', '')
        if response.status_code == 401:
            logger.error("401 Unauthorized: no auth credentials found.")
            logger.error(f"Auth header sent: {headers.get('Authorization')}")
            logger.error(f"Payload snippet: {json.dumps(payload)[:200]}…")
            sys.exit(1)
        logger.error(f"LLM API error {response.status_code}: {response.text}")
    except requests.RequestException as err:
        logger.exception(f"Exception during LLM call: {err}")
    return None

# Extract includes from source text
def extract_includes(src: str) -> List[str]:
    return INCLUDE_PATTERN.findall(src)

# Extract function body by matching braces
def extract_body(src: str, start: int) -> str:
    index = start
    while index < len(src) and src[index] != '{':
        index += 1
    if index >= len(src):
        return ''
    brace = 1
    index += 1
    begin = index
    while index < len(src) and brace:
        if src[index] == '{': brace += 1
        elif src[index] == '}': brace -= 1
        index += 1
    return src[begin:index-1]

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
        source = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        logger.warning(f"Cannot read {path}: {e}")
        return []
    includes = extract_includes(source)
    functions: List[FunctionInfo] = []
    for match in FUNC_PATTERN.finditer(source):
        signature = match.group(0).split('{')[0].strip()
        prefix = source[:match.start()].rstrip().splitlines()
        comments: List[str] = []
        for line in reversed(prefix):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                comments.append(stripped)
            elif stripped:
                break
        comment = '\n'.join(reversed(comments)).strip()
        body = extract_body(source, match.start())
        resources = FILE_CALL_PATTERN.findall(body)
        functions.append(FunctionInfo(
            file=str(path), signature=signature,
            includes=includes, comment=comment,
            body=body, resources=resources
        ))
    return functions

# Recursively scan project directory
def scan_project(root: pathlib.Path) -> List[FunctionInfo]:
    all_functions: List[FunctionInfo] = []
    for file in root.rglob('*.[ch]'):
        all_functions.extend(extract_functions_from_file(file))
    return all_functions

# Generate an executive brief
def generate_executive_brief(funcs: List[FunctionInfo]) -> str:
   prompt = (
       "The following functions have been extracted from a C project:\n" +
       "\n".join(f"- {f.signature}" for f in funcs) +
       "\n\nProvide a brief executive summary describing the overall purpose and flow of the codebase."
   )
   return call_openrouter(prompt) or ""

# Parse CLI arguments
def parse_args():
    parser = argparse.ArgumentParser(description="AInsight: LLM summaries for C codebases")
    parser.add_argument('project', nargs='?', help='Path to C project root')
    parser.add_argument('-o', '--output', default=None, help='Output JSON file path')
    parser.add_argument('--verbose', action='store_true', help='Enable debug logging')
    return parser.parse_args()

# Apply defaults and configure logging
def apply_defaults(args):
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    if not args.project:
        args.project = DEFAULT_PROJECT
    if not args.output:
        args.output = DEFAULT_OUTPUT
    return args

# Main execution flow
def run(args):
    project_dir = pathlib.Path(args.project).expanduser().resolve()
    if not project_dir.exists():
        logger.error(f"Project not found: {project_dir}")
        sys.exit(1)
    logger.info(f"Scanning project: {project_dir}")
    funcs = scan_project(project_dir)
    logger.info(f"Found {len(funcs)} functions")

    logger.info("Generating executive brief...")
    exec_summary = generate_executive_brief(funcs)

    logger.info("Generating detailed summaries for each function...")
    for idx, func in enumerate(funcs, start=1):
        func_prompt = (
            f"Function: {func.signature}\n"
            f"Comment:\n{func.comment}\n"
            f"Includes: {', '.join(func.includes)}\n"
            f"Implementation:\n{func.body.strip()}\n"
            f"Resources: {', '.join(func.resources)}\n\n"
            f"Describe the purpose and behavior of this function."
        )
        func.llm_summary = call_openrouter(func_prompt) or ""
        logger.info(f"[{idx}/{len(funcs)}] Summarized {func.signature}")

    out_json = pathlib.Path(args.output)
    data = {"executive_brief": exec_summary, "functions": [asdict(f) for f in funcs]}
    out_json.write_text(json.dumps(data, indent=2))
    logger.info(f"Written JSON to {out_json}")

    md_report = out_json.with_suffix('.md')
    with md_report.open('w', encoding='utf-8') as report:
        report.write(f"# Executive Summary\n\n{exec_summary}\n\n")
        report.write("---\n\n")
        for f in funcs:
            report.write(f"## {pathlib.Path(f.file).name} – {f.signature}\n")
            if f.comment:
                report.write(f"> {f.comment}\n")
            report.write(f"**Includes:** {', '.join(f.includes)}\n")
            if f.resources:
                report.write(f"**Resources:** {', '.join(f.resources)}\n")
            report.write(f"\n**Summary:** {f.llm_summary}\n\n")
    logger.info(f"Written Markdown to {md_report}")

# Entry point
if __name__ == '__main__':
    arguments = parse_args()
    arguments = apply_defaults(arguments)
    run(arguments)
