#!/usr/bin/env python3
"""
AInsight — main.py (OpenRouter API, always active summaries)
"""
import argparse
import json
import pathlib
import os
import re
import sys
from dataclasses import dataclass, asdict
from typing import List, Optional
import requests

# ───── Configuration ─────────────────────────────────
DEFAULT_PROJECT = pathlib.Path("C:/Users/uzann/Downloads/simple_c_project")
DEFAULT_OUTPUT = "summary.json"

# OpenRouter API settings
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_KEY = os.getenv("OPENROUTER_API_KEY")
if not OPENROUTER_KEY:
    key_file = pathlib.Path("openrouter_key.txt")
    if key_file.exists():
        OPENROUTER_KEY = key_file.read_text(encoding="utf-8").strip()
if not OPENROUTER_KEY:
    sys.exit("Error: OPENROUTER_API_KEY not set and openrouter_key.txt missing")

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
    headers: List[str]
    resources: List[str]
    llm_summary: Optional[str] = None

# Extract includes from source text
def extract_includes(src: str) -> List[str]:
    return INCLUDE_PATTERN.findall(src)

# Extract function body by matching braces
def extract_body(src: str, start: int) -> str:
    i = start
    while i < len(src) and src[i] != '{': i += 1
    if i >= len(src): return ''
    brace = 1
    i += 1
    start_body = i
    while i < len(src) and brace:
        if src[i] == '{': brace += 1
        elif src[i] == '}': brace -= 1
        i += 1
    return src[start_body:i-1]

# Find and read header content within project
def find_header_content(header_name: str, root: pathlib.Path) -> str:
    for path in root.rglob(header_name):
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
    return ''

# Read a resource file by relative path
def read_resource(path_str: str, root: pathlib.Path) -> str:
    path = (root / path_str).resolve()
    if path.exists() and path.is_file():
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ''
    return ''

# Extract functions, includes, headers, and resource calls from a file
def extract_functions_from_file(path: pathlib.Path) -> List[FunctionInfo]:
    try:
        src = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"[!] Cannot read {path}: {e}")
        return []
    includes = extract_includes(src)
    funcs: List[FunctionInfo] = []
    for m in FUNC_PATTERN.finditer(src):
        sig = m.group(0).split('{')[0].strip()
        # extract preceding comment
        pre_lines = src[:m.start()].rstrip().splitlines()
        comments: List[str] = []
        for line in reversed(pre_lines):
            s = line.strip()
            if s.startswith('//') or s.startswith('/*'):
                comments.append(s)
            elif s:
                break
        comment = '\n'.join(reversed(comments)).strip()
        body = extract_body(src, m.start())
        # gather header names (content implicit)
        headers = [hdr for hdr in includes if find_header_content(hdr, DEFAULT_PROJECT)]
        # detect resource file calls
        resource_paths = FILE_CALL_PATTERN.findall(body)
        funcs.append(FunctionInfo(
            file=str(path),
            signature=sig,
            includes=includes,
            comment=comment,
            body=body,
            headers=headers,
            resources=resource_paths
        ))
    return funcs

# Recursively scan project directory
def scan_project(root: pathlib.Path) -> List[FunctionInfo]:
    funcs: List[FunctionInfo] = []
    for f in root.rglob('*.[ch]'):
        funcs.extend(extract_functions_from_file(f))
    return funcs

# Call OpenRouter API
def call_openrouter(prompt: str) -> Optional[str]:
    headers = {"Authorization": f"Bearer {OPENROUTER_KEY}", "Content-Type": "application/json"}
    payload = {"model": MODEL_NAME, "messages": [{"role":"user","content":prompt}]}
    try:
        resp = requests.post(OPENROUTER_URL, headers=headers, json=payload, timeout=30)
        if resp.status_code == 200:
            return resp.json()['choices'][0]['message']['content']
        print(f"[!] API error {resp.status_code}: {resp.text}")
    except Exception as e:
        print(f"[!] Exception calling API: {e}")
    return None

# Parse CLI arguments
def parse_args():
    p = argparse.ArgumentParser(description="AInsight: always-running LLM summaries")
    p.add_argument('project', nargs='?', help='C project root')
    p.add_argument('-o','--output', default=None, help='Output JSON file')
    return p.parse_args()

# Apply defaults for IDE use
def apply_defaults(args):
    if not args.project:
        args.project = str(DEFAULT_PROJECT)
    if not args.output:
        args.output = DEFAULT_OUTPUT
    return args

# Main execution flow
def run(args):
    root = pathlib.Path(args.project).expanduser().resolve()
    if not root.exists():
        sys.exit(f"Project not found: {root}")
    print(f"Scanning project: {root}")
    infos = scan_project(root)
    print(f"Found {len(infos)} functions")

    # Always explain with LLM
    print("Generating LLM summaries for all functions...")
    for idx, info in enumerate(infos, start=1):
        # assemble prompt with full context
        hdr_texts = []
        for hdr in info.headers:
            content = find_header_content(hdr, root)
            if content:
                hdr_texts.append(f"Header {hdr}:\n{content}")
        res_texts = []
        for res in info.resources:
            content = read_resource(res, root)
            if content:
                res_texts.append(f"Resource {res}:\n{content}")
        prompt_parts = [
            f"File: {info.file}",
            f"Prototype: {info.signature}",
            f"Comment:\n{info.comment}",
            f"Implementation:\n{info.body}"
        ]
        prompt_parts += hdr_texts + res_texts
        prompt_parts.append("Describe the purpose and behavior of this function based on full code context.")
        prompt = "\n\n".join(prompt_parts)
        summary = call_openrouter(prompt)
        info.llm_summary = summary
        print(f"[{idx}/{len(infos)}] done")

    # Write JSON output including summaries
    out_path = pathlib.Path(args.output)
    out_path.write_text(json.dumps([asdict(f) for f in infos], indent=2))
    print(f"JSON output written to: {out_path}")

    # Write Markdown report
    md = out_path.with_suffix('.md')
    with md.open('w', encoding='utf-8') as fh:
        for info in infos:
            fh.write(f"### {pathlib.Path(info.file).name} – {info.signature}\n")
            if info.comment:
                fh.write(f"> {info.comment}\n")
            fh.write(f"**Includes:** {', '.join(info.includes)}\n\n")
            for hdr in info.headers:
                fh.write(f"**Header {hdr}:**\n```\n{find_header_content(hdr, root).strip()}\n```\n")
            for res in info.resources:
                fh.write(f"**Resource {res}:**\n```\n{read_resource(res, root).strip()}\n```\n")
            fh.write(f"**Implementation:**\n```c\n{info.body.strip()}\n```\n")
            if info.llm_summary:
                fh.write(f"{info.llm_summary}\n---\n")
    print(f"Markdown report written to: {md}")

if __name__ == '__main__':
    args = parse_args()
    args = apply_defaults(args)
    run(args)
