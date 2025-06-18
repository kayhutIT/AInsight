#!/usr/bin/env python3
"""
AInsight — main.py (OpenRouter API mode)
"""
import argparse
import json
import pathlib
from dataclasses import dataclass, asdict
from typing import List, Optional
import re
import sys
import requests

# ───── User-configurable defaults ─────────────────────
DEFAULT_PROJECT = pathlib.Path("C:/Users/uzann/Downloads/simple_c_project")
DEFAULT_OUTPUT = "summary.json"
DEFAULT_EXPLAIN = True  # set True to enable LLM explanations by default

# OpenRouter API configuration
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_KEY = "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"  # e.g. sk-or-... token
MODEL_NAME = "deepseek/deepseek-chat-v3-0324:free"  # default model

# Regex for functions and includes
FUNC_PATTERN = re.compile(
    r"""^\s*                 # possible indent
    (?:[a-zA-Z_][\w\s\*\[\]]+?) # return type
    \s+([a-zA-Z_]\w*)        # function name
    \s*\(([^)]*)\)\s*      # args
    \{                       # start of body
    """, re.MULTILINE | re.VERBOSE
)
INCLUDE_PATTERN = re.compile(r'^\s*#include\s+["<]([^">]+)[">]', re.MULTILINE)

@dataclass
class FunctionInfo:
    file: str
    signature: str
    comment: str
    includes: List[str]
    llm_summary: Optional[str] = None

# Extract includes declarations
def extract_includes(path: pathlib.Path) -> List[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    return INCLUDE_PATTERN.findall(text)

# Extract function signatures and preceding comments
def extract_functions_from_file(path: pathlib.Path) -> List[FunctionInfo]:
    try:
        src = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"[!] Cannot read {path}: {e}")
        return []
    includes = extract_includes(path)
    funcs: List[FunctionInfo] = []
    for m in FUNC_PATTERN.finditer(src):
        signature = m.group(0).split('{')[0].strip()
        pre_lines = src[:m.start()].rstrip().splitlines()
        comment_lines: List[str] = []
        for line in reversed(pre_lines):
            s = line.strip()
            if s.startswith('//') or s.startswith('/*'):
                comment_lines.append(s)
            elif not s:
                continue
            else:
                break
        comment = "\n".join(reversed(comment_lines)).strip()
        funcs.append(FunctionInfo(str(path), signature, comment, includes))
    return funcs

# Recursively scan project directory
def scan_project(root: pathlib.Path) -> List[FunctionInfo]:
    all_funcs: List[FunctionInfo] = []
    for f in root.rglob("*.[ch]"):
        all_funcs.extend(extract_functions_from_file(f))
    return all_funcs

# Call OpenRouter API for chat completions
def call_openrouter(prompt: str) -> Optional[str]:
    headers = {
        "Authorization": f"Bearer {OPENROUTER_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": MODEL_NAME,
        "messages": [{"role": "user", "content": prompt}]
    }
    try:
        resp = requests.post(OPENROUTER_URL, headers=headers, data=json.dumps(payload), timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            return data['choices'][0]['message']['content']
        print(f"[!] OpenRouter API error {resp.status_code}: {resp.text}")
    except Exception as e:
        print(f"[!] Exception calling OpenRouter: {e}")
    return None

# Parse CLI arguments
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="AInsight main (OpenRouter API only)")
    p.add_argument('project', nargs='?', help='Path to C project root')
    p.add_argument('-o', '--output', default=None, help='Output JSON file name')
    p.add_argument('--explain', action='store_true', help='Enable LLM explanations')
    return p.parse_args()

# Apply defaults when run from IDE without args
def apply_defaults(args: argparse.Namespace) -> argparse.Namespace:
    if not args.project:
        args.project = str(DEFAULT_PROJECT)
    if not args.output:
        args.output = DEFAULT_OUTPUT
    if DEFAULT_EXPLAIN and not args.explain:
        args.explain = True
    return args

# Main logic
def run(args: argparse.Namespace) -> None:
    root = pathlib.Path(args.project).expanduser().resolve()
    if not root.exists():
        sys.exit(f"Error: project path not found: {root}")
    print(f"Scanning project: {root}")
    infos = scan_project(root)
    print(f"=> {len(infos)} functions found")

    if args.explain:
        print("Running LLM explanations via OpenRouter...")
        for idx, info in enumerate(infos, start=1):
            prompt = (
                f"File: {info.file}\nPrototype: {info.signature}\nIncludes: {info.includes}\nComment:\n{info.comment}\nExplain:")
            info.llm_summary = call_openrouter(prompt)
            print(f"[{idx}/{len(infos)}] done")

    # Write JSON output
    out_path = pathlib.Path(args.output)
    out_path.write_text(json.dumps([asdict(f) for f in infos], indent=2, ensure_ascii=False))
    print(f"JSON output written to: {out_path}")

    # Markdown report if explanations included
    if args.explain:
        md = out_path.with_suffix('.md')
        with md.open('w', encoding='utf-8') as fh:
            for info in infos:
                fh.write(f"### {pathlib.Path(info.file).name} – {info.signature}\n")
                if info.comment:
                    fh.write(f"> {info.comment}\n")
                fh.write(f"**Includes:** {', '.join(info.includes)}\n\n")
                if info.llm_summary:
                    fh.write(f"{info.llm_summary}\n---\n")
        print(f"Markdown report written to: {md}")

if __name__ == '__main__':
    args = parse_args()
    args = apply_defaults(args)
    run(args)
