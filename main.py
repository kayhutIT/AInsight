#!/usr/bin/env python3
"""
AInsight — main.py (with dual API support for LLM and embeddings)
"""
import argparse
import json
import pathlib
from dataclasses import dataclass, asdict
from typing import List, Optional
import re
import subprocess
import sys
import requests

# ───── User-configurable defaults (for IDE runs) ─────
DEFAULT_PROJECT = pathlib.Path("C:/Users/uzann/Downloads/simple_c_project")
DEFAULT_OUTPUT = "summary.json"
DEFAULT_MODEL = "ollama"       # options: 'ollama', 'custom'
DEFAULT_EXPLAIN = False         # set True to enable LLM explanations by default
# ───── API configuration ────────────────────────────
# 1. Free Internet Service (Ollama CLI)
OLLAMA_CLI_CMD = ["ollama", "run"]

# 2. Dedicated API endpoints (fill these)
CUSTOM_API_URL = "https://your-custom-llm.example.com/v1/chat/completions"
CUSTOM_API_KEY = "YOUR_CUSTOM_API_KEY"
CUSTOM_EMBED_URL = "https://your-embed-service.example.com/v1/embeddings"
CUSTOM_EMBED_KEY = "YOUR_EMBED_API_KEY"
# ─────────────────────────────────────────────────────

@dataclass
class FunctionInfo:
    file: str
    signature: str
    comment: str
    includes: List[str]
    llm_summary: Optional[str] = None

# Regex patterns for functions and includes
FUNC_PATTERN = re.compile(
    r"""^\s*                 # possible indent
    (?:[a-zA-Z_][\w\s\*\[\]]+?)   # return type
    \s+([a-zA-Z_]\w*)        # function name
    \s*\(([^)]*)\)\s*      # args
    \{                       # start of body
    """, re.MULTILINE | re.VERBOSE
)
INCLUDE_PATTERN = re.compile(r'^\s*#include\s+["<]([^">]+)[">]', re.MULTILINE)


def extract_includes(path: pathlib.Path) -> List[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    return INCLUDE_PATTERN.findall(text)


def extract_functions_from_file(path: pathlib.Path) -> List[FunctionInfo]:
    try:
        src = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"[!] Cannot read {path}: {e}")
        return []
    includes = extract_includes(path)
    results: List[FunctionInfo] = []
    for m in FUNC_PATTERN.finditer(src):
        signature = m.group(0).split('{')[0].strip()
        before_lines = src[:m.start()].rstrip().splitlines()
        comment_lines: List[str] = []
        for line in reversed(before_lines):
            s = line.strip()
            if s.startswith('//') or s.startswith('/*'):
                comment_lines.append(s)
            elif s == '':
                continue
            else:
                break
        comment = "\n".join(reversed(comment_lines)).strip()
        results.append(FunctionInfo(str(path), signature, comment, includes))
    return results


def scan_project(root: pathlib.Path) -> List[FunctionInfo]:
    all_funcs: List[FunctionInfo] = []
    for file in root.rglob("*.[ch]"):
        all_funcs.extend(extract_functions_from_file(file))
    return all_funcs


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="AInsight main")
    p.add_argument('project', nargs='?', help='Path to the C project root')
    p.add_argument('-o', '--output', default=None, help='Output JSON file name')
    p.add_argument('-m', '--model', default=None, choices=['ollama','custom'], help='LLM backend')
    p.add_argument('--explain', action='store_true', help='Query LLM for explanations')
    return p.parse_args()


def apply_defaults(args: argparse.Namespace) -> argparse.Namespace:
    if not args.project:
        args.project = str(DEFAULT_PROJECT)
    if not args.output:
        args.output = DEFAULT_OUTPUT
    if not args.model:
        args.model = DEFAULT_MODEL
    if DEFAULT_EXPLAIN and not args.explain:
        args.explain = True
    return args


def call_ollama(prompt: str, model: str) -> str:
    cmd = OLLAMA_CLI_CMD + [model]
    try:
        res = subprocess.run(cmd, input=prompt.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return res.stdout.decode().strip()
    except Exception as e:
        return f"Ollama error: {e}"


def call_custom_llm(prompt: str) -> str:
    headers = {"Authorization": f"Bearer {CUSTOM_API_KEY}", "Content-Type": "application/json"}
    body = {"model": "custom-model", "messages": [{"role":"user","content":prompt}]}
    r = requests.post(CUSTOM_API_URL, headers=headers, json=body)
    if r.status_code == 200:
        data = r.json()
        return data.get('choices', [{}])[0].get('message', {}).get('content','')
    return f"Custom LLM error: {r.status_code} {r.text}"


def run(args: argparse.Namespace) -> None:
    root = pathlib.Path(args.project).expanduser().resolve()
    if not root.exists():
        sys.exit(f"Error: project path not found: {root}")
    print(f"Scanning project: {root}")
    infos = scan_project(root)
    print(f"Found {len(infos)} functions")

    out_path = pathlib.Path(args.output)
    out_path.write_text(json.dumps([asdict(i) for i in infos], indent=2, ensure_ascii=False))
    print(f"Summary written to JSON: {out_path}")

    if args.explain:
        print(f"Querying LLM using '{args.model}' backend...")
        for idx, info in enumerate(infos, start=1):
            prompt = (
                f"File: {info.file}\n"
                f"Prototype: {info.signature}\n"
                f"Includes: {info.includes}\n"
                f"Comment:\n{info.comment}\n"
                f"Explain:"
            )
            if args.model == 'ollama':
                info.llm_summary = call_ollama(prompt, DEFAULT_MODEL)
            else:
                info.llm_summary = call_custom_llm(prompt)
            print(f"[{idx}/{len(infos)}] done")

        md_path = out_path.with_suffix('.md')
        with md_path.open('w', encoding='utf-8') as fh:
            for info in infos:
                fh.write(f"### {pathlib.Path(info.file).name} – {info.signature}\n")
                if info.comment:
                    fh.write(f"> {info.comment}\n")
                fh.write(f"**Includes:** {', '.join(info.includes)}\n\n")
                fh.write(f"{info.llm_summary}\n---\n")
        print(f"Report written to Markdown: {md_path}")

if __name__ == '__main__':
    args = parse_args()
    args = apply_defaults(args)
    run(args)
