# python3 extract_private_trackers.py --src definitions --out PrivateTracker.list

import argparse
import os
import re
from collections import defaultdict
from typing import Dict, List, Set, Tuple


def rot13(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr(((o - 65 + 13) % 26) + 65))
        elif 97 <= o <= 122:
            out.append(chr(((o - 97 + 13) % 26) + 97))
        else:
            out.append(ch)
    return "".join(out)


def clean_host(s: str) -> str:
    s = s.strip()
    s = s.replace("\\/", "/")
    s = re.sub(r"^\*+\.", "", s)
    s = re.sub(r"^https?://", "", s, flags=re.I)
    s = re.sub(r"/.*$", "", s)
    s = re.sub(r":\d+$", "", s)
    return s.strip().strip(".").lower()


def looks_like_host(s: str) -> bool:
    if not s or "." not in s:
        return False
    if any(c.isspace() for c in s):
        return False
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", s):
        return False
    return bool(re.search(r"[a-z0-9-]+\.[a-z]{2,}$", s))


def is_private_site(content: str) -> bool:
    return re.search(r"""type\s*:\s*["']private["']""", content, flags=re.I) is not None


def should_force_rot13(raw: str) -> bool:
    """
    判断字符串是否看起来像是被 ROT13 加密过的。
    增加了对常见 TLD 加密形式的检测 (例如 .com -> .pbd)。
    """
    rl = raw.lower()
    # 1. 显式的加密前缀
    if ("uggcf://" in rl) or ("z-grnz" in rl):
        return True

    rot13_suffixes = [".pbd", ".arg", ".bet", ".pu", ".zr"]
    if any(rl.endswith(suf) for suf in rot13_suffixes):
        return True
        
    return False


ROT13_CALL_RE = re.compile(
    r"""rot13\s*\(\s*(?P<q>["'`])(?P<v>(?:\\.|(?!\1).)*?)(?P=q)\s*\)""",
    re.I | re.S,
)

STR_LIT_RE = re.compile(
    r"""(?P<q>["'`])(?P<v>(?:\\.|(?!\1).)*?)(?P=q)""",
    re.S,
)


def extract_array_items(content: str, key: str) -> List[Tuple[str, bool]]:
    m = re.search(rf"{re.escape(key)}\s*:\s*\[([\s\S]*?)\]", content, flags=re.I)
    if not m:
        return []
    block = m.group(1)

    items: List[Tuple[str, bool]] = []

    for mm in ROT13_CALL_RE.finditer(block):
        items.append((mm.group("v"), True))

    block2 = ROT13_CALL_RE.sub(" ", block)
    for mm in STR_LIT_RE.finditer(block2):
        items.append((mm.group("v"), False))

    return items


def choose_host_from_urls(raw: str) -> str:
    a = clean_host(raw)
    b = clean_host(rot13(raw))

    # 优先检查是否强制 ROT13 (包含新增的后缀检查)
    if should_force_rot13(raw):
        return b if looks_like_host(b) else a

    if (not looks_like_host(a)) and looks_like_host(b):
        return b

    return a


# --- 聚合/格式化逻辑 ---

def label_count(domain: str) -> int:
    return domain.count(".") + 1


def build_suffix_map(hosts: Set[str]) -> Dict[str, Set[str]]:
    m: Dict[str, Set[str]] = defaultdict(set)
    for h in hosts:
        labels = h.split(".")
        if len(labels) < 2:
            continue
        for k in range(2, len(labels) + 1):
            suf = ".".join(labels[-k:])
            m[suf].add(h)
    return m


def format_single_host(h: str) -> str:
    if h.startswith("www."):
        return f"+.{h[4:]}"
    else:
        return f"+.{h}"


def process_hosts(hosts: Set[str], threshold: int = 2) -> List[str]:
    remaining = set(h for h in hosts if looks_like_host(h))
    out_lines: Set[str] = set()

    while True:
        suf_map = build_suffix_map(remaining)
        cands = [(suf, covered) for suf, covered in suf_map.items() if len(covered) >= threshold]
        
        if not cands:
            break

        # 排序：优先覆盖多 -> 优先长后缀 -> 字母序
        cands.sort(key=lambda x: (-len(x[1]), -label_count(x[0]), x[0]))
        best_suf, covered_hosts = cands[0]

        out_lines.add(f"+.{best_suf}")
        remaining -= covered_hosts

    for h in remaining:
        formatted = format_single_host(h)
        out_lines.add(formatted)

    return sorted(list(out_lines), key=lambda x: (not x.startswith("+."), x.lstrip("+.")))


def main():
    ap = argparse.ArgumentParser(description="Extract private tracker hosts with aggregation and custom rules.")
    ap.add_argument("--src", required=True, help="Path to extracted definitions folder")
    ap.add_argument("--out", default="PrivateTracker.list", help="Output file (default: PrivateTracker.list)")
    ap.add_argument("--no-comments", action="store_true", help="Do not write '# filename.ts' comment lines")
    ap.add_argument("--threshold", type=int, default=2, help="Merge to '+.<suffix>' when >=threshold hosts share it (default: 2)")
    args = ap.parse_args()

    ts_paths: List[str] = []
    for root, _, files in os.walk(args.src):
        for fn in files:
            if fn.endswith(".ts"):
                ts_paths.append(os.path.join(root, fn))
    ts_paths.sort(key=lambda p: os.path.basename(p).lower())

    lines_out: List[str] = []

    for path in ts_paths:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        if not is_private_site(content):
            continue

        hosts: Set[str] = set()

        # 处理 urls
        for val, is_r in extract_array_items(content, "urls"):
            raw = rot13(val) if is_r else val
            h = choose_host_from_urls(raw)
            if looks_like_host(h):
                hosts.add(h)

        # 处理 formerHosts
        for val, is_r in extract_array_items(content, "formerHosts"):
            raw = rot13(val) if is_r else val
            h = choose_host_from_urls(raw)
            if looks_like_host(h):
                hosts.add(h)

        if not hosts:
            continue

        filename = os.path.basename(path)
        if not args.no_comments:
            lines_out.append(f"# {filename}")

        lines_out.extend(process_hosts(hosts, threshold=args.threshold))
        lines_out.append("")

    while lines_out and lines_out[-1] == "":
        lines_out.pop()

    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines_out) + ("\n" if lines_out else ""))

    print(f"OK. Wrote: {args.out}")


if __name__ == "__main__":
    main()
