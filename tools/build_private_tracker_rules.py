#!/usr/bin/env python3
"""从 PT-depiler 的站点定义生成 mihomo 域名规则集（PrivateTracker.list）。

处理链：
    下载上游源码包（一次请求）
      -> 逐个读 src/packages/site/definitions/*.ts
      -> 取该站当前在用的 urls（不碰 legacyUrls 等旧域名）
      -> 解密（明文 / ROT13 / rot13() 包裹）
      -> 提取 host（去 www.、端口、路径）
      -> 求注册域（eTLD+1），bt./pt. 前缀和教育/政府域保留完整
      -> 输出 `+.domain` 形式的 mihomo 规则

注册域怎么算：
    默认拉 Public Suffix List（publicsuffix.org，约 330 KB，缓存 30 天）求 eTLD+1：
    zp.m-team.io -> m-team.io、x.us.kg -> x.us.kg、sjtu.edu.cn -> sjtu.edu.cn。
    下载失败时退回内置后缀表（83 条常见多段后缀 + 两条模式规则），不会产生
    +.edu.cn / +.us.kg 这类灾难规则，但长尾后缀可能不准。

为什么不能简单取"后两段"：
    那样会把 sjtu.edu.cn 变成 edu.cn、把 x.us.kg 变成 us.kg，
    一条规则就把整个教育网/免费域名服务代理掉。

用法：
    python tools/build_private_tracker_rules.py                        # 自动下载 master，只收私有站
    python tools/build_private_tracker_rules.py --include-public      # 连 public 站一起收
    python tools/build_private_tracker_rules.py --ref release          # 跟随最新正式 release
    python tools/build_private_tracker_rules.py --ref v0.0.6.1998      # 固定版本
    python tools/build_private_tracker_rules.py --src ./definitions    # 用本地目录，不联网
    python tools/build_private_tracker_rules.py --psl ./psl.dat        # 用本地 PSL 文件
    python tools/build_private_tracker_rules.py --no-psl               # 完全离线，用内置表

输出示例：
    # mteam
    +.m-team.cc
    +.m-team.io
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

UPSTREAM_REPO = "pt-plugins/PT-depiler"
DEFINITIONS_REL = "src/packages/site/definitions"
USER_AGENT = "MihomoRules-pt-rules-builder/3.0"

PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
PSL_MAX_AGE = 30 * 86400  # 缓存 30 天

# bt./pt. 这类前缀通常是共享域下的 PT 子域（如 pt.sjtu.edu.cn），保留完整
KEEP_SUBDOMAIN_LABELS = {"bt", "pt"}
# 教育/政府/科研机构后缀：整域提升会误伤整个机构，保留完整 host
INSTITUTIONAL_LABELS = {"edu", "ac", "gov", "mil", "sch", "k12"}
# 国别二级域的前缀（com.cn / co.uk / ne.jp…），没有 PSL 时用来识别公共后缀
COUNTRY_SECOND_LEVEL = {"com", "co", "net", "org", "ne", "or", "go", "id", "idv", "nom", "web"}

# ROT13：把字母沿字母表平移 13 位，同一函数既编码也解码
_ROT13_TABLE = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)
_URL_SCHEME = re.compile(r"^https?://", re.I)
_INLINE_ROT13 = re.compile(r"^(?:rot13|ROT13)\s*\(\s*(['\"])(.*?)\1\s*\)$", re.S)

# 没有 PSL 可用时的兜底：常见多段公共后缀（含用户提到的 us.kg）
FALLBACK_SUFFIXES = {
    "edu.cn", "gov.cn", "com.cn", "net.cn", "org.cn", "ac.cn",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.kr", "or.kr", "ne.kr", "go.kr", "ac.kr",
    "com.tw", "org.tw", "net.tw", "edu.tw", "gov.tw", "idv.tw",
    "com.hk", "org.hk", "net.hk", "edu.hk", "gov.hk",
    "com.sg", "org.sg", "net.sg", "edu.sg", "gov.sg",
    "com.br", "net.br", "org.br", "edu.br", "gov.br",
    "co.in", "net.in", "org.in", "edu.in", "gov.in",
    "com.mx", "com.ar", "com.tr", "com.ua", "co.za", "co.nz", "co.il",
    "pp.ua", "us.kg", "dpdns.org",
    "github.io", "gitlab.io", "vercel.app", "netlify.app", "pages.dev",
    "workers.dev", "herokuapp.com", "blogspot.com", "azurewebsites.net",
    "cloudfront.net", "firebaseapp.com", "web.app", "appspot.com",
    "duckdns.org", "no-ip.org", "ddns.net", "ngrok.io", "ngrok-free.app",
}


def log(msg: str) -> None:
    """日志一律走 stderr，stdout 只留给结果路径。"""
    print(msg, file=sys.stderr, flush=True)


def rot13(text: str) -> str:
    return text.translate(_ROT13_TABLE)


# --------------------------------------------------------------------------- #
# 一、TS 文本解析：只认"顶层缩进 2 空格"的字段，避免命中嵌套对象里的同名字段
# --------------------------------------------------------------------------- #

def _top_field_pattern(key: str) -> re.Pattern[str]:
    return re.compile(rf"(?m)^[ ]{{2}}(?![ ]){re.escape(key)}\s*:")


def read_string_field(source: str, key: str) -> str | None:
    m = re.search(
        rf"(?m)^[ ]{{2}}(?![ ]){re.escape(key)}\s*:\s*(['\"])(.*?)\1\s*,?\s*$",
        source,
    )
    return m.group(2) if m else None


def read_array_block(source: str, key: str) -> str | None:
    """读出 `  urls: [ ... ]` 的方括号内部内容，支持单行和多行。

    手写括号配对（跳过字符串字面量），因为数组里可能嵌对象、字符串里可能有括号。
    """
    m = _top_field_pattern(key).search(source)
    if not m:
        return None
    start = source.find("[", m.end())
    if start < 0:
        return None

    depth = 0
    i = start
    while i < len(source):
        ch = source[i]
        if ch in "\"'`":
            quote = ch
            i += 1
            while i < len(source) and source[i] != quote:
                if source[i] == "\\":
                    i += 1
                i += 1
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return source[start + 1 : i]
        i += 1
    return None


def read_string_items(block: str | None) -> list[str]:
    if not block:
        return []
    items: list[str] = []
    for m in re.finditer(r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'', block):
        raw = m.group(1) if m.group(1) is not None else m.group(2)
        items.append(raw.replace('\\"', '"').replace("\\'", "'"))
    return items


# --------------------------------------------------------------------------- #
# 二、解密与 host 提取
# --------------------------------------------------------------------------- #

def decrypt_url(raw: str) -> str | None:
    """把一条 urls 元素解成 http(s) URL；解不出来返回 None。

    上游域名只有两种写法：明文 `https://...` 和 ROT13 `uggcf://...`，
    也兼容 rot13("...") 包裹的形式。
    """
    text = raw.strip()
    inline = _INLINE_ROT13.match(text)
    if inline:
        text = inline.group(2)
    for candidate in (text, rot13(text)):
        if _URL_SCHEME.match(candidate):
            return candidate
    return None


def host_from_url(url: str) -> str | None:
    """取出 host：小写、无端口、无路径、去 www. 前缀。"""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    host = (parts.hostname or "").strip(".").lower()
    if not host:
        return None
    if host.startswith("www."):
        host = host[4:]
    if "." not in host or not re.fullmatch(r"[a-z0-9.-]+", host):
        return None
    return host


# --------------------------------------------------------------------------- #
# 三、Public Suffix List：求注册域（eTLD+1）
# --------------------------------------------------------------------------- #

def default_psl_cache() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "mihomo-rules", "public_suffix_list.dat")


def parse_psl(path: str) -> set[str]:
    rules: set[str] = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            rule = line.split()[0].lower()
            rules.add(rule)
            if not rule.isascii():
                try:
                    rules.add(rule.encode("idna").decode())
                except UnicodeError:
                    pass
    return rules


def load_psl(explicit: str | None, cache: str | None) -> tuple[set[str] | None, str]:
    """返回 (规则集合, 来源说明)。拿不到时返回 (None, 原因)，由调用方降级。"""
    if explicit:
        try:
            return parse_psl(explicit), f"本地文件 {explicit}"
        except OSError as exc:
            log(f"warning: 读不了 --psl 文件（{exc}），改用其它来源")

    cache_path = cache or default_psl_cache()
    if os.path.exists(cache_path):
        age = time.time() - os.path.getmtime(cache_path)
        if age < PSL_MAX_AGE:
            try:
                return parse_psl(cache_path), "本地缓存"
            except OSError:
                pass

    try:
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        _download(PSL_URL, cache_path, None)
        return parse_psl(cache_path), "在线下载"
    except Exception as exc:  # noqa: BLE001 - 网络问题不该让整次生成失败
        log(f"warning: 下载 PSL 失败（{exc}）")
        if os.path.exists(cache_path):
            try:
                return parse_psl(cache_path), "过期缓存"
            except OSError:
                pass
        return None, "不可用"


def psl_suffix(host: str, rules: set[str]) -> str:
    """按 PSL 算法求 host 的公共后缀（处理通配 * 和例外 !）。"""
    labels = host.split(".")

    # 例外规则优先：!www.ck 表示 www.ck 是注册域，不是公共后缀
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if "!" + candidate in rules:
            return ".".join(labels[i + 1 :])

    best: str | None = None
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in rules and (best is None or len(candidate) > len(best)):
            best = candidate
        if i + 1 < len(labels):
            wildcard = "*." + ".".join(labels[i + 1 :])
            if wildcard in rules and (best is None or len(candidate) > len(best)):
                best = candidate
    return best or labels[-1]


def registrable_domain(host: str, rules: set[str]) -> str | None:
    suffix = psl_suffix(host, rules)
    if suffix == host:
        return None  # host 本身就是公共后缀
    depth = suffix.count(".") + 1
    labels = host.split(".")
    if len(labels) <= depth:
        return None
    return ".".join(labels[-(depth + 1) :])


def canonical_host(host: str, rules: set[str] | None) -> tuple[str, str]:
    """决定这个 host 最终写成什么域名，返回 (域名, 原因)。

    1. bt./pt. 前缀：通常是共享域下的 PT 子域，保留完整
    2. 教育/政府/科研机构域：保留完整，避免把整个机构走代理
    3. 其余：提升到注册域（eTLD+1），例如 zp.m-team.io -> m-team.io
    """
    labels = host.split(".")

    if labels[0] in KEEP_SUBDOMAIN_LABELS:
        return host, "keep"

    if rules:
        suffix = psl_suffix(host, rules)
        if suffix.split(".")[0] in INSTITUTIONAL_LABELS:
            return host, "institution"
        return registrable_domain(host, rules) or host, "lift"

    # 没有 PSL：退回"后两段"，再用内置表和模式规则躲开 edu.xx / com.xx / us.kg 这类
    if len(labels) <= 2:
        return host, "fallback"
    last2 = ".".join(labels[-2:])
    first, _, cc = last2.partition(".")

    # 机构域：edu./ac./gov./mil./sch. 后面跟任意国别码，一律保留完整，
    # 避免把整个机构送进代理（对没收录在表里的 edu.my / ac.th 也生效）
    if first in INSTITUTIONAL_LABELS:
        return host, "institution"

    # 国别二级域：com.xx / co.xx / net.xx … 视为公共后缀，注册域往上取一段
    if last2 in FALLBACK_SUFFIXES or (first in COUNTRY_SECOND_LEVEL and len(cc) == 2 and cc.isalpha()):
        return ".".join(labels[-3:]), "fallback"

    return last2, "fallback"


def drop_covered(domains: list[str]) -> list[str]:
    """去掉被更宽规则覆盖的条目：已有 example.com 时，a.example.com 是多余的。"""
    kept: list[str] = []
    for domain in sorted(set(domains), key=lambda d: (d.count("."), d)):
        if any(domain == k or domain.endswith("." + k) for k in kept):
            continue
        kept.append(domain)
    return sorted(kept)


# --------------------------------------------------------------------------- #
# 四、上游下载
# --------------------------------------------------------------------------- #

def _headers(token: str | None) -> dict[str, str]:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _get_json(url: str, token: str | None):
    import json

    req = urllib.request.Request(url, headers=_headers(token))
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _download(url: str, dst: str, token: str | None, attempts: int = 3) -> None:
    last: object = None
    for attempt in range(1, attempts + 1):
        try:
            req = urllib.request.Request(url, headers=_headers(token))
            with urllib.request.urlopen(req, timeout=180) as resp, open(dst, "wb") as fh:
                shutil.copyfileobj(resp, fh, 1 << 20)
            return
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403, 404):  # 重试没有意义
                raise
            last = exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = exc
        if attempt < attempts:
            log(f"下载失败（第 {attempt}/{attempts} 次）：{last}，5 秒后重试…")
            time.sleep(5)
    raise RuntimeError(f"下载失败：{url}（{last}）")


def latest_release_tag(repo: str, token: str | None) -> str:
    releases = _get_json(f"https://api.github.com/repos/{repo}/releases?per_page=30", token)
    for rel in releases:
        if rel.get("draft") or rel.get("prerelease"):
            continue
        return rel["tag_name"]
    raise RuntimeError("上游没有找到正式 release")


def download_definitions(repo: str, ref: str, workdir: str, token: str | None) -> str:
    os.makedirs(workdir, exist_ok=True)
    archive = os.path.join(workdir, "upstream.zip")
    quoted = urllib.parse.quote(ref, safe="")

    url = None
    for kind in ("heads", "tags"):
        candidate = f"https://codeload.github.com/{repo}/zip/refs/{kind}/{quoted}"
        try:
            _download(candidate, archive, token)
        except Exception as exc:  # noqa: BLE001
            log(f"跳过 {candidate}：{exc}")
            continue
        url = candidate
        break
    if url is None:
        raise RuntimeError(f"无法下载 {repo}@{ref}（分支和 tag 都试过了）")
    log(f"已下载 {url}（{os.path.getsize(archive)} 字节）")

    marker = f"/{DEFINITIONS_REL}/"
    out_dir = os.path.join(workdir, "definitions")
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir)

    count = 0
    with zipfile.ZipFile(archive) as zf:
        for name in zf.namelist():
            if marker not in name or not name.endswith(".ts"):
                continue
            rel = name.split(marker, 1)[1]
            target = os.path.join(out_dir, *rel.split("/"))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(name) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
            count += 1

    os.remove(archive)
    if count == 0:
        raise RuntimeError(f"压缩包里没有 {DEFINITIONS_REL} 下的 .ts 文件，上游结构可能变了")
    log(f"解出 {count} 个 .ts 定义文件")
    return out_dir


# --------------------------------------------------------------------------- #
# 五、生成规则
# --------------------------------------------------------------------------- #

def parse_site(path: str) -> tuple[str, str, list[str]]:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        source = fh.read()

    site_id = read_string_field(source, "id") or os.path.splitext(os.path.basename(path))[0]
    site_type = read_string_field(source, "type") or "private"

    hosts: list[str] = []
    for item in read_string_items(read_array_block(source, "urls")):
        url = decrypt_url(item)
        if not url:
            continue
        host = host_from_url(url)
        if host:
            hosts.append(host)

    return site_id, site_type, list(dict.fromkeys(hosts))


def build_ruleset(
    definitions_dir: str,
    include_public: bool,
    with_comments: bool,
    psl_rules: set[str] | None,
) -> tuple[list[str], dict[str, int]]:
    files = sorted(
        (os.path.join(definitions_dir, f) for f in os.listdir(definitions_dir) if f.endswith(".ts")),
        key=lambda p: os.path.basename(p).lower(),
    )

    lines: list[str] = []
    seen: set[str] = set()
    stats = {
        "files": 0,
        "sites": 0,
        "sites_skipped": 0,
        "hosts": 0,
        "rules": 0,
        "duplicates": 0,
        "lift": 0,
        "keep": 0,
        "institution": 0,
        "fallback": 0,
    }

    for path in files:
        site_id, site_type, hosts = parse_site(path)
        stats["files"] += 1
        if not hosts:
            continue
        if site_type != "private" and not include_public:
            stats["sites_skipped"] += 1
            continue

        stats["sites"] += 1
        stats["hosts"] += len(hosts)

        domains: list[str] = []
        for host in hosts:
            domain, why = canonical_host(host, psl_rules)
            stats[why] += 1
            domains.append(domain)

        rules: list[str] = []
        for domain in drop_covered(domains):
            rule = f"+.{domain}"
            if rule in seen:
                stats["duplicates"] += 1
                continue
            seen.add(rule)
            rules.append(rule)

        if not rules:
            continue
        if with_comments:
            lines.append(f"# {site_id}")
        lines.extend(rules)
        lines.append("")

    while lines and lines[-1] == "":
        lines.pop()

    stats["rules"] = len(seen)
    return lines, stats


def main() -> int:
    ap = argparse.ArgumentParser(description="从 PT-depiler 生成 mihomo 域名规则集")
    ap.add_argument("--out", default="ruleset/PrivateTracker.list", help="输出文件")
    ap.add_argument("--src", default=None, help="本地 definitions 目录（给了就不联网取上游）")
    ap.add_argument("--ref", default="master", help="上游分支或 tag；填 release 表示最新正式 release")
    ap.add_argument("--repo", default=UPSTREAM_REPO, help="上游仓库")
    ap.add_argument("--include-public", action="store_true", help="连 public 站一起收录（默认只收 private）")
    ap.add_argument("--no-comments", action="store_true", help="不输出 # 站点名 注释")
    ap.add_argument("--min-domains", type=int, default=100, help="少于这个条数视为解析失败并退出")
    ap.add_argument("--workdir", default=None, help="下载/解压用的临时目录")
    ap.add_argument("--psl", default=None, help="本地 Public Suffix List 文件（最精确）")
    ap.add_argument("--psl-cache", default=None, help="PSL 缓存路径（默认 ~/.cache/mihomo-rules/）")
    ap.add_argument("--no-psl", action="store_true", help="不联网，只用内置后缀表（会过期，不推荐）")
    args = ap.parse_args()

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")

    if args.src:
        definitions_dir = args.src
        if not os.path.isdir(definitions_dir):
            log(f"error: --src 目录不存在：{definitions_dir}")
            return 2
    else:
        ref = args.ref
        if ref.lower() == "release":
            ref = latest_release_tag(args.repo, token)
            log(f"最新 release：{ref}")
        workdir = args.workdir or os.path.join(
            os.environ.get("RUNNER_TEMP") or tempfile.gettempdir(), "pt-depiler"
        )
        try:
            definitions_dir = download_definitions(args.repo, ref, workdir, token)
        except Exception as exc:  # noqa: BLE001
            log(f"error: 取上游定义失败：{exc}")
            return 1

    if args.psl:
        psl_rules, psl_source = load_psl(args.psl, None)
    elif args.no_psl:
        psl_rules, psl_source = None, "内置表（--no-psl，可能过期）"
    else:
        psl_rules, psl_source = load_psl(None, args.psl_cache)
    log(f"PSL：{psl_source}" + (f"（{len(psl_rules)} 条规则）" if psl_rules else ""))

    lines, stats = build_ruleset(
        definitions_dir,
        include_public=args.include_public,
        with_comments=not args.no_comments,
        psl_rules=psl_rules,
    )

    if stats["rules"] < args.min_domains:
        log(
            f"error: 只生成 {stats['rules']} 条规则（阈值 {args.min_domains}），"
            f"上游目录结构可能变了，已中止，未写文件"
        )
        return 1

    out_dir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(out_dir, exist_ok=True)
    # newline="\n"：Windows 上也不要写出 CRLF，保证本地和 CI 字节一致
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + ("\n" if lines else ""))

    log(
        f"完成：{stats['files']} 个定义文件，收录 {stats['sites']} 个站"
        f"（跳过 public {stats['sites_skipped']} 个），"
        f"{stats['hosts']} 个 host -> {stats['rules']} 条规则"
        f"（去重 {stats['duplicates']} 条；"
        f"提升 {stats['lift']}、保留 bt/pt {stats['keep']}、机构域 {stats['institution']}）"
    )
    print(os.path.abspath(args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
