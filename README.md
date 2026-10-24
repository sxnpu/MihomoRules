# MihomoRules

type: http  
behavior: domain  
format: text

## 规则文件

| 文件 | 说明 |
| --- | --- |
| `ruleset/PrivateTracker.list` | 私有 PT 站点域名，由 `tools/build_private_tracker_rules.py` 从 [PT-depiler](https://github.com/pt-plugins/PT-depiler) 的站点定义自动生成，**不要手改** |
| `ruleset/*.list`（其余） | 手工维护的规则 |

## 订阅方式

```yaml
rule-providers:
  private-tracker:
    type: http
    behavior: domain
    format: text
    url: "https://raw.githubusercontent.com/sxnpu/MihomoRules/main/ruleset/PrivateTracker.list"
    path: ./ruleset/PrivateTracker.list
    interval: 86400
```

## 自动更新

`.github/workflows/update-private-tracker.yml`：

- **定时**：每周一 **00:00 UTC**（`cron: "0 0 * * 1"`）。GitHub Actions 的 cron 本身按 UTC 解析，
  所以这里就是格林威治时间周一零点，不做任何时区换算。
- **手动**：仓库 Actions 页面 → `Update PrivateTracker` → `Run workflow`，可填 `ref`（`master` / `release` / 具体 tag）。
- **改脚本也会跑**：动到 `tools/build_private_tracker_rules.py` 或本工作流并推到 `main` 时触发一次，方便验证。
- 每次只下载一个约 5 MB 的上游源码包（一次请求），不逐个抓 raw 文件。
- 生成结果与仓库现有文件一致时**不提交**；有差异才 commit + push。
- 生成少于 100 条规则会判为解析失败，任务直接失败且不写文件。

## 生成规则

`tools/build_private_tracker_rules.py` 的处理方式：

1. **注释用站点 id**：每个 `.ts` 顶层的 `id:`（如 `mteam`、`13city`）作为该段第一行注释。
2. **只取当前域名**：只读顶层 `urls:`，`legacyUrls:` 等旧域名一律忽略。
3. **解密**：支持明文 `https://` 和 ROT13 的 `uggcf://`（也兼容 `rot13("...")` 包裹的写法）。
4. **规范化 host**：去 `www.` 前缀、端口、路径，转小写。
5. **求注册域（eTLD+1）**：把子域提升到注册域，例如
   `zp.m-team.io` → `m-team.io`、`tracker.hqmusic.info` → `hqmusic.info`。
   两个例外保留完整 host：
   - `bt.` / `pt.` 前缀：这类通常是共享域下的 PT 子域，如 `pt.sjtu.edu.cn`。
   - 教育/政府/科研机构后缀（`edu.cn`、`ac.uk`、`edu.au`…）：整域提升会把整个机构送进代理，
     如 `hudbt.hust.edu.cn` 保持原样。
6. **去冗余**：已被更宽规则覆盖的条目会被丢掉（有 `+.agsvpt.cn` 就不需要 `+.pt.agsvpt.cn`）。
7. 输出 `+.domain`，`+.` 是 mihomo 的 domain 通配写法，等价于"域名本身 + 所有子域"。

输出格式：

```text
# mteam
+.m-team.cc
+.m-team.io

# hqmusic
+.hqmusic.info

# sjtu
+.pt.sjtu.edu.cn
```

### 注册域是怎么算的

默认拉取 [Public Suffix List](https://publicsuffix.org/list/public_suffix_list.dat)（约 330 KB、10856 条规则），
缓存到 `~/.cache/mihomo-rules/public_suffix_list.dat`（30 天有效），所以每周实际只下载一次。

效果：

- `zp.m-team.io` → `m-team.io`
- `x.us.kg` → `x.us.kg`（`us.kg` 是公共后缀，不会误伤整个免费域名服务）
- `sjtu.edu.cn` → `sjtu.edu.cn`（`edu.cn` 是公共后缀）
- `hudbt.hust.edu.cn` → 保留完整（教育机构域豁免，避免整个学校走代理）

下载失败时退回内置后缀表（83 条常见多段后缀 + 两条模式规则），不会产生 `+.edu.cn` / `+.us.kg`
这类灾难规则，但长尾后缀可能不准——**内置表是 2026-10 的手写快照，不会自动更新**。

- 完全离线：`--no-psl`
- 用本地 PSL 文件：`--psl path\to\public_suffix_list.dat`
- 内置表的更新渠道：PSL 官方仓库 <https://github.com/publicsuffix/list>（约每月更新几次）

## 本地手动跑一次

```powershell
# 自动下载上游最新 master 并生成（只收 private 站）
python tools\build_private_tracker_rules.py --out ruleset\PrivateTracker.list

# 连 public 站一起收
python tools\build_private_tracker_rules.py --out ruleset\PrivateTracker.list --include-public

# 固定某个版本
python tools\build_private_tracker_rules.py --ref v0.0.6.1998

# 用已经解压好的本地 definitions 目录（不联网取上游）
python tools\build_private_tracker_rules.py --src _upstream\definitions
```

脚本用 Python 的 `urllib`，在 Windows 上会自动读取系统代理设置（也就是 mihomo 的 `127.0.0.1:7890`），
本地开着代理就能直接跑；CI 里是 GitHub 机房直连，不依赖代理。
