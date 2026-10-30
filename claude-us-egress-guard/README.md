# Claude US Egress Guard

一个面向 macOS 的、无需 TUN 的 Claude/Chrome 网络出口保护方案，同时提供可安装为 Codex skill 的操作指南。

这套方案解决三个问题：

1. Claude Desktop 及其 Helper 进程只能访问本机 Xray 代理，不能自行直连公网。
2. 普通浏览器和国内应用保持物理网卡直连，不接管系统默认路由。
3. 通过 PAC、进程 GID 和 PF 形成多层 fail-closed 边界，避免代理失效后悄悄回落直连。

> 这不是匿名工具，也不能消除已发送给模型的数据风险。它保护的是网络路径和进程出口，不保护数据库内容、提示词、客户数据或公司机密。

## 架构

```text
Claude Desktop / Code Mode
  -> 专用进程组 GID
  -> PF：只允许 127.0.0.1:17891
  -> 本地 Xray HTTP 代理
  -> 自建美国 VPS
  -> Anthropic

Chrome
  -> 托管 PAC
  -> 国内/局域网直连，其他公网走 127.0.0.1:17891
  -> 自建美国 VPS

飞书、国内网站、普通应用
  -> 物理网卡直连
```

核心约束：

- 不使用 TUN。
- 不要求 Day8、Clash 或 Mihomo 同时运行。
- 默认路由必须是物理网卡，不能是 `utun*`。
- Xray 只监听回环地址。
- Claude 在预检失败时拒绝启动。
- 不把 VLESS UUID、REALITY 私钥、代理密码、SSH 私钥或令牌提交到仓库。

## 目录

```text
claude-us-egress-guard/
├── SKILL.md
├── README.md
├── SECURITY.md
├── .github/workflows/validate.yml
├── agents/openai.yaml
├── references/
│   ├── architecture.md
│   ├── installation.md
│   ├── operations.md
│   └── diagnostics.md
├── scripts/
│   ├── audit_macos.py
│   ├── render_pac.py
│   ├── sanitize_xray_config.py
│   └── check_public_safety.py
├── tests/
│   └── test_scripts.py
└── assets/
    ├── claude_egress_gid_launcher.c
    ├── claude_split.pac
    ├── chrome-policy.plist.example
    ├── com.google.Chrome.plist.example
    ├── client.example.json
    ├── launch_claude_protected.sh
    ├── pf_rules.example.conf
    ├── safe_restart_prepare.py
    ├── seattle-xray.plist.example
    ├── start_guarded_xray.sh.example
    └── xray-server.example.json
```

## 只读检查

先运行审计，不修改系统：

```bash
python3 scripts/audit_macos.py
```

严格检查指定美国出口和 GID：

```bash
python3 scripts/audit_macos.py \
  --expected-exit 203.0.113.10 \
  --expected-gid 62001 \
  --strict
```

审计会检查：

- 默认路由是否为物理接口。
- `utun`、Day8、Clash/Mihomo 是否仍接管网络。
- Xray 代理端口是否监听。
- 经过代理与不经代理的公开出口是否不同。
- Claude Desktop 及其后代进程的 GID。
- 系统 PAC、LaunchAgent/LaunchDaemon 和 PF 配置是否存在。

## 安装为 Codex skill

把仓库克隆到 `$CODEX_HOME/skills`，或在现有 skill 目录中只保留本目录：

```bash
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
git clone <this-repository-url> \
  "${CODEX_HOME:-$HOME/.codex}/skills/claude-us-egress-guard"
```

之后可在 Codex 中显式调用：

```text
Use $claude-us-egress-guard to audit this Mac without changing the network.
```

详细安装与风险边界见：

- [架构与威胁模型](references/architecture.md)
- [从 VPS 到 macOS 的安装](references/installation.md)
- [日常使用与关闭](references/operations.md)
- [故障诊断](references/diagnostics.md)

## 安全发布检查

提交前执行：

```bash
python3 scripts/check_public_safety.py .
python3 -m py_compile scripts/*.py
python3 -m unittest discover -s tests -v
```

示例文件只使用保留域名、文档专用地址和明确占位符。真实配置应保存在用户目录，权限设为 `0600`。

## 已知限制

- PAC 是否生效取决于客户端是否遵循系统代理策略；Chromium 浏览器应配合托管策略。
- PF 进程组隔离依赖启动器正确设置真实和有效 GID；启动后仍需检查所有 Helper。
- 原生 SSH、数据库客户端等非 HTTP 协议不会自动使用 `--proxy-server`。
- 给 Claude 增加 SSH 或数据库工具会扩大数据边界，必须单独设计授权、脱敏、审计和人工确认。
- macOS 升级可能改变 PF、LaunchAgent、隐私权限或 Electron Helper 行为，升级后必须重新验收。

## License

MIT
