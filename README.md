# 🛡️ ClawCheck

> **OpenClaw Vulnerability Scanner** — Detect the ClawJacked vulnerability (CVE-2026-CLAW)

[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/badge/pypi-1.0.1-green.svg)](https://pypi.org/project/clawcheck/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## 📋 产品定位

**ClawCheck** 是一个命令行安全工具，用于检测 OpenClaw 安装中的 **ClawJacked 漏洞**（CVE-2026-CLAW）。

该漏洞由 Oasis Security 于 2026 年 2 月 26 日披露，允许任何网站通过 WebSocket 利用程序静默劫持 OpenClaw 代理。

**核心特点：**

| 特性 | 说明 |
|------|------|
| 🔍 **自动发现** | 自动检测本地 OpenClaw 安装 |
| 🎯 **版本检测** | 对比已知漏洞版本范围 |
�� **深度探测** | WebSocket 安全指标探测 |
| 🔒 **隐私优先** | 完全离线能力，无外部数据传输 |
| 🤖 **CI/CD 集成** | 支持 JSON/SARIF 输出格式 |
| 🛠️ **自动修复** | 一键升级到安全版本 |

**目标用户：** 安全研究人员、DevOps 工程师、系统管理员、OpenClaw 用户

---

## ⚠️ 关于 ClawJacked 漏洞

### 漏洞概览

| 属性 | 值 |
|------|------|
| **CVE 编号** | CVE-2026-CLAW |
| **披露日期** | 2026年2月26日 |
| **严重程度** | HIGH |
| **影响版本** | OpenClaw < 2026.2.25 |
| **修复版本** | OpenClaw >= 2026.2.25 |
| **披露来源** | [Oasis Security](https://www.oasis.security/blog/openclaw-vulnerability) |

### 攻击链

```mermaid
sequenceDiagram
    participant Victim as 👤 受害者
    participant Website as 🌐 恶意网站
    participant Browser as 🌍 浏览器
    participant OpenClaw as 🤖 OpenClaw
    participant Attacker as 👾 攻击者

    Note over Victim,Attacker: 用户访问恶意网站
    Victim->>Website: 访问 URL
    Website->>Browser: 注入恶意 JavaScript

    Note over Browser,OpenClaw: 步骤 1: WebSocket Origin 绕过
    Browser->>OpenClaw: 连接到 localhost:18789
    Note right of OpenClaw: 无 CORS 限制!
    OpenClaw-->>Browser: 连接已接受

    Note over Browser,OpenClaw: 步骤 2: 无速率限制
    loop 暴力尝试 (数百次/秒)
        Browser->>OpenClaw: 认证尝试
        OpenClaw-->>Browser: 拒绝
    end

    Note over Browser,OpenClaw: 步骤 3: 自动信任注册
    Browser->>OpenClaw: 成功认证
    OpenClaw-->>Browser: 设备自动批准!

    Note over OpenClaw,Attacker: 步骤 4: 完全控制
    Attacker->>OpenClaw: 发送消息、读取日志
    OpenClaw-->>Attacker: 数据外泄

    Note over Victim,Attacker: 工作站已被入侵!
```

### 漏洞组件

```mermaid
graph TB
    subgraph ClawJacked 漏洞
        A[WebSocket Origin 绕过]
        B[无 Localhost 速率限制]
        C[自动信任注册]
    end

    subgraph 攻击后果
        D[完全工作站入侵]
        E[数据外泄]
        F[隐私侵犯]
    end

    A --> D
    B --> D
    C --> D
    D --> E
    D --> F

    style A fill:#ff6b6b
    style B fill:#ff6b6b
    style C fill:#ff6b6b
    style D fill:#c92a2a
    style E fill:#c92a2a
    style F fill:#c92a2a
```

**影响：** 可从浏览器标签页发起的工作站完全入侵

**修复：** 更新到 OpenClaw 2026.2.25 或更高版本

---

## 🚀 快速启动

### 环境要求

| 工具 | 版本要求 |
|------|----------|
| Python | 3.9+ |
| OpenClaw | 任意版本（用于检测） |

### 安装

#### 方式一：pip 安装（推荐）

```bash
pip install clawcheck
clawcheck
```

#### 方式二：pipx 隔离安装

```bash
pipx install clawcheck
```

#### 方式三：从源码安装

```bash
git clone https://github.com/yourusername/clawcheck.git
cd clawcheck
pip install -e .
```

### 基本使用

```bash
# 执行扫描
clawcheck

# 查看详细输出
clawcheck -v

# 查看超详细输出（包含 WebSocket 探测）
clawcheck -vv
```

---

## 📖 功能用例

### 用例一：基本漏洞扫描

执行本地 OpenClaw 安装的安全扫描。

```mermaid
flowchart TD
    A[clawcheck] --> B{发现 OpenClaw?}
    B -->|否| C[退出码: 3<br/>NOT_FOUND]
    B -->|是| D{版本存在漏洞?}
    D -->|是| E[VULNERABLE<br/>退出码: 1]
    D -->|否| F[SECURE<br/>退出码: 0]
    E --> G[显示修复建议]

    style E fill:#ff6b6b
    style F fill:#51cf66
    style C fill:#ffd93d
```

**输出示例：**

```
🛡️  ClawCheck - OpenClaw Vulnerability Scanner

📍 发现 OpenClaw 实例
   版本: 2026.2.12
   路径: /home/user/.openclaw/openclaw.json
   网关: 运行中 (127.0.0.1:18789)

⚠️  检测到漏洞
   CVE-2026-CLAW (ClawJacked)
   严重程度: HIGH

   漏洞指标:
   ✗ 版本检查: FAIL (2026.2.12 < 2026.2.25)
   ✗ Origin 验证: FAIL
   ✗ 速率限制: FAIL

🔧 修复建议:
   openclaw upgrade
```

---

### 用例二：JSON/SARIF 输出（CI/CD 集成）

生成机器可读的扫描结果，用于 CI/CD 流水线集成。

**JSON 输出：**

```bash
clawcheck --json
clawcheck --json --output results.json
```

**SARIF 输出（用于 GitHub Actions、GitLab CI 等）：**

```bash
clawcheck --sarif --output sarif.json
```

**GitHub Actions 集成示例：**

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  clawcheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: pip install clawcheck
      - run: clawcheck --sarif --output sarif.json
      - uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: sarif.json
```

---

### 用例三：自动修复

一键升级 OpenClaw 到安全版本。

```mermaid
flowchart TD
    A[clawcheck fix] --> B{需要确认?}
    B -->|是| C[显示将要执行的操作]
    B -->|否 --force| D[跳过确认]
    C --> E{用户确认?}
    E -->|是| D
    E -->|否| F[取消操作]

    D --> G[备份当前配置]
    G --> H[执行 openclaw upgrade]
    H --> I[验证升级结果]

    I --> J{升级成功?}
    J -->|是| K[✅ 修复完成]
    J -->|否| L[❌ 修复失败]

    style K fill:#51cf66
    style L fill:#ff6b6b
```

**使用方式：**

```bash
# 预演模式 - 查看将要执行的操作
clawcheck fix --dry-run

# 执行修复（需要确认）
clawcheck fix

# 强制修复（无需确认）
clawcheck fix --force
```

---

### 用例四：持续监控

持续监控 OpenClaw 安全状态，适合长期运行的服务器。

```mermaid
flowchart LR
    A[启动监控] --> B[间隔扫描]
    B --> C{发现漏洞?}
    C -->|是| D[记录日志]
    C -->|否| B
    D --> E[发送通知]
    E --> B

    style D fill:#ff6b6b
    style E fill:#ffd93d
```

**使用方式：**

```bash
# 持续监控（默认 60 秒间隔）
clawcheck monitor

# 自定义间隔（30 秒）
clawcheck monitor --interval 30

# 带日志文件
clawcheck monitor --log-file clawcheck.log
```

---

### 用例五：高级扫描选项

针对特定场景的扫描配置。

```mermaid
flowchart TD
    A[开始扫描] --> B[配置选项]

    B --> C[超时设置]
    B --> D[配置路径]
    B --> E[详细程度]

    C --> F[执行扫描]
    D --> F
    E --> F

    F --> G{扫描结果}
    G --> H[JSON 输出]
    G --> I[SARIF 输出]
    G --> J[终端输出]

    style F fill:#e3f2fd
    style H fill:#bbdefb
    style I fill:#bbdefb
    style J fill:#bbdefb
```

**使用示例：**

```bash
# 自定义超时时间
clawcheck --timeout 60

# 自定义配置路径
clawcheck --config-path /custom/path/openclaw.json

# 组合多个选项
clawcheck -vv --json --output scan.json --timeout 60
```

---

## 📊 退出码与脚本集成

### 退出码说明

```mermaid
flowchart TD
    Start[clawcheck scan] --> Check{OpenClaw Found?}
    Check -->|No| NotFound[退出码: 3<br/>NOT_FOUND]
    Check -->|Yes| Scan{扫描成功?}
    Scan -->|Error| Error[退出码: 2<br/>ERROR]
    Scan -->|Success| Vulnerable{发现漏洞?}
    Vulnerable -->|Yes| VulnExit[退出码: 1<br/>VULNERABLE]
    Vulnerable -->|No| Secure[退出码: 0<br/>SECURE]

    NotFound --> End[结束]
    Error --> End
    VulnExit --> End
    Secure --> End

    style NotFound fill:#ffd93d
    style Error fill:#ff6b6b
    style VulnExit fill:#ff6b6b
    style Secure fill:#51cf66
```

| 退出码 | 含义 | 使用场景 |
|--------|------|----------|
| 0 | SECURE | 未发现漏洞 |
| 1 | VULNERABLE | 检测到漏洞 |
| 2 | ERROR | 扫描错误（权限、超时等） |
| 3 | NOT_FOUND | 未安装或未运行 OpenClaw |

**脚本集成示例：**

```bash
#!/bin/bash
# 安全检查脚本

clawcheck --json --output scan.json
EXIT_CODE=$?

case $EXIT_CODE in
  0)
    echo "✓ 安全 - 无需操作"
    # 正常继续 CI 流程
    ;;
  1)
    echo "✗ 存在漏洞 - 请执行: clawcheck fix"
    # 阻止部署
    exit 1
    ;;
  2)
    echo "⚠ 扫描错误 - 请检查日志"
    exit 2
    ;;
  3)
    echo "○ 未安装 OpenClaw - 跳过检查"
    # 可能是开发环境
    ;;
esac

exit $EXIT_CODE
```

---

## 🏗️ 项目架构

### 系统架构

```mermaid
flowchart TD
    subgraph CLI 层
        A[用户命令]
        B[clawcheck CLI]
    end

    subgraph 发现层
        C[配置扫描器]
        D[CLI 运行器]
        E[端口探测器]
    end

    subgraph 扫描层
        F[漏洞数据库]
        G[版本检查器]
        H[WebSocket 探测器]
    end

    subgraph 输出层
        I[终端格式化]
        J[JSON 格式化]
        K[SARIF 格式化]
    end

    subgraph 修复层
        L[备份管理器]
        M[更新执行器]
        N[验证器]
    end

    A --> B
    B --> C
    B --> D
    B --> E
    C --> G
    D --> G
    G --> F
    F --> H
    H --> I
    H --> J
    H --> K

    B --> L
    L --> M
    M --> N

    style A fill:#e3f2fd
    style B fill:#bbdefb
    style I fill:#90caf9
    style J fill:#90caf9
    style K fill:#90caf9
```

### 项目结构

```mermaid
graph TD
    Root[clawcheck/]

    Root --> Src[src/]
    Root --> Tests[tests/]
    Root --> Docs[docs/]
    Root --> Config[pyproject.toml,<br/>README.md,<br/>LICENSE]

    Src --> Package[clawcheck/]
    Package --> Init[__init__.py]
    Package --> CLI[cli.py<br/>Click CLI 接口]
    Package --> Discovery[discovery.py<br/>OpenClaw 发现]
    Package --> Models[models.py<br/>数据模型]
    Package --> Output[output.py<br/>输出格式化]
    Package --> Probe[probe.py<br/>WebSocket 探测]
    Package --> VulnDB[vuln_db.py<br/>漏洞数据库]

    Tests --> Unit[unit/<br/>单元测试]
    Tests --> Integration[integration/<br/>集成测试]

    Docs --> Plans[plans/<br/>实现计划]

    style Root fill:#e3f2fd
    style Src fill:#bbdefb
    style Tests fill:#bbdefb
    style Docs fill:#bbdefb
    style Config fill:#bbdefb
    style Package fill:#90caf9
```

### 模块说明

| 模块 | 功能 |
|------|------|
| `cli.py` | Click CLI 接口（scan/fix/monitor 命令） |
| `discovery.py` | OpenClaw 发现（配置、CLI、端口探测） |
| `models.py` | 数据模型（ScanResult、Finding、ExitCode 等） |
| `output.py` | 终端/JSON/SARIF 格式化器 |
| `probe.py` | WebSocket 漏洞探测器 |
| `vuln_db.py` | 漏洞数据库与版本检查 |

---

## 🔒 安全与隐私

ClawCheck 遵循负责任的扫描原则：

| 特性 | 说明 |
|------|------|
| ✅ **离线能力** | 无外部数据传输，完全本地运行 |
| ✅ **只读探测** | 不修改系统配置（扫描模式） |
| ✅ **速率限制** | 1 请求/秒（遵循 AWS 协作扫描指南） |
| ✅ **无暴力破解** | 从不尝试密码猜测 |
| ✅ **开源代码** | 完全可审计的代码 |

**安全约束：**

- 探测测试延迟：1 秒/请求
- 连接超时：30 秒
- 操作超时：10 秒
- 不执行实际暴力攻击
- 仅限只读操作

---

## 🧪 开发

### 运行测试

```bash
# 安装开发依赖
pip install -e ".[dev]"

# 运行测试
pytest

# 运行带覆盖率的测试
pytest --cov=clawcheck --cov-report=html
```

### 代码质量

```bash
# 代码格式化
black src/

# 代码检查
ruff check src/

# 类型检查
mypy src/
```

---

## 🤝 贡献

欢迎贡献！请遵循以下步骤：

1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 开启 Pull Request

---

## 📄 许可证

MIT License — 详见 [LICENSE](LICENSE) 文件

---

## ⚠️ 免责声明

本工具仅供安全测试使用。扫描系统前请务必获得适当授权。作者不对本软件的滥用负责。

---

## 🔗 相关链接

- [Oasis Security: ClawJacked 漏洞披露](https://www.oasis.security/blog/openclaw-vulnerability)
- [OpenClaw 仓库](https://github.com/openclaw/openclaw)
- [SARIF v2.1.0 规范](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [PyPI 包](https://pypi.org/project/clawcheck/)

---

**保持安全！ 🛡️**
