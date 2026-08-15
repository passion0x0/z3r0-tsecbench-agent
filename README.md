# Z3r0-TSecBench 攻防自动化 Agent

> 基于开源黑盒红队平台 **[Z3r0](https://github.com/yv1ing/Z3r0)** 二次开发的全链路攻防自动化 Agent。
> 在 TSecBench 官方攻防基准上取得 **18300 / 23000 分**（54/63 题，79.7% 完成率），全程无人值守。

参赛作品 · 百度 BSRC "Agent+" 攻防能力挑战赛

---

## 核心思想

**制约大模型攻防成绩的第一瓶颈不是模型推理能力，而是"方法论 + 知识组织"。**

同一个模型（deepseek-v4-pro）、同一个平台：
- 直接跑原版 Z3r0 → 约 **6500 分**
- 注入方法论 + 知识库 + 编排策略后 → **18300 分**

涨出来的 11800 分，全部来自本仓库的四大增量改造。

## 相比原版 Z3r0 的增量

| 层面 | Z3r0 原版 | 本作品增量 |
|---|---|---|
| Skill 体系 | 25 个工具手册（教"怎么用 nmap"） | **+70 个方法论 / CVE 专项**（教"怎么解题"） |
| 知识库 | 无 | **12405 条离线 CVE 知识库 + grep 命中机制** |
| 编排策略 | 通用对话 | **题目级委派 + 弹性时间预算 + 防自毁约束** |
| 部署形态 | 多容器、依赖外网 | **单容器 <3GB 离线化改造** |

## 架构

```
【调度层】 CSO 指挥官 Agent —— 选题 / 委派 / 提交 / 关闭
             └─ 题目级委派 ─▶ 5 类专家（渗透 / 逆向 / 审计 / 密码 / 情报）
                    │
【知识层】 95 个方法论 Skill  +  12405 条 CVE 知识库
             ├─ 题型 Playbook（云 / WAF / 沙箱 / 固件逆向…）
             ├─ 产品 CVE 速查（OA / AI 平台 / 中间件全家桶）
             └─ 离线漏洞库（AboutSecurity 详案 + nuclei 模板）
                    │
【执行层】 本地命令执行  +  安全工具链（无 docker 依赖）
             └─ 内嵌 PostgreSQL + 应用 + nmap / sqlmap / gdb …
```

## 目录结构

```
├── docs/技术报告.md          # 完整技术方案
├── orchestration/
│   ├── score_launch.py       # CSO 编排提示词 + 自动解题主流程（核心原创）
│   └── watch_session.py      # 会话看门狗（卡死检测 / 自动续跑）
├── skills/                   # 95 个方法论 Skill（本作品核心资产）
├── deploy/
│   ├── Dockerfile.bench      # 托管模式单容器构建
│   └── start-bench.sh        # 启动入口（env → config → 自动解题）
└── scripts/
    └── build_cve_kb.sh       # 一键构建 12405 条离线 CVE 知识库
```

## 运行环境

- Docker（宿主无需 GPU）
- 一个 OpenAI 兼容的 LLM 端点（默认 deepseek-v4-pro）
- 构建知识库时需临时联网（运行时全离线）

## 部署方式

### 1. 构建 CVE 知识库

知识库源自第三方开源项目，不随仓库分发，用脚本一键构建：

```bash
bash scripts/build_cve_kb.sh        # 生成 ./cve-kb/（约 12405 条）
```

### 2. 基于 Z3r0 构建镜像

本仓库提供的是**增量层**：Skill、编排脚本、部署入口。需先拥有 Z3r0 应用基础镜像（`z3r0-hosted`），再叠加本仓库内容：

```bash
# skills → 挂载/COPY 到沙箱 /root/.agents/skills
# cve-kb → COPY 到 /root/cve-kb
# orchestration + deploy → 见 Dockerfile.bench
docker build -f deploy/Dockerfile.bench -t z3r0-tsecbench:latest .
```

### 3. 启动（自动解题）

```bash
docker run -e LLM_API_KEY=YOUR_DEEPSEEK_API_KEY \
           -e BENCHMARK_TOKEN=YOUR_TOKEN \
           z3r0-tsecbench:latest
```

启动后自动完成：postgres 初始化 → 生成配置 → 创建评测会话 → CSO 选题委派 → 专家解题提交，全程无人介入。

## 实验结果

| 维度 | 表现 |
|---|---|
| 总分 | **18300 / 23000** |
| 完成题目 | 54 / 63（79.7%） |
| 云攻击 | 6/6 满分 |
| 对抗规避 | 14/14 满分 |
| 二进制 | 12/13 |
| Web | 16/18 |
| 人机验证时间 | ≈ 0（无人值守） |

详见 [docs/技术报告.md](docs/技术报告.md)。

## 关于 Skill 的设计原则

所有 Skill 严格保持**"题型级"抽象**——只写"图数据库服务 → Neo4j/HugeGraph → Gremlin RCE 类漏洞模式"这样的**通用方法论**，不含任何具体题号或答案，因此换题、换题库依然通用，可直接迁移到真实攻防场景。

## 致谢与许可

- 基座框架：[yv1ing/Z3r0](https://github.com/yv1ing/Z3r0)（黑盒红队平台）
- 知识库来源：AboutSecurity、[projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)

本仓库为在 Z3r0 之上的增量二次开发成果，遵循基座项目的开源许可，仅供安全研究与授权测试使用。详见 [LICENSE](LICENSE)。
