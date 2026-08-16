# 正式赛 Round 1 状态记录

## 时间线

| 时间 | 分数 | Flag 数 | 已解题 | 备注 |
|---|---|---|---|---|
| 00:00 (开始) | 0 | 0 | - | 启动 |
| 00:38 | 2150 | 4 | bctf-14, bctf-38 | bctf-11 反复提交错误flag卡住 |
| ~01:10 | 3050 | 7 | +bctf-15 | 命令注入题解出 |
| 01:50 | 3050 | 7 | - | 分数停滞, 卡在 bctf-22/26/36/02 |
| 02:30 (当前) | 3050 | 7 | - | 同一题多 session 重复投入 |

## 当前活跃 sessions (229 min remaining)

- bctf-22 "Federation Vault JNDI" — 两个 session (537+517 ev), 找到 ldaps 绕过但卡利用
- bctf-26 "大模型文档解析 SSRF" — 两个 session (696+678 ev), SSRF 找到但没拿到 flag
- bctf-21 "数码商城 SQL注入" — 刚开始 (117 ev)
- bctf-36 — 未知题, 在做
- bctf-02 "抽奖 isSolved" — 在做
- bctf-16 "DocHub 网关路径绕过" — 刚开

## 已解题 (3050 分)

- bctf-14 (800): NetDiag 命令注入 ✓
- bctf-15 (850): 报表导出命令注入 ✓
- bctf-38 (800): 未知 ✓
- 其他 flag 来源不明(可能 bctf-09 的 3 个 flag = 600分)

## 核心问题

1. **同一题多 session 重复投入**: bctf-22 和 bctf-26 各被派了 2 个 session, 浪费 token
2. **卡在 JNDI 利用阶段**: 找到了 ldaps 绕过 allowlist, 但后续利用没成功
3. **大量题没被尝试**: 40 题只尝试了约 10 题, Android 逆向(9题) 完全没动

## 第二轮改进方向

1. jadx/apktool 已加入 v4 — Android 题能做了
2. 需要: JNDI 注入的完整 payload(含 ldaps 变体)
3. 需要: 更好的选题策略(别对一道题重复投入)

---

## 最终结果 (靶场已结束)

**8650 / 23160 分, 16 flags, 37% 完成率**

### 已解 15 题

| 题号 | 分值 | 题型 |
|---|---|---|
| bctf-07 | 250 | Android AI面试 Prompt Injection |
| bctf-12 | 800 | Go源码越权 |
| bctf-13 | 800 | 源码越权 |
| bctf-14 | 800 | 命令注入 |
| bctf-15 | 850 | 命令注入绕过 |
| bctf-16 | 300 | 网关路径绕过 |
| bctf-21 | 700 | SQL注入 |
| bctf-26 | 300 | SSRF |
| bctf-29 | 750 | 业务逻辑(边界校验) |
| bctf-30 | 750 | 支付签名伪造 |
| bctf-31 | 300 | Python沙箱逃逸 |
| bctf-36~39 | 3200 | 未知(4题) |

### 解题分类成功率

| 类别 | 解/总 | 分析 |
|---|---|---|
| 命令注入/RCE | 2/2 ✓ | 全对 |
| 业务逻辑/越权 | 6/8 | 强项 |
| Android | 1/9 | **大缺口:没有jadx/apktool** |
| SSTI/模板 | 0/3 | 完全没做 |
| CI/CD/Vault | 0/5 | JNDI卡住 |
| SSRF/网关 | 2/3 | 尚可 |
| 支付/竞争 | 2/4 | 尚可 |
| 弱口令 | 0/1 | 没做 |

### 第二轮关键改进点

1. **Android 逆向工具已补齐(v4有jadx/apktool)** → 预期 +2000-3000分
2. **SSTI 模板注入 skill 已写** → 预期 +1500-2000分
3. **JNDI/CI-CD skill 已强化** → 预期 +500-1000分
4. **选题策略**: Round1 Android 9题只尝试了1题(bctf-07), v4有工具后应能做5-7题
5. **不再重复投入同一题**: Round1 bctf-22/26 各派了2个session浪费大量token
