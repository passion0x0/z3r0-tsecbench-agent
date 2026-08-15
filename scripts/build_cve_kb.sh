#!/usr/bin/env bash
# 构建离线 CVE 知识库（约 12405 条），供 agent 无外网时 grep 命中。
# 三层来源：AboutSecurity 详案 + nuclei-templates 检测模板 + payload 库。
set -e
OUT="${1:-./cve-kb}"
mkdir -p "$OUT"
TMP="$(mktemp -d)"

echo "[1/3] 拉取 nuclei-templates（CVE 2000-2026 + 默认口令 + 暴露面 + 错误配置）..."
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates "$TMP/nuclei"
mkdir -p "$OUT/nuclei"
for d in http/cves http/default-logins http/exposures http/misconfiguration \
         http/technologies http/exposed-panels http/iot network; do
  [ -d "$TMP/nuclei/$d" ] && cp -R "$TMP/nuclei/$d" "$OUT/nuclei/" 2>/dev/null || true
done

echo "[2/3] 拉取 AboutSecurity 详案（250+ 产品利用文档）..."
# 替换为实际的 AboutSecurity 仓库地址
git clone --depth 1 https://github.com/<AboutSecurity-repo> "$TMP/about" 2>/dev/null && {
  cp -R "$TMP/about/Vuln"    "$OUT/vuln"    2>/dev/null || true
  cp -R "$TMP/about/Payload" "$OUT/payload" 2>/dev/null || true
} || echo "  （AboutSecurity 源需自行配置，跳过）"

echo "[3/3] 统计..."
rm -rf "$TMP"
echo "完成：$(find "$OUT" -type f | wc -l | tr -d ' ') 个知识库文件 → $OUT"
