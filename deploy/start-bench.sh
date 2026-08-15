#!/bin/bash
# 托管模式入口(TSecBench hosted):从环境变量读配置 → 生成 config.json → 起内嵌 postgres + app → 自动解题。
# 与 start-hosted.sh 的区别:模型走平台大模型网关(env 注入),启动后自动开始解题循环。
set -e

export POSTGRES_USER="${POSTGRES_USER:-root}"
export POSTGRES_DB="${POSTGRES_DB:-z3r0}"
export POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-123456}"
export POSTGRES_HOST_AUTH_METHOD="${POSTGRES_HOST_AUTH_METHOD:-trust}"
export PGDATA="${PGDATA:-/var/lib/postgresql/18/docker}"
# import 后镜像丢失原 ENV PATH,补上 postgres bin 目录(initdb/pg_isready/psql 都在这里)
export PATH="/usr/lib/postgresql/18/bin:${PATH}"

PG_PORT=5432
APP_DIR=/app

# ---- 托管模式必需环境变量 ----
# 默认 key 已 bake 进镜像,上传时可不填 LLM_API_KEY(平台若注入同名变量会覆盖此默认值)
export LLM_API_KEY="${LLM_API_KEY:-${DEEPSEEK_API_KEY:-YOUR_DEEPSEEK_API_KEY}}"
export LLM_BASE_URL="${LLM_BASE_URL:-http://api.deepseek.com.tsecbench.gw/v1}"
export LLM_MODEL="${LLM_MODEL:-deepseek-v4-pro}"

if [ -z "$LLM_API_KEY" ]; then
    echo "[bench] 缺少 LLM_API_KEY / DEEPSEEK_API_KEY 环境变量" >&2
    exit 1
fi

echo "[bench] 启动内嵌 postgres ..."
# import 后的镜像会丢失 VOLUME 目录,手动创建 PGDATA + socket 目录并授权 postgres 用户
mkdir -p "${PGDATA}" /run/postgresql
chown -R postgres:postgres /var/lib/postgresql /run/postgresql 2>/dev/null || true
docker-entrypoint.sh postgres -c shared_preload_libraries=age -c listen_addresses='127.0.0.1' -p "${PG_PORT}" &
PG_PID=$!

for i in $(seq 1 60); do
    if pg_isready -h 127.0.0.1 -p "${PG_PORT}" -U "${POSTGRES_USER}" >/dev/null 2>&1; then
        echo "[bench] postgres 就绪 (${i}s)"; break
    fi
    if ! kill -0 "${PG_PID}" 2>/dev/null; then
        echo "[bench] postgres 启动失败" >&2; exit 1
    fi
    sleep 1
done

# ---- 从环境变量生成 config.json(模型走网关, 统一单一强模型) ----
echo "[bench] 生成 config.json (model=${LLM_MODEL} base_url=${LLM_BASE_URL}) ..."
mkdir -p "${APP_DIR}/.z3r0"
python3 - <<PYEOF
import json, os
tmpl = json.load(open("${APP_DIR}/hosted_config.json"))
for code in tmpl.get("agents", {}):
    tmpl["agents"][code]["model"] = os.environ.get("LLM_MODEL", "deepseek-v4-pro")
    tmpl["agents"][code]["base_url"] = os.environ.get("LLM_BASE_URL", "http://api.deepseek.com.tsecbench.gw/v1")
    tmpl["agents"][code]["api_key"] = os.environ.get("LLM_API_KEY", "")
    tmpl["agents"][code]["use_responses"] = False
json.dump(tmpl, open("${APP_DIR}/.z3r0/config.json", "w"), indent=2, ensure_ascii=False)
print("[bench] config.json 已写入,", len(tmpl.get("agents", {})), "个角色")
PYEOF

trap 'echo "[bench] 收到终止信号"; kill -TERM "${PG_PID}" 2>/dev/null; exit 0' TERM INT

echo "[bench] 启动 Z3r0 app ..."
cd "${APP_DIR}"
export Z3R0_DISABLE_LIGHTRAG=1
# import 后镜像丢失原 ENV,补上运行时关键环境变量(本地执行/无 docker daemon + tiktoken 缓存路径)
export Z3R0_LOCAL_EXEC=1
export TIKTOKEN_CACHE_DIR=/root/.cache/tiktoken
export PYTHONUNBUFFERED=1
export PYTHONDONTWRITEBYTECODE=1
python3 main.py &
APP_PID=$!

# 等 app 就绪 + seed 沙箱
for i in $(seq 1 60); do
    if python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/',timeout=2).getcode()==200 else 1)" >/dev/null 2>&1; then
        break
    fi
    if ! kill -0 "${APP_PID}" 2>/dev/null; then
        echo "[bench] app 启动失败" >&2; exit 1
    fi
    sleep 1
done
python3 "${APP_DIR}/hosted/seed_sandbox.py" 2>&1 | sed 's/^/[seed] /'

# ---- 自动解题循环 ----
echo "[bench] 开始自动解题 ..."
python3 /score_launch.py
echo "[bench] 首个会话已创建, 启动 watchdog 监控 ..."
exec python3 /watch_session.py
