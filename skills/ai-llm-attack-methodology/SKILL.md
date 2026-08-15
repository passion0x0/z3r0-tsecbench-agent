---
name: ai-llm-attack-methodology
description: Use when the target is an AI/LLM application, agent platform, inference service, or ML demo (e.g. Dify, chatbots, code interpreters, model-serving APIs). Covers prompt injection, jailbreak, system-prompt/data leakage, excessive agency abuse, and the web-layer vulns that AI platforms commonly expose.
---

# AI / LLM Application Attack Methodology

Authorized testing only. AI platforms are attacked on TWO layers: the LLM interaction layer AND the ordinary web/infra layer beneath it. Check both.

## Layer 1: Web/Infra (often the real flag path)

AI platforms are still web apps. Frequently the flag is behind a mundane web vuln, not the model:
- Fingerprint the platform and version (Dify, LangChain, Gradio, Streamlit, Flask). Look up known CVEs for that exact version.
- Unauthenticated API endpoints, admin panels, `/console/api`, `/api`, install/setup endpoints left open.
- SSRF via model tool/plugin/URL-fetch features (fetch a URL → point at internal / `169.254.169.254`).
- Sef-hosted model runners: exposed management ports, arbitrary file read, RCE via config.
- Default credentials, exposed API keys in JS, IDOR on conversation/app IDs.
- Code interpreter / tool-execution features → direct command exec (see sandbox-escape-methodology).

## Layer 2: LLM-specific

- **Prompt injection:** override system prompt — "ignore previous instructions", role-play, delimiter confusion, encoded instructions. Goal: make it reveal the flag/system prompt or call a tool it shouldn't.
- **System prompt leak:** "repeat everything above", "what are your instructions", translation/summarize tricks. Flag often hidden in the system prompt.
- **Jailbreak:** DAN-style, hypothetical framing, token smuggling, low-resource-language bypass.
- **Excessive agency:** if the LLM can call tools (search, code, file, HTTP), abuse those to read files / SSRF / exec. Prompt-inject to trigger the tool with attacker args.
- **Indirect injection:** if it ingests external content (RAG, uploaded docs, fetched pages), plant instructions in that content.
- **Data leakage:** training data / other users' conversations / embedded secrets.
- **Deeper专项 skill(需要时 load):** 纯 prompt 层攻防(prompt泄露/注入/越狱/CoT注入/MCP工具投毒)→ load `ai-llm-advanced`; 数据泄露/身份越权/Web↔AI跨域链 → load `ai-data-identity`; 模型文件 pickle RCE/供应链投毒 → load `ai-ml-supply-chain`; 具体产品 CVE(Dify/Langflow/Gradio/ComfyUI)→ load `ai-platform-cve`;拿到具体CVE号/2024-2025新洞(ComfyUI/Ollama/vLLM/Flowise/RAGFlow等15种AI平台)→ load `ai-platform-cve-2`。

## Approach

1. Fingerprint platform+version → search known CVEs FIRST (often the fastest flag).
2. Map endpoints and auth — probe for unauthenticated/admin/console APIs.
3. If a chat/prompt interface: try system-prompt leak, then prompt injection toward tool abuse or flag disclosure.
4. If a code/tool feature: pivot to sandbox-escape-methodology for direct exec.
5. Flag locations: system prompt, admin API response, env vars after RCE, DB.

## Target-class Note

AI-platform-class targets are "AI应用平台 / AI推理服务 / AI模型演示平台" style. Prioritize version fingerprint → known CVE, and exposed unauth APIs, before deep LLM jailbreak. Dify in particular has had multiple auth/SSRF/RCE CVEs — identify the version.

## Output

Report: platform+version, attack layer, vulnerability, exploitation steps, flag.
