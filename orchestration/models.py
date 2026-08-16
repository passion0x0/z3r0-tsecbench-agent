"""Native OpenAI model construction for configured agents."""

from __future__ import annotations

from collections.abc import AsyncIterator

from agents import (
    AgentOutputSchemaBase,
    Handoff,
    Model,
    ModelResponse,
    ModelRetryAdvice,
    ModelRetryAdviceRequest,
    ModelSettings,
    ModelTracing,
    TResponseInputItem,
    Tool,
)
from agents.models.openai_provider import OpenAIProvider
from agents.stream_events import TResponseStreamEvent
from openai.types.responses.response_prompt_param import ResponsePromptParam
from openai import AsyncOpenAI

from config import AgentConfig
from core.agent.model_input import ModelInputAdapter
from core.agent.dsml_salvage import salvage_chat_stream


def _install_dsml_salvage(client) -> None:
    """Wrap the client's chat.completions.create so leaked DeepSeek DSML
    tool-call markup in streamed content is recovered into real tool calls."""
    completions = client.chat.completions
    original_create = completions.create

    async def create(*args, **kwargs):
        result = await original_create(*args, **kwargs)
        if kwargs.get("stream"):
            return salvage_chat_stream(result)
        return result

    completions.create = create



class Z3r0OpenAIModel(Model):
    def __init__(self, cfg: AgentConfig, fallback_cfg: "AgentConfig | None" = None) -> None:
        self.model = cfg.model
        self._input_adapter = ModelInputAdapter()
        self._client = AsyncOpenAI(
            api_key=cfg.api_key or ("unused" if cfg.base_url else None),
            base_url=cfg.base_url or None,
        )
        _install_dsml_salvage(self._client)
        self._provider = OpenAIProvider(
            openai_client=self._client,
            use_responses=cfg.use_responses,
        )
        self._model = self._provider.get_model(cfg.model)

        # Fallback: 当主模型不可用(503/timeout/connection error)时自动切到备用模型
        self._fallback_model = None
        if fallback_cfg:
            fb_client = AsyncOpenAI(
                api_key=fallback_cfg.api_key or ("unused" if fallback_cfg.base_url else None),
                base_url=fallback_cfg.base_url or None,
            )
            _install_dsml_salvage(fb_client)
            fb_provider = OpenAIProvider(
                openai_client=fb_client,
                use_responses=fallback_cfg.use_responses,
            )
            self._fallback_model = fb_provider.get_model(fallback_cfg.model)

    def get_retry_advice(self, request: ModelRetryAdviceRequest) -> ModelRetryAdvice | None:
        return self._model.get_retry_advice(request)

    async def get_response(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: AgentOutputSchemaBase | None,
        handoffs: list[Handoff],
        tracing: ModelTracing,
        *,
        previous_response_id: str | None,
        conversation_id: str | None,
        prompt: ResponsePromptParam | None,
    ) -> ModelResponse:
        return await self._model.get_response(
            system_instructions,
            self._input_adapter.adapt(input),
            model_settings,
            tools,
            output_schema,
            handoffs,
            tracing,
            previous_response_id=previous_response_id,
            conversation_id=conversation_id,
            prompt=prompt,
        )

    async def stream_response(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: AgentOutputSchemaBase | None,
        handoffs: list[Handoff],
        tracing: ModelTracing,
        *,
        previous_response_id: str | None,
        conversation_id: str | None,
        prompt: ResponsePromptParam | None,
    ) -> AsyncIterator[TResponseStreamEvent]:
        adapted_input = self._input_adapter.adapt(input)
        try:
            async for event in self._model.stream_response(
                system_instructions, adapted_input, model_settings, tools,
                output_schema, handoffs, tracing,
                previous_response_id=previous_response_id,
                conversation_id=conversation_id, prompt=prompt,
            ):
                yield event
        except Exception as e:
            # Fallback: 主模型失败时切到备用模型
            if self._fallback_model and _is_retriable_error(e):
                import logging
                logging.getLogger(__name__).warning(
                    f"Primary model failed ({type(e).__name__}), falling back to secondary"
                )
                async for event in self._fallback_model.stream_response(
                    system_instructions, adapted_input, model_settings, tools,
                    output_schema, handoffs, tracing,
                    previous_response_id=previous_response_id,
                    conversation_id=conversation_id, prompt=prompt,
                ):
                    yield event
            else:
                raise

    async def close(self) -> None:
        await self._model.close()
        await self._provider.aclose()
        await self._client.close()


def _is_retriable_error(e: Exception) -> bool:
    """判断错误是否属于可 fallback 的临时故障(503/timeout/connection error)"""
    import openai
    if isinstance(e, (openai.APIConnectionError, openai.APITimeoutError)):
        return True
    if isinstance(e, openai.APIStatusError) and e.status_code in (502, 503, 504, 529):
        return True
    # httpx/httpcore 底层错误
    err_name = type(e).__name__
    if "RemoteProtocol" in err_name or "Timeout" in err_name or "ConnectionError" in err_name:
        return True
    return False


# ---- Fallback 配置: GLM 角色 fallback 到 DeepSeek, DeepSeek 角色 fallback 到 GLM ----
_FALLBACK_CFG_CACHE: dict = {}

def _get_fallback_cfg(primary_cfg: "AgentConfig") -> "AgentConfig | None":
    """根据主模型配置生成备用模型配置(互为 fallback)"""
    import os, copy
    # 判断主模型是 GLM 还是 DeepSeek
    if "glm" in (primary_cfg.model or "").lower() or "agent-awd" in (primary_cfg.base_url or ""):
        # GLM → fallback 到 DeepSeek
        fb = copy.copy(primary_cfg)
        fb.model = os.environ.get("LLM_MODEL", "deepseek-v4-pro")
        fb.base_url = os.environ.get("LLM_BASE_URL", "http://api.deepseek.com.tsecbench.gw/v1")
        fb.api_key = os.environ.get("LLM_API_KEY", "")
        return fb
    elif "deepseek" in (primary_cfg.model or "").lower():
        # DeepSeek → fallback 到 GLM
        fb = copy.copy(primary_cfg)
        fb.model = os.environ.get("GLM_MODEL", "glm-5.2-agent-chanllenge")
        fb.base_url = os.environ.get("GLM_BASE_URL", "http://agent-awd.baidu.com.tsecbench.gw/v1")
        fb.api_key = os.environ.get("GLM_API_KEY", "5q9C6VSjEg4sLNDu8dBfBe83326a4a3aA61d3cA6Dd8024Bb")
        return fb
    return None


def build_openai_model(cfg: AgentConfig) -> Z3r0OpenAIModel:
    # 纯 DeepSeek 单模型,不启用 fallback(稳定优先)
    return Z3r0OpenAIModel(cfg)
