"""
Provider-agnostic LLM client abstraction.

LLM Inspector uses an LLM as its reasoning brain (Planner, Executor,
Critic). This module defines a unified interface so the user can bring
any supported provider's API key -- Anthropic (Claude), OpenAI, Google
Gemini, or a local Ollama instance -- without the rest of the codebase
caring which one is behind the scenes.

Each provider adapter translates the unified message/tool format into
that provider's SDK format and normalizes responses back.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Unified response types -- every adapter returns these
# ---------------------------------------------------------------------------

@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def has_tool_calls(self) -> bool:
        return len(self.tool_calls) > 0


# ---------------------------------------------------------------------------
# Base class -- every provider implements this
# ---------------------------------------------------------------------------

class BaseLLMClient(ABC):
    """Async interface that Planner / Executor / Critic talk to."""

    provider_name: str = "base"

    @abstractmethod
    async def create_message(
        self,
        *,
        model: str,
        max_tokens: int,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse:
        ...

    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Rough per-call cost in USD. Override per provider for accuracy."""
        return (input_tokens / 1_000_000) * 3.0 + (output_tokens / 1_000_000) * 15.0


# ---------------------------------------------------------------------------
# Anthropic (Claude)
# ---------------------------------------------------------------------------

class AnthropicClient(BaseLLMClient):
    provider_name = "anthropic"

    def __init__(self, api_key: str) -> None:
        from anthropic import AsyncAnthropic
        self._client = AsyncAnthropic(api_key=api_key)

    async def create_message(self, *, model, max_tokens, system, messages, tools=None) -> LLMResponse:
        kwargs: dict[str, Any] = dict(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=messages,
        )
        if tools:
            kwargs["tools"] = tools

        resp = await self._client.messages.create(**kwargs)

        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for block in resp.content:
            if getattr(block, "type", "") == "text":
                text_parts.append(block.text)
            elif getattr(block, "type", "") == "tool_use":
                tool_calls.append(ToolCall(id=block.id, name=block.name, arguments=block.input))

        return LLMResponse(
            text="\n".join(text_parts),
            tool_calls=tool_calls,
            input_tokens=resp.usage.input_tokens,
            output_tokens=resp.usage.output_tokens,
        )

    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        return (input_tokens / 1_000_000) * 5.0 + (output_tokens / 1_000_000) * 25.0


# ---------------------------------------------------------------------------
# OpenAI (GPT-4o, o3, etc.)
# ---------------------------------------------------------------------------

class OpenAIClient(BaseLLMClient):
    provider_name = "openai"

    def __init__(self, api_key: str, base_url: str | None = None) -> None:
        from openai import AsyncOpenAI
        kwargs: dict[str, Any] = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        self._client = AsyncOpenAI(**kwargs)

    async def create_message(self, *, model, max_tokens, system, messages, tools=None) -> LLMResponse:
        oai_messages: list[dict[str, Any]] = [{"role": "system", "content": system}]
        for msg in messages:
            oai_messages.append(self._convert_message(msg))

        kwargs: dict[str, Any] = dict(
            model=model,
            max_tokens=max_tokens,
            messages=oai_messages,
        )
        if tools:
            kwargs["tools"] = [self._to_openai_tool(t) for t in tools]

        resp = await self._client.chat.completions.create(**kwargs)
        choice = resp.choices[0]

        text = choice.message.content or ""
        tool_calls: list[ToolCall] = []
        if choice.message.tool_calls:
            for tc in choice.message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, TypeError):
                    args = {}
                tool_calls.append(ToolCall(id=tc.id, name=tc.function.name, arguments=args))

        usage = resp.usage
        return LLMResponse(
            text=text,
            tool_calls=tool_calls,
            input_tokens=usage.prompt_tokens if usage else 0,
            output_tokens=usage.completion_tokens if usage else 0,
        )

    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        return (input_tokens / 1_000_000) * 2.5 + (output_tokens / 1_000_000) * 10.0

    @staticmethod
    def _to_openai_tool(tool: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "parameters": tool.get("input_schema", {}),
            },
        }

    @staticmethod
    def _convert_message(msg: dict[str, Any]) -> dict[str, Any]:
        role = msg["role"]
        content = msg.get("content")

        if role == "assistant" and isinstance(content, list):
            text_parts = []
            oai_tool_calls = []
            for block in content:
                if block.get("type") == "text":
                    text_parts.append(block["text"])
                elif block.get("type") == "tool_use":
                    oai_tool_calls.append({
                        "id": block["id"],
                        "type": "function",
                        "function": {
                            "name": block["name"],
                            "arguments": json.dumps(block["input"]),
                        },
                    })
            out: dict[str, Any] = {"role": "assistant", "content": "\n".join(text_parts) or None}
            if oai_tool_calls:
                out["tool_calls"] = oai_tool_calls
            return out

        if role == "user" and isinstance(content, list):
            tool_results = [b for b in content if b.get("type") == "tool_result"]
            if tool_results:
                oai_msgs: list[dict[str, Any]] = []
                for tr in tool_results:
                    oai_msgs.append({
                        "role": "tool",
                        "tool_call_id": tr["tool_use_id"],
                        "content": tr.get("content", ""),
                    })
                return oai_msgs[0] if len(oai_msgs) == 1 else oai_msgs  # type: ignore[return-value]

        return {"role": role, "content": content if isinstance(content, str) else json.dumps(content)}


# ---------------------------------------------------------------------------
# Groq (OpenAI-compatible, fast inference)
# ---------------------------------------------------------------------------

class GroqClient(OpenAIClient):
    provider_name = "groq"

    def __init__(self, api_key: str, base_url: str | None = None) -> None:
        super().__init__(
            api_key=api_key,
            base_url=base_url or "https://api.groq.com/openai/v1",
        )

    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        return (input_tokens / 1_000_000) * 0.60 + (output_tokens / 1_000_000) * 0.80


# ---------------------------------------------------------------------------
# Google Gemini
# ---------------------------------------------------------------------------

class GeminiClient(BaseLLMClient):
    provider_name = "gemini"

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    async def create_message(self, *, model, max_tokens, system, messages, tools=None) -> LLMResponse:
        from google import genai
        from google.genai import types as gtypes

        client = genai.Client(api_key=self._api_key)

        gemini_tools = None
        if tools:
            func_decls = []
            for t in tools:
                schema = dict(t.get("input_schema", {}))
                schema.pop("additionalProperties", None)
                func_decls.append(gtypes.FunctionDeclaration(
                    name=t["name"],
                    description=t.get("description", ""),
                    parameters=schema if schema else None,
                ))
            gemini_tools = [gtypes.Tool(function_declarations=func_decls)]

        gemini_contents = []
        for msg in messages:
            gemini_contents.extend(self._convert_message(msg))

        config = gtypes.GenerateContentConfig(
            system_instruction=system,
            max_output_tokens=max_tokens,
            tools=gemini_tools,
        )

        resp = await client.aio.models.generate_content(
            model=model,
            contents=gemini_contents,
            config=config,
        )

        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        if resp.candidates and resp.candidates[0].content:
            for part in resp.candidates[0].content.parts:
                if part.text:
                    text_parts.append(part.text)
                if part.function_call:
                    fc = part.function_call
                    tool_calls.append(ToolCall(
                        id=f"gemini_{fc.name}_{id(fc)}",
                        name=fc.name,
                        arguments=dict(fc.args) if fc.args else {},
                    ))

        input_tok = getattr(resp.usage_metadata, "prompt_token_count", 0) or 0
        output_tok = getattr(resp.usage_metadata, "candidates_token_count", 0) or 0

        return LLMResponse(
            text="\n".join(text_parts),
            tool_calls=tool_calls,
            input_tokens=input_tok,
            output_tokens=output_tok,
        )

    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        return (input_tokens / 1_000_000) * 1.25 + (output_tokens / 1_000_000) * 5.0

    @staticmethod
    def _convert_message(msg: dict[str, Any]) -> list[dict[str, Any]]:
        from google.genai import types as gtypes

        role = msg["role"]
        content = msg.get("content")
        gemini_role = "model" if role == "assistant" else "user"

        if role == "user" and isinstance(content, list):
            tool_results = [b for b in content if b.get("type") == "tool_result"]
            if tool_results:
                parts = []
                for tr in tool_results:
                    resp_data = tr.get("content", "")
                    try:
                        resp_obj = json.loads(resp_data)
                    except (json.JSONDecodeError, TypeError):
                        resp_obj = {"result": resp_data}
                    parts.append(gtypes.Part.from_function_response(
                        name=tr.get("tool_name", "tool"),
                        response=resp_obj,
                    ))
                return [{"role": "user", "parts": parts}]

        if role == "assistant" and isinstance(content, list):
            parts = []
            for block in content:
                if block.get("type") == "text":
                    parts.append(gtypes.Part.from_text(text=block["text"]))
                elif block.get("type") == "tool_use":
                    parts.append(gtypes.Part.from_function_call(
                        name=block["name"],
                        args=block["input"],
                    ))
            return [{"role": "model", "parts": parts}]

        text = content if isinstance(content, str) else json.dumps(content)
        return [{"role": gemini_role, "parts": [gtypes.Part.from_text(text=text)]}]


# ---------------------------------------------------------------------------
# Ollama (local models)
# ---------------------------------------------------------------------------

class OllamaClient(BaseLLMClient):
    provider_name = "ollama"

    def __init__(self, base_url: str = "http://localhost:11434") -> None:
        self._base_url = base_url.rstrip("/")

    async def create_message(self, *, model, max_tokens, system, messages, tools=None) -> LLMResponse:
        import httpx

        ollama_messages: list[dict[str, Any]] = [{"role": "system", "content": system}]
        for msg in messages:
            ollama_messages.extend(self._convert_message(msg))

        payload: dict[str, Any] = {
            "model": model,
            "messages": ollama_messages,
            "stream": False,
            "options": {"num_predict": max_tokens},
        }
        if tools:
            payload["tools"] = [self._to_ollama_tool(t) for t in tools]

        async with httpx.AsyncClient(timeout=300) as http:
            resp = await http.post(f"{self._base_url}/api/chat", json=payload)
            resp.raise_for_status()
            data = resp.json()

        text = data.get("message", {}).get("content", "")
        tool_calls: list[ToolCall] = []
        for i, tc in enumerate(data.get("message", {}).get("tool_calls", [])):
            fn = tc.get("function", {})
            tool_calls.append(ToolCall(
                id=f"ollama_{i}",
                name=fn.get("name", ""),
                arguments=fn.get("arguments", {}),
            ))

        input_tok = data.get("prompt_eval_count", 0) or 0
        output_tok = data.get("eval_count", 0) or 0

        return LLMResponse(
            text=text,
            tool_calls=tool_calls,
            input_tokens=input_tok,
            output_tokens=output_tok,
        )

    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        return 0.0

    @staticmethod
    def _to_ollama_tool(tool: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "parameters": tool.get("input_schema", {}),
            },
        }

    @staticmethod
    def _convert_message(msg: dict[str, Any]) -> list[dict[str, Any]]:
        role = msg["role"]
        content = msg.get("content")

        if role == "user" and isinstance(content, list):
            tool_results = [b for b in content if b.get("type") == "tool_result"]
            if tool_results:
                out = []
                for tr in tool_results:
                    out.append({"role": "tool", "content": tr.get("content", "")})
                return out

        if role == "assistant" and isinstance(content, list):
            text_parts = []
            tc_list = []
            for block in content:
                if block.get("type") == "text":
                    text_parts.append(block["text"])
                elif block.get("type") == "tool_use":
                    tc_list.append({
                        "function": {
                            "name": block["name"],
                            "arguments": block["input"],
                        }
                    })
            out_msg: dict[str, Any] = {"role": "assistant", "content": "\n".join(text_parts)}
            if tc_list:
                out_msg["tool_calls"] = tc_list
            return [out_msg]

        text = content if isinstance(content, str) else json.dumps(content)
        return [{"role": role, "content": text}]


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

PROVIDER_REGISTRY: dict[str, type[BaseLLMClient]] = {
    "anthropic": AnthropicClient,
    "openai": OpenAIClient,
    "groq": GroqClient,
    "gemini": GeminiClient,
    "ollama": OllamaClient,
}

DEFAULT_MODELS: dict[str, str] = {
    "anthropic": "claude-sonnet-4-20250514",
    "openai": "gpt-4o",
    "groq": "openai/gpt-oss-20b",
    "gemini": "gemini-2.5-flash",
    "ollama": "qwen2.5:14b",
}


def _is_local_url(url: str | None) -> bool:
    """True if the URL points to localhost / a local network address."""
    if not url:
        return False
    return any(tok in url for tok in ["localhost", "127.0.0.1", "0.0.0.0", "192.168.", "10."])


def build_llm_client(
    provider: str,
    api_key: str | None = None,
    base_url: str | None = None,
) -> BaseLLMClient:
    provider = provider.lower()
    if provider not in PROVIDER_REGISTRY:
        raise ValueError(
            f"Unknown provider {provider!r}. "
            f"Supported: {', '.join(PROVIDER_REGISTRY.keys())}"
        )

    if provider == "ollama":
        return OllamaClient(base_url=base_url or "http://localhost:11434")

    # Don't pass a local base_url (e.g. Ollama's localhost) to cloud providers —
    # it's almost certainly a leftover from a different provider config.
    cloud_base_url = None if _is_local_url(base_url) else base_url

    if not api_key:
        env_names = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "groq": "GROQ_API_KEY",
            "gemini": "GEMINI_API_KEY",
        }
        raise ValueError(
            f"No API key provided for {provider}. "
            f"Set {env_names.get(provider, 'the API key')} in your environment/.env, "
            f"or pass --api-key to the CLI."
        )

    if provider == "groq":
        return GroqClient(api_key=api_key, base_url=cloud_base_url)
    if provider == "openai":
        return OpenAIClient(api_key=api_key, base_url=cloud_base_url)
    if provider == "gemini":
        return GeminiClient(api_key=api_key)
    return AnthropicClient(api_key=api_key)
