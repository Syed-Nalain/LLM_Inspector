"""
Target model: the LLM application under test.

A Target is deliberately generic (a REST endpoint description) rather than
tied to any one vendor, because in the real world the "target LLM" is
almost always someone's product wrapped in a chatbot/API, not a raw model.
This same REST description is reused to configure Garak's `rest` generator
and Promptfoo's `http` provider, so we only ask the user to describe their
target once.

Authorization is a first-class field: LLM Inspector refuses to run any
attack tooling against a target that hasn't been explicitly marked as
authorized by whoever is registering it. This is a scope/consent gate,
not a security control -- see EXTENDED_README.md for what a real
authorization system would need beyond this.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

HttpMethod = Literal["get", "post", "put", "patch", "delete"]


@dataclass
class RestTargetConfig:
    """
    Generic description of an HTTP-based LLM target, e.g. a customer
    support chatbot's `/chat` endpoint.

    request_template: a JSON-serializable object where the literal string
        "$INPUT" marks where the attack prompt gets substituted, e.g.
        {"messages": [{"role": "user", "content": "$INPUT"}]}
    response_text_path: a JSONPath-ish dotted/bracket path into the JSON
        response identifying where the model's reply text lives, e.g.
        "choices[0].message.content" or "reply".
    """

    uri: str
    method: HttpMethod = "post"
    headers: dict[str, str] = field(default_factory=dict)
    request_template: dict[str, Any] | None = None
    response_text_path: str = "response"
    timeout_seconds: int = 30

    def to_garak_generator_options(self) -> dict[str, Any]:
        """Translate this config into a garak `rest` generator option block."""
        opts: dict[str, Any] = {
            "rest": {
                "RestGenerator": {
                    "uri": self.uri,
                    "method": self.method,
                    "headers": self.headers,
                    "response_json": True,
                    "response_json_field": self._as_jsonpath(self.response_text_path),
                    "req_template_json_object": self.request_template
                    or {"input": "$INPUT"},
                    "request_timeout": max(self.timeout_seconds, 120),
                }
            }
        }
        return opts

    def to_promptfoo_provider(self) -> dict[str, Any]:
        """Translate this config into a promptfoo `http` provider block."""
        body = self.request_template or {"input": "{{prompt}}"}
        body_str = json.dumps(body).replace('"$INPUT"', '"{{prompt}}"')
        return {
            "id": "http",
            "config": {
                "url": self.uri,
                "method": self.method.upper(),
                "headers": self.headers,
                "body": json.loads(body_str),
                "transformResponse": self._as_promptfoo_transform(
                    self.response_text_path
                ),
            },
        }

    @staticmethod
    def _as_jsonpath(dotted: str) -> str:
        # garak expects a leading-dollar JSONPath when the field name isn't
        # a bare top-level key.
        if "." in dotted or "[" in dotted:
            return "$." + dotted
        return dotted

    @staticmethod
    def _as_promptfoo_transform(dotted: str) -> str:
        parts = dotted.replace("[", ".").replace("]", "").split(".")
        expr = "json"
        for p in parts:
            expr += f"[{p!r}]" if not p.isdigit() else f"[{p}]"
        return expr


@dataclass
class Target:
    id: str
    name: str
    description: str
    rest_config: RestTargetConfig
    authorized: bool = False
    authorized_by: str | None = None
    authorized_at: str | None = None
    tags: list[str] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @classmethod
    def create(
        cls,
        name: str,
        description: str,
        rest_config: RestTargetConfig,
        authorized_by: str,
        tags: list[str] | None = None,
    ) -> "Target":
        """
        The only constructor path for a new Target. Authorization is
        required at creation time -- there is no "register now, authorize
        later" flow, on purpose (see EXTENDED_README for the gaps this
        still leaves).
        """
        return cls(
            id=str(uuid.uuid4())[:8],
            name=name,
            description=description,
            rest_config=rest_config,
            authorized=True,
            authorized_by=authorized_by,
            authorized_at=datetime.now(timezone.utc).isoformat(),
            tags=tags or [],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "rest_config": {
                "uri": self.rest_config.uri,
                "method": self.rest_config.method,
                "headers": self.rest_config.headers,
                "request_template": self.rest_config.request_template,
                "response_text_path": self.rest_config.response_text_path,
                "timeout_seconds": self.rest_config.timeout_seconds,
            },
            "authorized": self.authorized,
            "authorized_by": self.authorized_by,
            "authorized_at": self.authorized_at,
            "tags": self.tags,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Target":
        rc = d["rest_config"]
        return cls(
            id=d["id"],
            name=d["name"],
            description=d["description"],
            rest_config=RestTargetConfig(
                uri=rc["uri"],
                method=rc.get("method", "post"),
                headers=rc.get("headers", {}),
                request_template=rc.get("request_template"),
                response_text_path=rc.get("response_text_path", "response"),
                timeout_seconds=rc.get("timeout_seconds", 30),
            ),
            authorized=d.get("authorized", False),
            authorized_by=d.get("authorized_by"),
            authorized_at=d.get("authorized_at"),
            tags=d.get("tags", []),
            created_at=d.get("created_at", ""),
        )
