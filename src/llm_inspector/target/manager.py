"""
TargetManager: registration and lookup of authorized scan targets.

This is the gate referenced in the architecture doc's Agent Runtime
("stay within the authorized target"). Claude is told which target_id it
is allowed to test, and every MCP tool call is validated against the
TargetManager before anything gets sent over the network -- see
mcp_servers/red_team/server.py.
"""

from __future__ import annotations

from llm_inspector.storage.database import Database
from llm_inspector.target.target import RestTargetConfig, Target


class TargetNotAuthorizedError(Exception):
    pass


class TargetManager:
    def __init__(self, db: Database):
        self.db = db

    def register(
        self,
        name: str,
        description: str,
        uri: str,
        method: str,
        headers: dict[str, str],
        request_template: dict | None,
        response_text_path: str,
        authorized_by: str,
        tags: list[str] | None = None,
    ) -> Target:
        target = Target.create(
            name=name,
            description=description,
            rest_config=RestTargetConfig(
                uri=uri,
                method=method,  # type: ignore[arg-type]
                headers=headers,
                request_template=request_template,
                response_text_path=response_text_path,
            ),
            authorized_by=authorized_by,
            tags=tags,
        )
        self.db.upsert_target(target.id, target.to_dict(), target.created_at)
        return target

    def get(self, target_id: str) -> Target:
        data = self.db.get_target(target_id)
        if data is None:
            raise KeyError(f"Unknown target_id: {target_id}")
        return Target.from_dict(data)

    def require_authorized(self, target_id: str) -> Target:
        target = self.get(target_id)
        if not target.authorized:
            raise TargetNotAuthorizedError(
                f"Target {target_id!r} ({target.name}) is not authorized for "
                "testing. Refusing to run any security tool against it."
            )
        return target

    def list(self) -> list[Target]:
        return [Target.from_dict(d) for d in self.db.list_targets()]
