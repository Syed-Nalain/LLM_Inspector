import pytest

from llm_inspector.storage.database import Database
from llm_inspector.target.manager import TargetManager, TargetNotAuthorizedError


@pytest.fixture
def manager(tmp_path):
    db = Database(tmp_path / "test.db")
    return TargetManager(db)


def test_register_and_get(manager):
    t = manager.register(
        name="Test Bot",
        description="desc",
        uri="http://example.invalid/chat",
        method="post",
        headers={},
        request_template={"input": "$INPUT"},
        response_text_path="reply",
        authorized_by="alice",
    )
    fetched = manager.get(t.id)
    assert fetched.name == "Test Bot"
    assert fetched.authorized is True
    assert fetched.authorized_by == "alice"


def test_require_authorized_raises_for_unknown_target(manager):
    with pytest.raises(KeyError):
        manager.require_authorized("does-not-exist")


def test_unauthorized_target_is_rejected(manager):
    t = manager.register(
        name="Test Bot",
        description="desc",
        uri="http://example.invalid/chat",
        method="post",
        headers={},
        request_template=None,
        response_text_path="reply",
        authorized_by="alice",
    )
    # simulate a target that lost authorization
    t.authorized = False
    manager.db.upsert_target(t.id, t.to_dict(), t.created_at)
    with pytest.raises(TargetNotAuthorizedError):
        manager.require_authorized(t.id)


def test_rest_config_to_garak_options():
    from llm_inspector.target.target import RestTargetConfig

    cfg = RestTargetConfig(
        uri="http://x/chat",
        method="post",
        headers={"A": "B"},
        request_template={"messages": [{"role": "user", "content": "$INPUT"}]},
        response_text_path="choices[0].message.content",
    )
    opts = cfg.to_garak_generator_options()
    rest_opts = opts["rest"]["RestGenerator"]
    assert rest_opts["uri"] == "http://x/chat"
    assert rest_opts["response_json_field"] == "$.choices[0].message.content"


def test_rest_config_to_promptfoo_provider():
    from llm_inspector.target.target import RestTargetConfig

    cfg = RestTargetConfig(
        uri="http://x/chat",
        method="post",
        headers={},
        request_template={"input": "$INPUT"},
        response_text_path="reply",
    )
    provider = cfg.to_promptfoo_provider()
    assert provider["config"]["url"] == "http://x/chat"
    assert provider["config"]["body"] == {"input": "{{prompt}}"}
