"""One-shot helper to register the local Ollama target."""
from llm_inspector.config import get_settings
from llm_inspector.storage.database import Database
from llm_inspector.target.manager import TargetManager

settings = get_settings()
db = Database(settings.db_path)
manager = TargetManager(db)
target = manager.register(
    name="Qwen 0.5B Local",
    description="Local Qwen 2.5 0.5B model via Ollama",
    uri="http://localhost:11434/api/chat",
    method="post",
    headers={"Content-Type": "application/json"},
    request_template={
        "model": "qwen2.5:0.5b",
        "messages": [{"role": "user", "content": "$INPUT"}],
        "stream": False,
    },
    response_text_path="message.content",
    authorized_by="you",
)
print(f"Registered target: {target.id}")
