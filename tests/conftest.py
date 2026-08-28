from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples"))

from mock_target_server import Handler  # noqa: E402
from http.server import ThreadingHTTPServer  # noqa: E402


@pytest.fixture
def mock_target():
    """Starts the in-repo mock LLM target on an ephemeral local port.

    Yields (base_url, set_mode) where set_mode('safe'|'vulnerable') can be
    called at any point in the test to change the mock's personality.
    """
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    Handler.mode = "vulnerable"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    def set_mode(mode: str) -> None:
        Handler.mode = mode

    try:
        yield f"http://127.0.0.1:{port}/chat", set_mode
    finally:
        server.shutdown()
        server.server_close()
