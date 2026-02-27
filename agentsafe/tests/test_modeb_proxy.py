from agentsafe.integrations.model import ToolAction
from agentsafe.proxy.modeb_proxy import _route_matches, grant_scope_for_action


def test_route_matching():
    regexes = [r"^/v1/tools/execute$", r"^/api/tools/.+"]
    assert _route_matches("/v1/tools/execute", regexes)
    assert _route_matches("/api/tools/run", regexes)
    assert not _route_matches("/health", regexes)


def test_scope_string_for_shell():
    action = ToolAction(
        request_id="x",
        actor="a",
        session_id="s",
        tool="shell.run",
        args={"command": "ls -la"},
        route="/v1/tools/execute",
    )
    assert grant_scope_for_action(action) == "shell.run ls -la"
