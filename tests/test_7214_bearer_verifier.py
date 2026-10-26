"""Bearers a plugin verifies itself (C-1009, issue #7214): the run token of a governed run.

elitea_core registers a verifier for its prefix; such a bearer is decided by that verifier only and never sent to
auth_core, a refusal or a failure refuses the request (no fallback), and an accepted one runs as its user, still
subject to the admission check of that user's epochs. Any other bearer takes the path it always took.
"""
import pathlib
import sys
import types

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from test_revocation_epochs import FakeRedis, World  # noqa: E402  pylint: disable=C0413


class Clock:
    now = 1000.0

    def __call__(self):
        return self.now


class Request:
    def __init__(self, headers):
        self.headers = headers
        self.host = "platform"
        self.scheme = "http"
        self.remote_addr = "10.0.0.1"
        self.method = "POST"
        self.full_path = "/app/2/mcp/elitea_core/applications?"
        self.query_string = b""
        self.cookies = {}
        self.environ = {"marker": "environ"}


class AuthCore(World):
    """auth_core: counts the authorize calls a registered bearer must never make."""

    def __init__(self):
        super().__init__()
        self.authorize_calls = 0

    def auth_authorize(self, source, headers, cookies):
        self.authorize_calls += 1
        return {"auth_ok": True, "headers": {"X-Auth-Type": "token", "X-Auth-ID": "10"}}


@pytest.fixture
def core():
    return AuthCore()


@pytest.fixture
def auth(auth_module, core):
    module = auth_module.Module(
        types.SimpleNamespace(rpc_manager=core, event_manager=types.SimpleNamespace(fire_event=lambda *a, **k: None),
                              url_prefix=""),
        types.SimpleNamespace(config={}),
    )
    module._epoch_clock = Clock()
    module.redis = FakeRedis()
    module.get_cache_redis_client = lambda: module.redis
    module.geoip = None
    return module


@pytest.fixture
def hook(auth, auth_module, monkeypatch):
    flask_stub = auth_module.flask
    monkeypatch.setattr(flask_stub, "g", types.SimpleNamespace(), raising=False)
    monkeypatch.setattr(flask_stub, "make_response", lambda body, status: (body, status), raising=False)

    def run(headers, mode="rpc"):
        monkeypatch.setattr(flask_stub, "request", Request(headers), raising=False)
        monkeypatch.setattr(auth_module, "request", flask_stub.request, raising=False)
        auth.auth_mode = mode
        result = auth._before_request_hook()
        return result, flask_stub.g.auth

    return run


def verifier(calls, reply):
    def verify(token, environ):
        calls.append((token, environ))
        if isinstance(reply, Exception):
            raise reply
        return reply
    return verify


def test_a_registered_bearer_is_decided_by_its_verifier_and_runs_as_its_user(auth, hook, core):
    calls = []
    auth.register_bearer_verifier("eio1.", verifier(calls, {"ok": True, "user_id": 1}))
    result, identity = hook({"Authorization": "Bearer eio1.body.mac"})
    assert result is None and (identity.type, identity.id, identity.reference) == ("user", 1, "-")
    assert calls == [("eio1.body.mac", {"marker": "environ"})]
    assert core.authorize_calls == 0


@pytest.mark.parametrize("reply,status,code", [
    ({"ok": False, "status": 403, "code": "CONTEXT_NOT_LIVE", "message": "no longer admitted"}, 403, "CONTEXT_NOT_LIVE"),
    ({"ok": False, "status": 401, "code": "INTERNAL_TOKEN_EXPIRED", "message": "past"}, 401, "INTERNAL_TOKEN_EXPIRED"),
    ({"ok": True, "user_id": "1"}, 401, "INTERNAL_TOKEN_INVALID"),
    ({"ok": True, "user_id": True}, 401, "INTERNAL_TOKEN_INVALID"),
    (None, 401, "INTERNAL_TOKEN_INVALID"),
    (RuntimeError("boom"), 401, "INTERNAL_TOKEN_INVALID"),
    ({"ok": False, "status": 503, "code": "DEPENDENCY_UNAVAILABLE", "message": "try again"}, 503, "DEPENDENCY_UNAVAILABLE"),
    ({"ok": False, "status": 500, "code": "X", "message": "m"}, 401, "X"),
])
def test_a_refused_or_failing_verification_refuses_the_request_without_a_fallback(auth, hook, core, reply, status, code):
    auth.register_bearer_verifier("eio1.", verifier([], reply))
    result, identity = hook({"Authorization": "Bearer eio1.body.mac"})
    body, got_status = result
    assert got_status == status and body["error"] == code and "boom" not in str(body)
    assert identity.type == "public" and core.authorize_calls == 0


def test_a_suspended_user_is_refused_even_with_a_good_token(auth, hook, core):
    core.users[1].update(active=False, reason="user_suspended")
    auth.register_bearer_verifier("eio1.", verifier([], {"ok": True, "user_id": 1}))
    result, identity = hook({"Authorization": "Bearer eio1.body.mac"})
    assert result == ("Access Denied", 403)   # the request ends here, as for a suspended session


def test_other_bearers_take_the_usual_path(auth, hook, core):
    calls = []
    auth.register_bearer_verifier("eio1.", verifier(calls, {"ok": True, "user_id": 1}))
    result, identity = hook({"Authorization": "Bearer eyJhbGciOi.pat.value"})
    assert result is None and calls == [] and core.authorize_calls == 1
    assert (identity.type, identity.id) == ("token", 10)


def test_without_a_registered_verifier_nothing_changes(auth, hook, core):
    hook({"Authorization": "Bearer eio1.body.mac"})
    assert core.authorize_calls == 1


@pytest.mark.parametrize("prefix", ["e", "eio1", "eyJ", "Bearer ", "eio1.x", "EIO1.", ""])
def test_a_prefix_must_be_a_type_marker(auth, prefix):
    with pytest.raises(ValueError):
        auth.register_bearer_verifier(prefix, lambda token, environ: None)


def test_a_prefix_can_be_removed(auth):
    auth.register_bearer_verifier("eio1.", lambda token, environ: None)
    auth.unregister_bearer_verifier("eio1.")
    assert auth.bearer_verifiers == {}
