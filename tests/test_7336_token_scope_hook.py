"""What an API token may do on a request (C-1009, #7336): the registered token scope checker.

elitea_core registers the checker (governance and the route table are its); the hook asks it for every request an
admitted API token makes, after the token's own admission (its epochs). Without a checker, and for any caller that is
not a token, the hook is what it was. A refusal or a failing checker refuses the request; the token is not checked again.
The REST create endpoint checks a scope before auth_core does.
"""
import datetime
import importlib.util
import pathlib
import sys
import types

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from test_7214_bearer_verifier import AuthCore, auth, core, hook, verifier  # noqa: E402,F401  pylint: disable=C0413,W0611


class Checker:
    def __init__(self, reply=None):
        self.reply, self.calls = reply, []

    def __call__(self, token_id):
        self.calls.append(token_id)
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


def test_without_a_checker_a_token_request_is_unchanged(auth, hook):
    result, identity = hook({"Authorization": "Bearer pat"})
    assert result is None and (identity.type, identity.id) == ("token", 10)


def test_a_token_request_the_checker_allows_passes_as_before(auth, hook):
    checker = Checker()
    auth.register_token_scope_checker(checker)

    result, identity = hook({"Authorization": "Bearer pat"})
    assert result is None and (identity.type, identity.id) == ("token", 10) and checker.calls == [10]


@pytest.mark.parametrize("reply, status, code", [
    ({"status": 403, "code": "TOKEN_SCOPE_PROJECT", "message": "Not this project"}, 403, "TOKEN_SCOPE_PROJECT"),
    ({"status": 403, "code": "TOKEN_SCOPE_OPERATION", "message": "Not this operation"}, 403, "TOKEN_SCOPE_OPERATION"),
    ({"status": 503, "code": "DEPENDENCY_UNAVAILABLE", "message": "later"}, 503, "DEPENDENCY_UNAVAILABLE"),
    ({"status": 200, "code": "X", "message": "m"}, 403, "X"),                 # a refusal is never a success
    ("refused", 403, "TOKEN_SCOPE_OPERATION"),
    (RuntimeError("secret-in-error"), 503, "DEPENDENCY_UNAVAILABLE"),         # a failing checker fails closed
])
def test_a_refusal_or_a_failure_of_the_checker_refuses_the_request(auth, hook, reply, status, code):
    auth.register_token_scope_checker(Checker(reply))

    result, identity = hook({"Authorization": "Bearer pat"})
    body, got_status = result
    assert (got_status, body["error"]) == (status, code) and body["message"] and "secret" not in str(body)
    assert identity.type == "public"


def test_a_session_or_a_public_caller_never_reaches_the_checker(auth, hook, core):
    checker = Checker({"status": 403, "code": "TOKEN_SCOPE_PROJECT", "message": "no"})
    auth.register_token_scope_checker(checker)
    core.auth_authorize = lambda source, headers, cookies: {"auth_ok": True, "headers": {"X-Auth-Type": "user",
                                                                                          "X-Auth-ID": "1"}}
    assert hook({})[0] is None
    core.auth_authorize = lambda source, headers, cookies: {"auth_ok": True, "headers": {}}
    assert hook({})[0] is None
    assert checker.calls == []


def test_a_run_token_bearer_never_reaches_the_checker(auth, hook):
    checker = Checker({"status": 403, "code": "TOKEN_SCOPE_PROJECT", "message": "no"})
    auth.register_token_scope_checker(checker)
    auth.register_bearer_verifier("eio1.", verifier([], {"ok": True, "user_id": 1}))

    assert hook({"Authorization": "Bearer eio1.body.mac"})[0] is None and checker.calls == []


def test_a_revoked_token_is_refused_by_its_epochs_before_the_checker(auth, hook, core):
    checker = Checker()
    auth.register_token_scope_checker(checker)
    core.tokens[10]["expired"] = True

    assert hook({"Authorization": "Bearer pat"})[0] == ("Access Denied", 403) and checker.calls == []


def test_unregistering_stops_the_check(auth, hook):
    checker = Checker({"status": 403, "code": "TOKEN_SCOPE_PROJECT", "message": "no"})
    auth.register_token_scope_checker(checker)
    auth.unregister_token_scope_checker(Checker())   # someone else's: kept
    assert hook({"Authorization": "Bearer pat"})[0] is not None
    auth.unregister_token_scope_checker(checker)
    assert hook({"Authorization": "Bearer pat"})[0] is None


def test_a_checker_must_be_callable(auth):
    with pytest.raises(ValueError):
        auth.register_token_scope_checker("not callable")


# --- the REST create endpoint ------------------------------------------------------------------

@pytest.fixture
def token_api(auth_module, monkeypatch):
    members = {5, 7}
    tools = types.ModuleType("tools")
    tools.auth = types.SimpleNamespace(
        check_user_in_projects=lambda ids, user_id: [item for item in ids if item in members])
    tools.api_tools = types.SimpleNamespace(APIBase=object)
    monkeypatch.setitem(sys.modules, "tools", tools)
    monkeypatch.setattr(auth_module.flask, "jsonify", lambda value: value, raising=False)
    package = auth_module.__name__.rsplit(".", 1)[0]
    spec = importlib.util.spec_from_file_location(
        f"{package}.api.v2.token", pathlib.Path(auth_module.__file__).parent / "api" / "v2" / "token.py")
    module = importlib.util.module_from_spec(spec)
    for name in (f"{package}.api", f"{package}.api.v2"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    spec.loader.exec_module(module)
    return module


def soon(days=30):
    return datetime.datetime.now() + datetime.timedelta(days=days)


def test_an_unscoped_token_needs_no_scope_check(token_api):
    assert token_api._scope_error(9, None, None, None) is None   # pylint: disable=W0212


def test_a_scope_on_the_creators_projects_is_accepted(token_api):
    assert token_api._scope_error(9, soon(90), [5, 7], ["run", "build"]) is None   # pylint: disable=W0212


@pytest.mark.parametrize("expires, projects, operations, fragment", [
    ("soon", [5, 6], ["run"], "projects you are a member of"),
    ("soon", [404], ["run"], "projects you are a member of"),
    ("soon", [], ["run"], "scope_projects"),
    ("soon", ["5"], ["run"], "scope_projects"),
    ("soon", None, ["run"], "scope_projects"),
    ("soon", [5], [], "scope_operations"),
    ("soon", [5], ["deploy"], "scope_operations"),
    ("soon", [5], None, "scope_operations"),
    (None, [5], ["run"], "needs an expiry"),
    ({}, [5], ["run"], "needs an expiry"),
    ("far", [5], ["run"], "within 90 days"),
    ("past", [5], ["run"], "within 90 days"),
])
def test_an_invalid_scope_is_a_readable_refusal(token_api, expires, projects, operations, fragment):
    moment = {"soon": soon(), "far": soon(91), "past": soon(-1)}.get(expires, expires) \
        if isinstance(expires, str) else expires
    assert fragment in token_api._scope_error(9, moment, projects, operations)   # pylint: disable=W0212
