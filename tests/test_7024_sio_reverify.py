"""A socket whose handshake authorization failed is authorized again, instead of staying anonymous (#7024).

A socket is authorized once, when it connects, and ``sio_users[sid]`` keeps the answer for its whole life.
When the auth service was down or too slow at that moment, the call failed and a user with a valid session
was stored as a logged-out one: every later send was refused until the page was reloaded, however long ago
the auth service came back.

The failure is now told apart from a real answer. A failed call leaves the socket *unverified*, keeping the
request it connected with, and the next membership check authorizes it again. A clean "not authorized"
answer (an expired cookie) is final: the same cookie would get the same answer.
"""
import queue
import types

import pytest

SOURCE_COOKIES = {"session": "abc"}
SOURCE_HEADERS = {"Authorization": "Bearer token"}


class _FakeRequest:
    def __init__(self, environ):  # pylint: disable=W0613
        self.full_path = "/socket.io/?EIO=4"
        self.query_string = b"EIO=4"
        self.method = "GET"
        self.scheme = "https"
        self.host = "dev.example"
        self.remote_addr = "10.0.0.1"
        self.headers = types.SimpleNamespace(items=lambda: SOURCE_HEADERS.items())
        self.cookies = types.SimpleNamespace(items=lambda: SOURCE_COOKIES.items())


def _authorized(user_id="42"):
    return {
        "auth_ok": True,
        "headers": {"X-Auth-Type": "user", "X-Auth-ID": user_id, "X-Auth-Reference": "ref-1"},
    }


def _refused():
    return {"auth_ok": False, "headers": {}}


class _Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


class _Plugin:
    """The parts of the plugin the socket authorization touches, with a scripted authorize RPC."""

    def __init__(self, auth_module, outcomes, cached=None):
        module = auth_module.Module
        self.auth_mode = "rpc"
        self.sio_reverify_min_interval_s = 5.0
        self.sio_users = {}
        self.clock = _Clock()
        self._sio_clock = self.clock
        self.outcomes = list(outcomes)
        self.calls = 0
        self.timeouts = []
        self.cached = cached
        self.cache_writes = []
        self.suspended = False
        self.members = {(42, 1)}
        self.during_call = None
        rpc = types.SimpleNamespace(timeout=self._timeout)
        self.context = types.SimpleNamespace(url_prefix="", rpc_manager=rpc)
        for name in ("_sio_authorize", "_sio_reverify", "sio_make_auth_data", "is_sio_user_in_project"):
            setattr(self, name, types.MethodType(getattr(module, name), self))
        self._sio_auth_data_from_status = module._sio_auth_data_from_status  # pylint: disable=W0212

    def _timeout(self, seconds):
        self.timeouts.append(seconds)
        return types.SimpleNamespace(auth_authorize=self._authorize)

    def _authorize(self, *_args):
        self.calls += 1
        if self.during_call:
            self.during_call()
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def _get_auth_cache_key(self, _cookies, _headers):
        return "auth:token:key"

    def _get_cached_auth(self, _key):
        return self.cached

    def _set_cached_auth(self, key, status):
        self.cache_writes.append((key, status))

    def is_project_suspended(self, _project_id):
        return self.suspended

    def current_user(self, auth_data=None):
        return {"id": auth_data.id if auth_data.type == "user" else None}

    def check_user_in_project(self, project_id, user_id):
        return (user_id, project_id) in self.members

    def connect(self, sid="sid-1"):
        self.sio_users[sid] = self.sio_make_auth_data({})
        return self.sio_users[sid]


@pytest.fixture
def plugin(auth_module, monkeypatch):
    monkeypatch.setattr(auth_module.flask, "Request", _FakeRequest, raising=False)

    def make(outcomes, **kwargs):
        return _Plugin(auth_module, outcomes, **kwargs)

    return make


# ---- the handshake --------------------------------------------------------------------------------------

def test_a_successful_handshake_is_a_verified_user(plugin):
    p = plugin([_authorized("42")])

    auth_data = p.connect()

    assert (auth_data.type, auth_data.id, auth_data.reference) == ("user", 42, "ref-1")
    assert not getattr(auth_data, "unverified", False)
    assert p.calls == 1


def test_a_clean_refusal_is_final_and_is_not_marked_unverified(plugin):
    """An expired cookie: the auth service answered. Asking again with the same cookie changes nothing."""
    p = plugin([_refused()])

    auth_data = p.connect()

    assert (auth_data.type, auth_data.id) == ("public", "-")
    assert not getattr(auth_data, "unverified", False)
    assert not hasattr(auth_data, "handshake")


@pytest.mark.parametrize("failure", [queue.Empty(), RuntimeError("rpc down"), TimeoutError()])
def test_a_failed_call_leaves_the_socket_unverified_and_keeps_the_request(plugin, failure):
    p = plugin([failure])

    auth_data = p.connect()

    assert (auth_data.type, auth_data.id) == ("public", "-")
    assert auth_data.unverified is True
    assert auth_data.handshake["headers"] == SOURCE_HEADERS
    assert auth_data.handshake["cookies"] == SOURCE_COOKIES
    assert auth_data.handshake["source"]["uri"] == "/socket.io/?EIO=4"


def test_the_handshake_makes_one_call_and_does_not_retry(plugin):
    p = plugin([queue.Empty(), _authorized()])

    p.connect()

    # A retry held the handshake for up to twice as long and only helped outages shorter than itself
    assert p.calls == 1
    assert p.timeouts == [15]


def test_a_cached_answer_skips_the_call(plugin):
    p = plugin([], cached=_authorized("7"))

    auth_data = p.connect()

    assert auth_data.id == 7
    assert p.calls == 0


def test_only_a_successful_answer_is_cached(plugin):
    p = plugin([_authorized()])
    p.connect()
    assert p.cache_writes == [("auth:token:key", _authorized())]

    refused = plugin([_refused()])
    refused.connect()
    assert not refused.cache_writes

    failed = plugin([queue.Empty()])
    failed.connect()
    assert not failed.cache_writes


def test_a_non_numeric_user_id_is_anonymous(plugin):
    p = plugin([_authorized("not-a-number")])

    auth_data = p.connect()

    assert (auth_data.type, auth_data.id) == ("user", "-")


# ---- authorizing again at the membership check ---------------------------------------------------------

def test_an_unverified_socket_is_authorized_again_and_then_belongs_to_its_project(plugin):
    p = plugin([queue.Empty(), _authorized("42")])
    p.connect()
    assert p.is_sio_user_in_project("sid-1", 1) is True
    assert p.calls == 2
    assert p.sio_users["sid-1"].id == 42


def test_the_replacement_does_not_keep_the_cookies(plugin):
    p = plugin([queue.Empty(), _authorized("42")])
    p.connect()

    p.is_sio_user_in_project("sid-1", 1)

    assert not hasattr(p.sio_users["sid-1"], "handshake")
    assert not getattr(p.sio_users["sid-1"], "unverified", False)


def test_the_stored_request_is_what_is_sent_again(plugin):
    p = plugin([queue.Empty(), _authorized("42")])
    sent = []
    original = p._authorize  # pylint: disable=W0212
    p._authorize = lambda *args: (sent.append(args), original(*args))[1]  # pylint: disable=W0212
    p.connect()

    p.is_sio_user_in_project("sid-1", 1)

    assert sent[0] == sent[1]


def test_a_clean_refusal_on_the_second_attempt_is_final(plugin):
    """The auth service answered this time: the cookie really is invalid, so the socket stops being retried."""
    p = plugin([queue.Empty(), _refused()])
    p.connect()

    assert p.is_sio_user_in_project("sid-1", 1) is False
    p.clock.now += 60
    assert p.is_sio_user_in_project("sid-1", 1) is False

    assert p.calls == 2
    assert not getattr(p.sio_users["sid-1"], "unverified", False)


def test_a_second_failure_keeps_the_socket_unverified_for_a_later_try(plugin):
    p = plugin([queue.Empty(), queue.Empty(), _authorized("42")])
    p.connect()

    p.clock.now += 6
    assert p.is_sio_user_in_project("sid-1", 1) is False
    assert p.sio_users["sid-1"].unverified is True

    p.clock.now += 6
    assert p.is_sio_user_in_project("sid-1", 1) is True


def test_an_outage_of_any_length_ends_when_the_auth_service_is_back(plugin):
    """The case a handshake retry could not cover: auth down for minutes, then the user sends."""
    p = plugin([queue.Empty()] + [queue.Empty()] * 5 + [_authorized("42")])
    p.connect()

    for _ in range(5):
        p.clock.now += 6
        assert p.is_sio_user_in_project("sid-1", 1) is False
    p.clock.now += 6

    assert p.is_sio_user_in_project("sid-1", 1) is True


def test_the_first_send_is_checked_at_once_however_soon_after_connecting(plugin):
    """The failed handshake call has already used its time, so the connect itself must not count against it."""
    p = plugin([queue.Empty(), _authorized("42")])
    p.connect()

    assert p.is_sio_user_in_project("sid-1", 1) is True


def test_a_burst_of_sends_makes_one_call(plugin):
    p = plugin([queue.Empty(), queue.Empty()])
    p.connect()

    for _ in range(6):
        p.clock.now += 0.5
        p.is_sio_user_in_project("sid-1", 1)

    assert p.calls == 2


def test_it_tries_again_once_the_interval_has_passed(plugin):
    p = plugin([queue.Empty(), queue.Empty(), _authorized("42")])
    p.connect()
    p.is_sio_user_in_project("sid-1", 1)

    p.clock.now += p.sio_reverify_min_interval_s + 0.1

    assert p.is_sio_user_in_project("sid-1", 1) is True
    assert p.calls == 3


def test_a_second_send_that_arrives_during_the_call_does_not_start_another(plugin):
    p = plugin([queue.Empty(), _authorized("42")])
    p.connect()
    inner = []

    def second_send():
        inner.append(p.is_sio_user_in_project("sid-1", 1))

    p.during_call = second_send
    p.clock.now += 6
    p.is_sio_user_in_project("sid-1", 1)

    assert p.calls == 2
    assert inner == [False]


def test_a_verified_user_is_never_authorized_again(plugin):
    p = plugin([_authorized("42")])
    p.connect()

    for _ in range(3):
        p.clock.now += 60
        assert p.is_sio_user_in_project("sid-1", 1) is True

    assert p.calls == 1


def test_a_verified_user_outside_the_project_is_refused_without_a_call(plugin):
    p = plugin([_authorized("42")])
    p.connect()

    assert p.is_sio_user_in_project("sid-1", 99) is False
    assert p.calls == 1


def test_a_socket_that_disconnects_during_the_call_is_not_brought_back(plugin):
    p = plugin([queue.Empty(), _authorized("42")])
    p.connect()
    p.during_call = lambda: p.sio_users.pop("sid-1")
    p.clock.now += 6

    assert p.is_sio_user_in_project("sid-1", 1) is False
    assert "sid-1" not in p.sio_users


def test_an_unknown_socket_and_a_missing_project_are_refused_without_a_call(plugin):
    p = plugin([queue.Empty()])
    p.connect()
    p.calls = 0

    assert p.is_sio_user_in_project("nobody", 1) is False
    assert p.is_sio_user_in_project("sid-1", None) is False

    assert p.calls == 0


def test_a_suspended_project_is_refused_before_any_call(plugin):
    p = plugin([queue.Empty()])
    p.connect()
    p.suspended = True
    p.calls = 0
    p.clock.now += 60

    assert p.is_sio_user_in_project("sid-1", 1) is False

    assert p.calls == 0


def test_the_interval_can_be_changed(plugin):
    p = plugin([queue.Empty(), queue.Empty(), queue.Empty(), _authorized("42")])
    p.sio_reverify_min_interval_s = 30
    p.connect()
    p.is_sio_user_in_project("sid-1", 1)
    assert p.calls == 2

    p.clock.now += 29
    p.is_sio_user_in_project("sid-1", 1)
    assert p.calls == 2

    p.clock.now += 2
    p.is_sio_user_in_project("sid-1", 1)
    assert p.calls == 3
