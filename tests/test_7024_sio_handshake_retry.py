"""The socket handshake gives the authorize call a second chance (#7024).

A socket is authenticated once, at handshake, and ``sio_users[sid]`` keeps the result for the socket's
whole life. A single failed ``auth_authorize`` call (pylon_auth restarting, a flapping network) stored a
valid user as anonymous, and every chat send from that tab was then dropped until the page was refreshed.
"""
import queue
import types

import pytest

COOKIES = {"session": "abc"}
HEADERS = {"Authorization": "Bearer token"}


class _FakeRequest:
    def __init__(self, environ):  # pylint: disable=W0613
        self.full_path = "/socket.io/?EIO=4"
        self.query_string = b"EIO=4"
        self.method = "GET"
        self.scheme = "https"
        self.host = "dev.example"
        self.remote_addr = "10.0.0.1"
        self.headers = types.SimpleNamespace(items=lambda: HEADERS.items())
        self.cookies = types.SimpleNamespace(items=lambda: COOKIES.items())


def _authorized(user_id="42"):
    return {
        "auth_ok": True,
        "headers": {"X-Auth-Type": "user", "X-Auth-ID": user_id, "X-Auth-Reference": "ref-1"},
    }


class _Handshake:
    """The parts of the plugin ``sio_make_auth_data`` touches, with a scripted authorize RPC."""

    def __init__(self, outcomes, cached=None):
        self.auth_mode = "rpc"
        self.sio_authorize_retry_delay_s = 0.5
        self.sio_authorize_retry_timeout_s = 3
        self.outcomes = list(outcomes)
        self.calls = 0
        self.cached = cached
        self.cache_writes = []
        self.timeouts = []
        rpc = types.SimpleNamespace(timeout=self._timeout)
        self.context = types.SimpleNamespace(url_prefix="", rpc_manager=rpc)

    def _timeout(self, seconds):
        self.timeouts.append(seconds)
        return types.SimpleNamespace(auth_authorize=self._authorize)

    def _authorize(self, *_args):
        self.calls += 1
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


@pytest.fixture
def pauses(auth_module, monkeypatch):
    """Record the pauses instead of sleeping them."""
    recorded = []
    monkeypatch.setattr(auth_module.time, "sleep", recorded.append)
    return recorded


@pytest.fixture
def make_auth_data(auth_module, monkeypatch, pauses):  # pylint: disable=W0613
    monkeypatch.setattr(auth_module.flask, "Request", _FakeRequest, raising=False)

    def run(handshake):
        return auth_module.Module.sio_make_auth_data(handshake, {})

    return run


def test_a_failed_first_attempt_does_not_leave_the_user_anonymous(make_auth_data):
    handshake = _Handshake([queue.Empty(), _authorized("42")])

    auth_data = make_auth_data(handshake)

    assert (auth_data.type, auth_data.id, auth_data.reference) == ("user", 42, "ref-1")
    assert handshake.calls == 2


@pytest.mark.parametrize("failure", [queue.Empty(), RuntimeError("rpc down"), TimeoutError()])
def test_any_failure_of_the_call_is_retried(make_auth_data, failure):
    handshake = _Handshake([failure, _authorized()])

    assert make_auth_data(handshake).type == "user"
    assert handshake.calls == 2


def test_two_failures_leave_an_anonymous_socket(make_auth_data):
    handshake = _Handshake([queue.Empty(), queue.Empty()])

    auth_data = make_auth_data(handshake)

    assert (auth_data.type, auth_data.id, auth_data.reference) == ("public", "-", "-")
    assert handshake.calls == 2


def test_it_stops_after_two_attempts(make_auth_data):
    handshake = _Handshake([queue.Empty(), queue.Empty(), _authorized()])

    assert make_auth_data(handshake).type == "public"
    assert handshake.calls == 2


def test_a_first_attempt_that_works_is_not_repeated(make_auth_data):
    handshake = _Handshake([_authorized()])

    assert make_auth_data(handshake).type == "user"
    assert handshake.calls == 1


def test_a_refusal_is_an_answer_and_is_not_retried(make_auth_data):
    handshake = _Handshake([{"auth_ok": False, "headers": {}}, _authorized()])

    auth_data = make_auth_data(handshake)

    assert (auth_data.type, auth_data.id, auth_data.reference) == ("public", "-", "-")
    assert handshake.calls == 1


def test_the_second_attempt_is_shorter_so_the_handshake_stays_inside_the_client_limit(make_auth_data):
    handshake = _Handshake([queue.Empty(), _authorized()])

    make_auth_data(handshake)

    # The first call keeps its 15 s. The client gives up after 20 s, so the retry cannot be another 15 s.
    assert handshake.timeouts == [15, 3]


def test_the_worst_case_stays_below_the_client_connect_limit(make_auth_data, pauses):
    handshake = _Handshake([queue.Empty(), queue.Empty()])

    make_auth_data(handshake)

    worst_case = handshake.timeouts[0] + sum(pauses) + handshake.timeouts[1]
    assert worst_case < 20


def test_there_is_a_pause_before_the_second_attempt_and_none_before_the_first(make_auth_data, pauses):
    handshake = _Handshake([queue.Empty(), _authorized()])

    make_auth_data(handshake)

    assert pauses == [0.5]


def test_a_first_attempt_that_works_does_not_pause(make_auth_data, pauses):
    make_auth_data(_Handshake([_authorized()]))

    assert pauses == []


def test_the_retry_settings_can_be_changed(make_auth_data, pauses):
    handshake = _Handshake([queue.Empty(), _authorized()])
    handshake.sio_authorize_retry_delay_s = 2
    handshake.sio_authorize_retry_timeout_s = 5

    make_auth_data(handshake)

    assert handshake.timeouts == [15, 5]
    assert pauses == [2]


def test_only_a_successful_result_is_cached(make_auth_data):
    handshake = _Handshake([queue.Empty(), _authorized()])

    make_auth_data(handshake)

    assert handshake.cache_writes == [("auth:token:key", _authorized())]


def test_nothing_is_cached_when_both_attempts_fail(make_auth_data):
    handshake = _Handshake([queue.Empty(), queue.Empty()])

    make_auth_data(handshake)

    assert not handshake.cache_writes


def test_a_cached_result_skips_the_call_altogether(make_auth_data):
    handshake = _Handshake([], cached=_authorized("7"))

    auth_data = make_auth_data(handshake)

    assert auth_data.id == 7
    assert handshake.calls == 0


def test_a_non_numeric_user_id_is_anonymous_after_a_retry_too(make_auth_data):
    handshake = _Handshake([queue.Empty(), _authorized("not-a-number")])

    auth_data = make_auth_data(handshake)

    assert (auth_data.type, auth_data.id) == ("user", "-")
