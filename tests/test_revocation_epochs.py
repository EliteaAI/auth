"""Bounded auth-cache staleness: revocation epochs (C-1009, issue #6944).

pylon_main used to trust its caches for up to a minute after a user was suspended,
a role removed or a token deleted. Entries are now keyed with the epoch they were
built under, the epoch is re-read every epoch_ttl seconds, and a newer epoch is a
miss. A suspended user or an expired token is refused at admission.
"""
import types

import pytest


class World:
    """auth_core as the hook sees it: epochs and the admission verdict per identity."""

    def __init__(self):
        self.users = {1: {"user": 0, "active": True, "reason": None}}
        self.tokens = {10: {"user_id": 1, "token": 0}}
        self.calls = []
        self.down = False

    def timeout(self, _seconds):
        return self

    def auth_get_revocation_epochs(self, user_id=None, token_id=None):
        self.calls.append((user_id, token_id))
        if self.down:
            raise RuntimeError("auth down")
        if token_id is not None:
            token = self.tokens.get(token_id)
            if token is None:
                return {"user": None, "token": None, "user_id": None, "active": False, "reason": "token_missing"}
            user_id = token["user_id"]
        user = self.users.get(user_id)
        if user is None:
            return {"user": None, "token": None, "user_id": user_id, "active": False, "reason": "user_missing"}
        result = {"user": user["user"], "token": None, "user_id": user_id,
                  "active": user["active"], "reason": user["reason"]}
        if token_id is not None:
            result["token"] = token["token"]
            if token.get("expired"):
                result.update(active=False, reason="token_expired")
        return result

    def bump_user(self, user_id, **changes):
        self.users[user_id]["user"] += 1
        self.users[user_id].update(changes)


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class FakeRedis:
    def __init__(self):
        self.data = {}

    def get(self, key):
        return self.data.get(key)

    def setex(self, key, _ttl, value):
        self.data[key] = value

    def delete(self, key):
        self.data.pop(key, None)


@pytest.fixture
def world():
    return World()


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def auth(auth_module, world, clock):
    module = auth_module.Module(
        types.SimpleNamespace(
            rpc_manager=world,
            event_manager=types.SimpleNamespace(fire_event=lambda *a, **k: None),
            url_prefix="",
        ),
        types.SimpleNamespace(config={}),
    )
    module._epoch_clock = clock
    module.redis = FakeRedis()
    module.get_cache_redis_client = lambda: module.redis
    return module


def make_cached(auth, calls, kind="user", id_name="user_id"):
    cache = auth.get_user_cache if kind == "user" else auth.get_token_cache

    def fetch(*args, **kwargs):
        calls.append((args, kwargs))
        return {"fetched": len(calls)}

    return auth._epoch_cached(fetch, cache, kind, id_name)


# --- the epoch read is cached for epoch_ttl --------------------------------


def test_epoch_read_is_cached_for_epoch_ttl(auth, world, clock):
    assert auth.epoch_ttl == 5.0

    assert auth._read_epochs("user", 1)["user"] == 0
    clock.now += 4.9
    auth._read_epochs("user", 1)
    assert len(world.calls) == 1

    clock.now += 0.2  # 5.1 s after the read
    auth._read_epochs("user", 1)
    assert len(world.calls) == 2


def test_a_revocation_is_visible_after_at_most_epoch_ttl(auth, world, clock):
    assert auth._identity_active("user", 1)

    world.bump_user(1, active=False, reason="user_suspended")
    assert auth._identity_active("user", 1)  # still inside the TTL: the documented bound

    clock.now += 5.1
    assert not auth._identity_active("user", 1)


def test_unreadable_epochs_fail_closed_and_are_not_cached(auth, world, clock):
    world.down = True

    assert auth._read_epochs("user", 1) is None
    assert not auth._identity_active("user", 1)

    world.down = False
    assert auth._identity_active("user", 1)  # no stale failure remembered


def test_only_users_and_tokens_with_integer_ids_have_epochs(auth, world):
    assert auth._read_epochs("public", 1) is None
    assert auth._read_epochs("user", "-") is None
    assert world.calls == []


# --- cache entries are keyed with the epoch ---------------------------------


def test_same_key_same_epoch_is_a_hit(auth):
    calls = []
    get_user = make_cached(auth, calls)

    assert get_user(1) == get_user(1)
    assert len(calls) == 1


def test_same_key_with_a_newer_epoch_is_a_miss(auth, world, clock):
    calls = []
    get_user = make_cached(auth, calls)
    get_user(1)

    world.bump_user(1)
    clock.now += 5.1
    get_user(1)

    assert len(calls) == 2


def test_token_entries_miss_on_either_the_token_or_the_owner_epoch(auth, world, clock):
    calls = []
    get_token = make_cached(auth, calls, kind="token", id_name="token_id")
    get_token(10)

    world.bump_user(1)  # owner's role changed
    clock.now += 5.1
    get_token(10)
    assert len(calls) == 2

    world.tokens[10]["token"] += 1  # token retired
    clock.now += 5.1
    get_token(10)
    assert len(calls) == 3


def test_keyword_calls_share_the_epoch_of_their_id(auth, world, clock):
    calls = []
    get_user = make_cached(auth, calls)
    get_user(user_id=1)
    get_user(user_id=1)
    assert len(calls) == 1

    world.bump_user(1)
    clock.now += 5.1
    get_user(user_id=1)
    assert len(calls) == 2


def test_cache_is_bypassed_when_the_epoch_cannot_be_read(auth, world):
    calls = []
    get_user = make_cached(auth, calls)
    world.down = True

    get_user(1)
    get_user(1)

    assert len(calls) == 2


def test_lookup_without_an_id_keeps_plain_ttl_caching(auth, world):
    calls = []
    get_user = make_cached(auth, calls)

    get_user(email="a@example.com")
    get_user(email="a@example.com")

    assert len(calls) == 1
    assert world.calls == []


# --- auth_invalidate evicts at once ------------------------------------------


def test_invalidate_event_evicts_without_waiting_for_the_ttl(auth, world, clock):
    calls = []
    get_user = make_cached(auth, calls)
    get_user(1)
    world.bump_user(1)

    auth._on_auth_invalidate(None, "auth_invalidate", {"kind": "user", "id": 1, "epoch": 1})
    get_user(1)

    assert len(calls) == 2  # no clock advance: the event dropped the epoch read
    assert auth.counters["auth_invalidate_events_total"] == 1


def test_invalidate_of_a_user_also_drops_the_epoch_reads_of_their_tokens(auth, world):
    auth._read_epochs("token", 10)
    world.bump_user(1, active=False, reason="user_suspended")

    auth._on_auth_invalidate(None, "auth_invalidate", {"kind": "user", "id": 1, "epoch": 1})

    assert not auth._identity_active("token", 10)


def test_invalidate_only_touches_the_matching_identity(auth, world):
    world.users[2] = {"user": 0, "active": True, "reason": None}
    calls = []
    get_user = make_cached(auth, calls)
    get_user(1)
    get_user(2)

    auth._on_auth_invalidate(None, "auth_invalidate", {"kind": "user", "id": 1, "epoch": 1})
    get_user(2)

    assert len(calls) == 2


def test_malformed_invalidate_payloads_are_ignored(auth):
    auth._on_auth_invalidate(None, "auth_invalidate", None)
    auth._on_auth_invalidate(None, "auth_invalidate", {"kind": "user"})

    assert auth.counters["auth_invalidate_events_total"] == 0


# --- Redis auth-result cache ----------------------------------------------------


def authorized(user_id=1, auth_type="user"):
    return {
        "auth_ok": True,
        "headers": {"X-Auth-Type": auth_type, "X-Auth-ID": str(user_id), "X-Auth-Reference": "r"},
    }


def test_cached_auth_is_stamped_with_the_epochs_and_served_while_current(auth):
    auth._set_cached_auth("k", authorized())

    assert auth._get_cached_auth("k")["headers"]["X-Auth-ID"] == "1"
    assert auth.counters["auth_epoch_mismatch_total"] == 0


def test_cached_auth_with_an_older_epoch_is_a_miss_and_is_dropped(auth, world, clock):
    auth._set_cached_auth("k", authorized())

    world.bump_user(1)
    clock.now += 5.1

    assert auth._get_cached_auth("k") is None
    assert "k" not in auth.redis.data
    assert auth.counters["auth_epoch_mismatch_total"] == 1


def test_cached_auth_without_epochs_is_not_trusted(auth):
    import json
    auth.redis.data["k"] = json.dumps(authorized())  # written by a build that predates epochs

    assert auth._get_cached_auth("k") is None


def test_inactive_identity_is_never_cached(auth, world):
    world.users[1]["active"] = False

    auth._set_cached_auth("k", authorized())

    assert auth.redis.data == {}


def test_public_results_are_cached_as_before(auth):
    auth._set_cached_auth("k", {"auth_ok": True, "headers": {"X-Auth-Type": "public"}})

    assert auth._get_cached_auth("k") is not None


def test_cached_auth_is_served_from_a_recent_read_and_refused_beyond_the_stale_bound(auth, world, clock):
    auth._set_cached_auth("k", authorized())
    world.down = True
    clock.now += 5.1  # past epoch_ttl, inside epoch_stale_max_s: the last read still vouches

    assert auth._get_cached_auth("k") is not None

    clock.now += 60  # beyond the stale bound: nothing vouches, refused
    assert auth._get_cached_auth("k") is None


# --- admission at the hook ------------------------------------------------------


class FakeRequest:
    def __init__(self, headers):
        self.headers = headers
        self.host = "platform"
        self.scheme = "https"
        self.remote_addr = "10.0.0.1"
        self.method = "GET"
        self.full_path = "/api/v1/x?"
        self.query_string = b""
        self.cookies = {}


@pytest.fixture
def hook(auth, auth_module, monkeypatch):
    flask_stub = auth_module.flask
    monkeypatch.setattr(flask_stub, "g", types.SimpleNamespace(), raising=False)

    def run(headers, mode="traefik"):
        monkeypatch.setattr(flask_stub, "request", FakeRequest(headers), raising=False)
        monkeypatch.setattr(auth_module, "request", flask_stub.request, raising=False)
        auth.auth_mode = mode
        auth.geoip = None
        result = auth._before_request_hook()
        return result, flask_stub.g.auth

    return run


def test_active_user_is_admitted(hook):
    _, identity = hook({"X-Auth-Type": "user", "X-Auth-ID": "1"})

    assert (identity.type, identity.id) == ("user", 1)


def test_suspended_user_session_is_refused_at_admission(hook, world, clock):
    """Sessions were never checked for suspension; only tokens were."""
    world.users[1].update(active=False, reason="user_suspended")

    _, identity = hook({"X-Auth-Type": "user", "X-Auth-ID": "1"})

    assert (identity.type, identity.id) == ("public", "-")


def test_expired_token_is_refused_at_admission(hook, world):
    world.tokens[10]["expired"] = True

    _, identity = hook({"X-Auth-Type": "token", "X-Auth-ID": "10"})

    assert identity.type == "public"


def test_deleted_token_is_refused_at_admission(hook, world):
    del world.tokens[10]

    _, identity = hook({"X-Auth-Type": "token", "X-Auth-ID": "10"})

    assert identity.type == "public"


def test_unreadable_epochs_refuse_admission(hook, world):
    world.down = True

    _, identity = hook({"X-Auth-Type": "user", "X-Auth-ID": "1"})

    assert identity.type == "public"


def test_public_requests_cost_no_epoch_read(hook, world):
    hook({"X-Auth-Type": "public"})

    assert world.calls == []


def test_rpc_mode_denies_a_revoked_cached_identity_and_forgets_it(hook, auth, world, clock, monkeypatch):
    key = auth._get_auth_cache_key({}, {"Authorization": "Bearer abc"})
    auth._set_cached_auth(key, authorized())
    world.bump_user(1, active=False, reason="user_suspended")
    clock.now += 5.1
    monkeypatch.setattr(auth, "access_denied_reply", lambda: "denied")
    authorize_calls = []
    world.auth_authorize = lambda *a: authorize_calls.append(a) or {"auth_ok": False, "action": "deny"}

    result, _ = hook({"Authorization": "Bearer abc"}, mode="rpc")

    assert result == "denied"
    assert key not in auth.redis.data
    assert authorize_calls, "a revoked cache entry must fall through to the authoritative authorize"


# --- permissions never outlive the verdict --------------------------------------


def test_permissions_are_empty_for_a_revoked_identity(auth, world, clock, monkeypatch):
    monkeypatch.setattr(auth, "project_id", None, raising=False)
    auth.context.rpc_manager = world
    world.project_get_id = lambda: 1
    auth.get_user_permissions = lambda *a, **k: {"some.permission"}
    who = types.SimpleNamespace(type="user", id=1)

    assert auth.resolve_permissions(auth_data=who) == {"some.permission"}

    world.bump_user(1, active=False, reason="user_suspended")
    clock.now += 5.1

    assert auth.resolve_permissions(auth_data=who) == set()


def test_a_recent_read_survives_an_auth_outage_within_epoch_stale_max(auth, world, clock):
    assert auth.epoch_stale_max_s == 60.0
    assert auth._identity_active("user", 1)  # one real read at t=1000

    world.down = True
    clock.now += 30  # past epoch_ttl, inside the stale bound: last read still counts
    assert auth._identity_active("user", 1)
    assert len(world.calls) == 2  # the retry was attempted, then the stale read served

    clock.now += 31  # 61 s after the read: beyond the bound, fail closed
    assert auth._read_epochs("user", 1) is None
    assert not auth._identity_active("user", 1)

    world.down = False
    assert auth._identity_active("user", 1)  # recovers on the next successful read


def test_no_prior_read_fails_closed_during_an_outage(auth, world):
    world.down = True
    assert auth._read_epochs("token", 10) is None
