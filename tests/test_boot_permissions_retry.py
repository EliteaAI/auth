"""Permission registration during boot survives pylon_auth still coming up.

A request published before auth_core registered `auth_insert_permissions` is lost and
surfaces as queue.Empty after the RPC proxy timeout. Restarting pylon_auth together with
pylon_main (2026-10-15) turned one such loss into a failed admin module and a cascade of
skipped dependants. The bounded retry keeps trying until a deadline, then fails loudly.
"""
import queue
import types

import pytest


def _fake(deadline_s, fail_times, exc=queue.Empty):
    calls = []

    def insert_permissions(rows):
        calls.append(rows)
        if len(calls) <= fail_times:
            raise exc()
        return "ok"

    return types.SimpleNamespace(
        insert_permissions=insert_permissions,
        permissions_rpc_deadline_s=deadline_s,
        permissions_retry_sleep_s=0,
        calls=calls,
    )


def test_retries_until_auth_answers(auth_module):
    fake = _fake(deadline_s=30, fail_times=2)

    result = auth_module.Module._insert_permissions_bounded(fake, [("admin", "default", "p")])

    assert result == "ok"
    assert len(fake.calls) == 3
    assert fake.calls[0] == [("admin", "default", "p")]


def test_gives_up_at_the_deadline_and_reraises(auth_module):
    fake = _fake(deadline_s=0, fail_times=10)

    with pytest.raises(queue.Empty):
        auth_module.Module._insert_permissions_bounded(fake, [("admin", "default", "p")])

    assert len(fake.calls) == 1


def test_template_registration_goes_through_the_bounded_path(auth_module):
    fake = _fake(deadline_s=30, fail_times=1)
    fake.local_permissions = set()
    fake._insert_permissions_bounded = lambda rows: auth_module.Module._insert_permissions_bounded(fake, rows)

    auth_module.Module._create_template_permissions(fake, {
        "permissions": ["some.perm"],
        "recommended_roles": {"administration": {"admin": True}},
    })

    assert len(fake.calls) == 2
    assert fake.local_permissions == {"some.perm"}
