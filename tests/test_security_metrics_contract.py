"""Contract of the security metrics accessor copy in this plugin (C-1009, #6754).

``security_metrics_client.py`` duplicates the accessor of the tracing plugin. The values below are the
contract: the same vectors are pinned in tracing, auth, indexer_worker and elitea_core, so a change to the
line format, the token rules, the label allow-list or the rate cap has to be made in all four places.
"""
import importlib.util
import pathlib
import sys
import types

import pytest

PLUGIN_ROOT = pathlib.Path(__file__).resolve().parent.parent

# What this plugin declares: metric name -> label keys.
DECLARED = {"auth_epoch_mismatch_total": (), "auth_invalidate_events_total": ()}


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def client(monkeypatch):
    """The accessor in its local-fallback mode: no tracing tool, lines captured from pylon's log."""
    lines = []
    monkeypatch.setitem(sys.modules, "tools", types.ModuleType("tools"))
    monkeypatch.setitem(sys.modules, "pylon.core.tools",
                        types.SimpleNamespace(log=types.SimpleNamespace(info=lambda msg, *a: lines.append(msg))))
    spec = importlib.util.spec_from_file_location("security_metrics_client_under_test",
                                                  PLUGIN_ROOT / "security_metrics_client.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module._clock = Clock()
    module.lines = lines
    return module


def test_pinned_constants(client):
    assert (client.ALLOWED_LABEL_KEYS, client.MAX_LABEL_VALUE_LEN, client.LOG_INTERVAL_S) == (
        frozenset({"capability"}), 64, 10.0)


def test_line_format_token_rules_and_rate_cap(client):
    plain = client.SecurityCounter("auth_epoch_mismatch_total", "d")
    labelled = client.SecurityCounter("worker_capability_reject_total", "d", ("capability",))

    plain.inc()
    labelled.inc(capability="task_envelope.v1")
    labelled.inc(capability="x y=1\nz")
    plain.inc()
    plain.inc()
    client._clock.t += 10
    plain.inc()
    labelled.inc(capability="")
    labelled.inc(capability="é" * 100)

    assert client.lines == [
        "security_metric name=auth_epoch_mismatch_total value=1",
        "security_metric name=worker_capability_reject_total value=1 capability=task_envelope.v1",
        "security_metric name=worker_capability_reject_total value=1 capability=x_y_1_z",
        "security_metric name=auth_epoch_mismatch_total value=3",
        "security_metric name=worker_capability_reject_total value=1 capability=-",
        "security_metric name=worker_capability_reject_total value=1 capability=" + "_" * 64,
    ]
    assert plain.total() == 4 and labelled.total() == 4


@pytest.mark.parametrize("key", ["user_id", "project_id", "token", "reason"])
def test_label_keys_outside_the_allow_list_are_refused(client, key):
    with pytest.raises(ValueError):
        client.SecurityCounter("m_total", "d", (key,))


def test_wrong_labels_are_a_caller_error(client):
    counter = client.SecurityCounter("m_total", "d", ("capability",))

    with pytest.raises(ValueError):
        counter.inc()
    with pytest.raises(ValueError):
        counter.inc(capability="a", extra="b")
    assert counter.total() == 0 and client.lines == []


def test_declared_counters_match_the_contract(auth_module):
    module = auth_module.Module(types.SimpleNamespace(rpc_manager=None, event_manager=None, url_prefix=""),
                                types.SimpleNamespace(config={}))

    assert {name: counter.labels for name, counter in module.counters.items()} == DECLARED
