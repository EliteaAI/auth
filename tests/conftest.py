"""Import the auth plugin as a package with its pylon/runtime deps stubbed."""
import importlib.util
import pathlib
import sys
import types

import pytest

PLUGIN_ROOT = pathlib.Path(__file__).resolve().parent.parent
PACKAGE = "auth_plugin_under_test"


def _stub(name, **attrs):
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    return module


@pytest.fixture(scope="session")
def auth_module():
    class Log:
        def __getattr__(self, _name):
            return lambda *a, **k: None

    stubs = {
        "flask": _stub("flask", request=None, make_response=None),
        "redis": _stub("redis"),
        "cachetools": _stub("cachetools"),
        "pygeoip": _stub("pygeoip"),
        "pylon": _stub("pylon"),
        "pylon.core": _stub("pylon.core"),
        "pylon.core.tools": _stub("pylon.core.tools", log=Log(), module=_stub("m", ModuleModel=object)),
        "pylon.core.tools.context": _stub("pylon.core.tools.context", Context=types.SimpleNamespace),
    }
    saved = {name: sys.modules.get(name) for name in stubs}
    sys.modules.update(stubs)

    package = types.ModuleType(PACKAGE)
    package.__path__ = [str(PLUGIN_ROOT)]
    sys.modules[PACKAGE] = package
    spec = importlib.util.spec_from_file_location(f"{PACKAGE}.module", PLUGIN_ROOT / "module.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        for name in [n for n in sys.modules if n.startswith(PACKAGE)]:
            sys.modules.pop(name)
        for name, previous in saved.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
