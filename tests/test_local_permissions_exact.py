"""auth.local_permissions holds only exact registered strings (issue #6874).

It feeds the admin Roles matrix rows and the permissions PUT allowlist. Auth used
to expand every string into its prefixes (`configuration`, `configuration.evaluation`)
left over from when has_access matched by prefix; those rows grant nothing.
"""
import types


def _fake_module():
    fake = types.SimpleNamespace(local_permissions=set(), inserted=[])
    fake.insert_permissions = fake.inserted.extend
    return fake


def test_registration_adds_only_the_exact_string(auth_module):
    fake = _fake_module()

    auth_module.Module._create_template_permissions(fake, {
        "permissions": ["configuration.evaluation.platform_dimensions.view"],
        "recommended_roles": {"administration": {"admin": True, "viewer": False}},
    })

    assert fake.local_permissions == {"configuration.evaluation.platform_dimensions.view"}
    assert ("admin", "administration", "configuration.evaluation.platform_dimensions.view") in fake.inserted
    assert not any(row[1] == "administration" and row[0] == "viewer" for row in fake.inserted)


def test_prefix_generators_are_gone(auth_module):
    assert not hasattr(auth_module, "generate_permissions_from_string")
    assert not hasattr(auth_module, "generate_permissions")


def test_registration_never_generates_developer_rows(auth_module):
    fake = _fake_module()

    auth_module.Module._create_template_permissions(fake, {
        "permissions": ["some.perm"],
        "recommended_roles": {
            "administration": {"admin": True},
            "developer": {"admin": True, "viewer": True},
        },
    })

    assert {row[1] for row in fake.inserted} == {"administration", "default"}
