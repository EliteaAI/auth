"""Identity verifier (C-1009, #6756): evidence -> VerifiedPrincipal | TypedRejection.

Tokens are signed in-test with a freshly generated RSA key; the verifier sees the
public half through a StaticKeySource and a frozen clock. The auth module's
dependencies (epochs, session context, user link) are plain-attribute stubs.
"""
import json
import pathlib
import subprocess
import sys
import textwrap
import types

import pytest

jwt = pytest.importorskip("jwt")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from pydantic import ValidationError  # noqa: E402

PLUGIN_ROOT = pathlib.Path(__file__).resolve().parent.parent

NOW = 1_800_000_000.0
TENANT = "11111111-2222-3333-4444-555555555555"
OID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
ISSUER = f"https://login.microsoftonline.com/{TENANT}/v2.0"
AUDIENCE = "api://elitea-api-test"
WORKLOAD_ISS = "https://workload.example.test"
WORKLOAD_AUD = "elitea:governed-ops"
COOKIE = "session-cookie-value-xyz"
USER_ID = 7
KINDS = frozenset({"session_user", "workload", "legacy_pat"})


def _keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ).decode()
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private, public


PRIVATE, PUBLIC = _keypair()
OTHER_PRIVATE, _ = _keypair()


@pytest.fixture
def mods(auth_module):
    package = auth_module.__name__.rsplit(".", 1)[0]
    return types.SimpleNamespace(
        verifier=sys.modules[f"{package}.utils.identity_verifier"],
        identity=sys.modules[f"{package}.models.pd.identity"],
    )


def session_claims(**overrides):
    claims = {
        "iss": ISSUER, "aud": AUDIENCE, "tid": TENANT, "oid": OID,
        "nbf": NOW - 10, "exp": NOW + 3600, "uti": "uti-1",
    }
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


def workload_claims(**overrides):
    claims = {"iss": WORKLOAD_ISS, "aud": WORKLOAD_AUD, "sub": "svc-1", "exp": NOW + 3600, "nbf": NOW - 10}
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


def sign(claims, key=PRIVATE, alg="RS256", kid="k1"):
    return jwt.encode(claims, key, algorithm=alg, headers={"kid": kid} if kid else None)


class FakeAuth:
    """The three things the verifier asks the auth module for."""

    def __init__(self):
        self.calls = []
        self.epochs = {"user": 3, "token": None, "user_id": USER_ID, "active": True, "reason": None}
        self.context = {
            "user_id": USER_ID,
            "provider_attr": {
                "delegation": {"access_token": sign(session_claims())},
                "identity": {"tid": TENANT, "oid": OID},
            },
        }
        self.linked = {"id": USER_ID}
        self.fail = set()

    def _call(self, name, *args):
        self.calls.append((name, args))
        if name in self.fail:
            raise RuntimeError(f"{name} is down: secret-in-error-text")

    def read_identity_epochs(self, kind, auth_id):
        self._call("read_identity_epochs", kind, auth_id)
        return self.epochs

    def get_referenced_auth_context(self, auth_reference):
        self._call("get_referenced_auth_context", auth_reference)
        return self.context

    def get_user_by_idp_subject(self, issuer, tid, oid):
        self._call("get_user_by_idp_subject", issuer, tid, oid)
        return self.linked

    def set_token(self, token):
        self.context["provider_attr"]["delegation"] = {"access_token": token}

    def called(self, name):
        return [c for c in self.calls if c[0] == name]


SETTINGS = {
    "session_user": {
        "tenant_id": TENANT, "audience": AUDIENCE,
        "jwks_uri": f"https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys",
        "leeway_s": 60,
    },
    "workload": {
        "issuer": WORKLOAD_ISS, "jwks_uri": "https://workload.example.test/jwks",
        "audiences": {"governed_ops": WORKLOAD_AUD},
    },
}


class Clock:
    def __init__(self):
        self.now = NOW

    def __call__(self):
        return self.now


@pytest.fixture
def auth():
    return FakeAuth()


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def build(mods, auth, clock):
    def make(section=SETTINGS, key_sources=None):
        sources = key_sources if key_sources is not None else {
            "session_user": mods.verifier.StaticKeySource({"k1": PUBLIC}),
            "workload": mods.verifier.StaticKeySource({"k1": PUBLIC}),
        }
        return mods.verifier.IdentityVerifier(
            mods.verifier.load_verifier_settings(section), auth_module=auth, clock=clock, key_sources=sources,
        )
    return make


@pytest.fixture
def verifier(build):
    return build()


def session_evidence(mods, user_id=USER_ID):
    return mods.identity.SessionUserEvidence(kind="session_user", user_id=user_id, auth_reference=COOKIE)


def workload_evidence(mods, token, use="governed_ops"):
    return mods.identity.WorkloadEvidence(kind="workload", token=token, use=use)


def verify_session(mods, verifier, kinds=KINDS):
    return verifier.verify(session_evidence(mods), admitted_kinds=kinds)


def assert_rejected(result, code):
    assert type(result).__name__ == "TypedRejection", result
    assert result.reason_code == code


def assert_verified(result):
    assert type(result).__name__ == "VerifiedPrincipal", result


# --- session_user: the happy path ---------------------------------------------


def test_valid_session_user_is_verified(mods, auth, verifier):
    principal = verify_session(mods, verifier)

    assert_verified(principal)
    assert (principal.kind, principal.user_id, principal.subject_ref) == ("user", USER_ID, f"user:{USER_ID}")
    evidence = principal.evidence
    assert (evidence.type, evidence.issuer, evidence.tid, evidence.oid) == ("verified_user", ISSUER, TENANT, OID)
    assert (evidence.delegation_ref, evidence.audience) == ("uti-1", AUDIENCE)
    assert principal.expires_at.timestamp() == NOW + 3600
    assert principal.epochs == {"user": 3, "token": None}
    assert auth.called("read_identity_epochs") == [("read_identity_epochs", ("user", USER_ID))]
    assert auth.called("get_referenced_auth_context") == [("get_referenced_auth_context", (COOKIE,))]
    assert auth.called("get_user_by_idp_subject") == [("get_user_by_idp_subject", (ISSUER, TENANT, OID))]


def test_the_injected_clock_decides_expiry(mods, verifier, clock):
    assert_verified(verify_session(mods, verifier))
    clock.now = NOW + 3600 + 61  # past exp + leeway
    assert_rejected(verify_session(mods, verifier), "IDENTITY_EXPIRED")


# --- session_user: one negative per rule --------------------------------------


def test_kind_not_admitted(mods, verifier):
    assert_rejected(verify_session(mods, verifier, kinds=frozenset({"workload"})), "IDENTITY_KIND_NOT_ADMITTED")
    assert_rejected(verify_session(mods, verifier, kinds=frozenset()), "IDENTITY_KIND_NOT_ADMITTED")


@pytest.mark.parametrize("section", [None, {}, {"workload": SETTINGS["workload"]}])
def test_kind_without_settings_is_not_admitted_even_when_listed(mods, build, auth, section):
    verifier = build(section)

    assert not verifier.configured("session_user")
    assert_rejected(verify_session(mods, verifier), "IDENTITY_KIND_NOT_ADMITTED")
    assert auth.calls == []


def test_inactive_identity_is_revoked_and_nothing_else_is_asked(mods, auth, verifier):
    auth.epochs = {"user": 4, "token": None, "user_id": USER_ID, "active": False, "reason": "user_suspended"}

    assert_rejected(verify_session(mods, verifier), "IDENTITY_REVOKED")
    assert auth.called("get_referenced_auth_context") == []


@pytest.mark.parametrize(
    "dependency", ["read_identity_epochs", "get_referenced_auth_context", "get_user_by_idp_subject"],
)
def test_a_failing_dependency_is_dependency_unavailable(mods, auth, verifier, dependency):
    auth.fail.add(dependency)

    assert_rejected(verify_session(mods, verifier), "DEPENDENCY_UNAVAILABLE")


def test_unreadable_epochs_are_dependency_unavailable(mods, auth, verifier):
    auth.epochs = None

    assert_rejected(verify_session(mods, verifier), "DEPENDENCY_UNAVAILABLE")


@pytest.mark.parametrize("context", [
    {},
    {"provider_attr": {}},
    {"provider_attr": {"delegation": None}},
    {"provider_attr": {"delegation": {}}},
    {"provider_attr": {"delegation": {"access_token": ""}}},
    {"provider_attr": {"delegation": {"access_token": 5}}},
    None,
])
def test_no_delegated_token_is_evidence_missing(mods, auth, verifier, context):
    auth.context = context

    assert_rejected(verify_session(mods, verifier), "IDENTITY_EVIDENCE_MISSING")


def test_session_of_another_user_is_unlinked(mods, auth, verifier):
    auth.context["user_id"] = USER_ID + 1

    assert_rejected(verify_session(mods, verifier), "IDENTITY_SUBJECT_UNLINKED")


def test_signature_by_another_key_is_invalid(mods, auth, verifier):
    auth.set_token(sign(session_claims(), key=OTHER_PRIVATE))

    assert_rejected(verify_session(mods, verifier), "IDENTITY_SIGNATURE_INVALID")


def test_unknown_or_absent_kid_is_invalid(mods, auth, verifier):
    auth.set_token(sign(session_claims(), kid="other"))
    assert_rejected(verify_session(mods, verifier), "IDENTITY_SIGNATURE_INVALID")

    auth.set_token(sign(session_claims(), kid=None))
    assert_rejected(verify_session(mods, verifier), "IDENTITY_SIGNATURE_INVALID")


def test_alg_none_is_refused(mods, auth, verifier):
    auth.set_token(jwt.encode(session_claims(), None, algorithm="none", headers={"kid": "k1"}))

    assert_rejected(verify_session(mods, verifier), "IDENTITY_SIGNATURE_INVALID")


def test_hs256_is_refused(mods, auth, verifier):
    auth.set_token(jwt.encode(session_claims(), "x" * 48, algorithm="HS256", headers={"kid": "k1"}))

    assert_rejected(verify_session(mods, verifier), "IDENTITY_SIGNATURE_INVALID")


@pytest.mark.parametrize("token", ["not.a.jwt", "garbage"])
def test_a_token_that_is_not_a_jwt_is_invalid(mods, auth, verifier, token):
    auth.set_token(token)

    assert_rejected(verify_session(mods, verifier), "IDENTITY_SIGNATURE_INVALID")


def test_an_unreachable_key_source_is_dependency_unavailable(mods, build):
    class Down:
        def signing_key(self, token):
            raise mods.verifier.KeyUnavailable()

    verifier = build(key_sources={"session_user": Down()})

    assert_rejected(verify_session(mods, verifier), "DEPENDENCY_UNAVAILABLE")


def test_expired_beyond_leeway_is_refused_within_leeway_accepted(mods, auth, verifier):
    auth.set_token(sign(session_claims(exp=NOW - 61)))
    assert_rejected(verify_session(mods, verifier), "IDENTITY_EXPIRED")

    auth.set_token(sign(session_claims(exp=NOW - 59)))
    assert_verified(verify_session(mods, verifier))


def test_not_yet_valid_beyond_leeway_is_refused_within_leeway_accepted(mods, auth, verifier):
    auth.set_token(sign(session_claims(nbf=NOW + 61)))
    assert_rejected(verify_session(mods, verifier), "IDENTITY_EXPIRED")

    auth.set_token(sign(session_claims(nbf=NOW + 59)))
    assert_verified(verify_session(mods, verifier))


@pytest.mark.parametrize("missing", ["exp", "nbf"])
def test_a_token_without_a_time_window_is_refused(mods, auth, verifier, missing):
    auth.set_token(sign(session_claims(**{missing: None})))

    assert_rejected(verify_session(mods, verifier), "IDENTITY_EXPIRED")


def test_non_numeric_times_are_refused(mods, auth, verifier):
    auth.set_token(sign(session_claims(exp="soon")))

    assert_rejected(verify_session(mods, verifier), "IDENTITY_EXPIRED")


@pytest.mark.parametrize("aud", ["api://another", None, ["api://another"]])
def test_wrong_or_missing_audience(mods, auth, verifier, aud):
    auth.set_token(sign(session_claims(aud=aud)))

    assert_rejected(verify_session(mods, verifier), "IDENTITY_AUDIENCE_MISMATCH")


def test_wrong_issuer_tenant(mods, auth, verifier):
    other = "99999999-2222-3333-4444-555555555555"
    auth.set_token(sign(session_claims(iss=f"https://login.microsoftonline.com/{other}/v2.0")))

    assert_rejected(verify_session(mods, verifier), "IDENTITY_TENANT_MISMATCH")


def test_wrong_tid_claim(mods, auth, verifier):
    auth.set_token(sign(session_claims(tid="99999999-2222-3333-4444-555555555555")))

    assert_rejected(verify_session(mods, verifier), "IDENTITY_TENANT_MISMATCH")


def test_missing_tid_or_oid(mods, auth, verifier):
    auth.set_token(sign(session_claims(tid=None)))
    assert_rejected(verify_session(mods, verifier), "IDENTITY_TENANT_MISMATCH")

    auth.set_token(sign(session_claims(oid=None)))
    assert_rejected(verify_session(mods, verifier), "IDENTITY_SUBJECT_UNLINKED")


def test_nobody_is_linked_to_the_token_subject(mods, auth, verifier):
    auth.linked = None

    assert_rejected(verify_session(mods, verifier), "IDENTITY_SUBJECT_UNLINKED")


def test_the_subject_is_linked_to_another_user(mods, auth, verifier):
    auth.linked = {"id": USER_ID + 1}

    assert_rejected(verify_session(mods, verifier), "IDENTITY_SUBJECT_UNLINKED")


@pytest.mark.parametrize("identity", [
    None, {}, {"tid": TENANT}, {"tid": TENANT, "oid": "someone-else"}, {"tid": "other", "oid": OID},
])
def test_the_session_identity_must_match_the_token(mods, auth, verifier, identity):
    auth.context["provider_attr"]["identity"] = identity

    assert_rejected(verify_session(mods, verifier), "IDENTITY_SUBJECT_UNLINKED")


def test_the_first_failing_step_wins(mods, auth, verifier):
    auth.epochs = {"user": 4, "token": None, "user_id": USER_ID, "active": False, "reason": "x"}
    auth.set_token("garbage")

    assert_rejected(verify_session(mods, verifier), "IDENTITY_REVOKED")


def test_an_unexpected_error_fails_closed(mods, auth, verifier):
    auth.set_token(sign(session_claims(exp=1e30)))  # a time no datetime can hold

    assert_rejected(verify_session(mods, verifier), "DEPENDENCY_UNAVAILABLE")


# --- workload -------------------------------------------------------------------


def test_valid_workload(mods, verifier):
    principal = verifier.verify(workload_evidence(mods, sign(workload_claims())), admitted_kinds=KINDS)

    assert_verified(principal)
    assert (principal.kind, principal.user_id, principal.evidence) == ("workload", None, None)
    assert principal.subject_ref == f"workload:{WORKLOAD_ISS}#svc-1"
    assert principal.expires_at.timestamp() == NOW + 3600


def test_workload_use_must_be_known(mods, verifier):
    result = verifier.verify(workload_evidence(mods, sign(workload_claims()), use="other"), admitted_kinds=KINDS)

    assert_rejected(result, "IDENTITY_AUDIENCE_MISMATCH")


def test_workload_audience_is_exact(mods, verifier):
    result = verifier.verify(
        workload_evidence(mods, sign(workload_claims(aud="elitea:governed-ops-x"))), admitted_kinds=KINDS,
    )

    assert_rejected(result, "IDENTITY_AUDIENCE_MISMATCH")


def test_workload_issuer_is_exact(mods, verifier):
    result = verifier.verify(
        workload_evidence(mods, sign(workload_claims(iss="https://evil.example.test"))), admitted_kinds=KINDS,
    )

    assert_rejected(result, "IDENTITY_TENANT_MISMATCH")


def test_workload_bad_signature_expired_and_not_admitted(mods, verifier):
    bad = workload_evidence(mods, sign(workload_claims(), key=OTHER_PRIVATE))
    assert_rejected(verifier.verify(bad, admitted_kinds=KINDS), "IDENTITY_SIGNATURE_INVALID")

    expired = workload_evidence(mods, sign(workload_claims(exp=NOW - 120)))
    assert_rejected(verifier.verify(expired, admitted_kinds=KINDS), "IDENTITY_EXPIRED")

    valid = workload_evidence(mods, sign(workload_claims()))
    assert_rejected(verifier.verify(valid, admitted_kinds=frozenset({"session_user"})), "IDENTITY_KIND_NOT_ADMITTED")


def test_workload_without_a_subject_is_refused(mods, verifier):
    result = verifier.verify(workload_evidence(mods, sign(workload_claims(sub=None))), admitted_kinds=KINDS)

    assert type(result).__name__ == "TypedRejection"


# --- legacy_pat -----------------------------------------------------------------


def pat(mods, token_id=10):
    return mods.identity.LegacyPatEvidence(kind="legacy_pat", token_id=token_id)


def test_legacy_pat_is_denied_unless_admitted(mods, auth, verifier):
    result = verifier.verify(pat(mods), admitted_kinds=frozenset({"session_user"}))

    assert_rejected(result, "IDENTITY_KIND_NOT_ADMITTED")
    assert auth.calls == []


def test_legacy_pat_admitted_yields_an_asserted_user(mods, auth, verifier):
    auth.epochs = {"user": 3, "token": 5, "user_id": USER_ID, "active": True, "reason": None}

    principal = verifier.verify(pat(mods), admitted_kinds=frozenset({"legacy_pat"}))

    assert (principal.kind, principal.user_id) == ("legacy_pat", USER_ID)
    assert principal.evidence.type == "asserted_user"
    assert (principal.evidence.issuer, principal.evidence.subject) == ("elitea:pat", f"user:{USER_ID}")
    assert principal.epochs == {"user": 3, "token": 5}
    assert auth.called("read_identity_epochs") == [("read_identity_epochs", ("token", 10))]


def test_legacy_pat_needs_no_settings(mods, build):
    verifier = build(None)

    assert verifier.configured("legacy_pat")
    assert_verified(verifier.verify(pat(mods), admitted_kinds=frozenset({"legacy_pat"})))


def test_legacy_pat_revoked_or_unreadable(mods, auth, verifier):
    auth.epochs = {"user": 3, "token": 5, "user_id": USER_ID, "active": False, "reason": "token_expired"}
    assert_rejected(verifier.verify(pat(mods), admitted_kinds=KINDS), "IDENTITY_REVOKED")

    auth.epochs = None
    assert_rejected(verifier.verify(pat(mods), admitted_kinds=KINDS), "DEPENDENCY_UNAVAILABLE")


# --- config -----------------------------------------------------------------------


def settings_with(**session_overrides):
    return {"session_user": dict(SETTINGS["session_user"], **session_overrides)}


@pytest.mark.parametrize("tenant", ["common", "organizations", "consumers", "", "not-a-guid", f"{{{TENANT}}}"])
def test_non_guid_tenants_are_refused(mods, tenant):
    with pytest.raises(ValueError):
        mods.verifier.load_verifier_settings(settings_with(tenant_id=tenant))


@pytest.mark.parametrize("override", [
    {"jwks_uri": "http://login.microsoftonline.com/keys"},
    {"jwks_uri": "login.microsoftonline.com/keys"},
    {"jwks_uri": "https://"},
    {"leeway_s": -1},
    {"leeway_s": 301},
    {"leeway_s": 1.5},
    {"audience": ""},
    {"algorithms": ["HS256"]},
    {"algorithms": ["none"]},
    {"algorithms": []},
    {"unknown_key": 1},
])
def test_bad_session_user_settings_are_refused(mods, override):
    with pytest.raises(ValueError):
        mods.verifier.load_verifier_settings(settings_with(**override))


@pytest.mark.parametrize("workload", [
    {"issuer": "", "jwks_uri": "https://w.test/jwks", "audiences": {"a": "b"}},
    {"issuer": "i", "jwks_uri": "http://w.test/jwks", "audiences": {"a": "b"}},
    {"issuer": "i", "jwks_uri": "https://w.test/jwks", "audiences": {}},
    {"issuer": "i", "jwks_uri": "https://w.test/jwks", "audiences": {"a": ""}},
    {"issuer": "i", "jwks_uri": "https://w.test/jwks"},
])
def test_bad_workload_settings_are_refused(mods, workload):
    with pytest.raises(ValueError):
        mods.verifier.load_verifier_settings({"workload": workload})


def test_unknown_sections_and_non_mappings_are_refused(mods):
    with pytest.raises(ValueError):
        mods.verifier.load_verifier_settings({"session_usr": {}})
    with pytest.raises(ValueError):
        mods.verifier.load_verifier_settings(["session_user"])


def test_absent_section_configures_nothing(mods):
    settings = mods.verifier.load_verifier_settings(None)

    assert (settings.session_user, settings.workload) == (None, None)


def test_valid_settings_and_defaults(mods):
    settings = mods.verifier.load_verifier_settings(
        {"session_user": dict(SETTINGS["session_user"], tenant_id=TENANT.upper())}
    )

    assert settings.session_user.tenant_id == TENANT
    assert settings.session_user.algorithms == ("RS256",)
    assert settings.session_user.jwks_lifespan_s == 3600


def test_one_jwks_key_source_per_uri(mods):
    shared = "https://keys.example.test/jwks"
    section = {
        "session_user": dict(SETTINGS["session_user"], jwks_uri=shared),
        "workload": dict(SETTINGS["workload"], jwks_uri=shared),
    }
    verifier = mods.verifier.IdentityVerifier(mods.verifier.load_verifier_settings(section), auth_module=None)

    assert verifier._key_sources["session_user"] is verifier._key_sources["workload"]
    assert isinstance(verifier._key_sources["session_user"], mods.verifier.JwksKeySource)


# --- nothing secret in any result ---------------------------------------------------


def test_no_token_or_cookie_in_any_result(mods, auth, verifier):
    session_token = auth.context["provider_attr"]["delegation"]["access_token"]
    workload_token = sign(workload_claims())
    secrets = [session_token, workload_token, COOKIE]
    #
    results = [verify_session(mods, verifier)]
    for change in (
            lambda: auth.set_token(sign(session_claims(aud="api://another"))),
            lambda: auth.set_token(sign(session_claims(), key=OTHER_PRIVATE)),
            lambda: auth.set_token("garbage"),
            lambda: setattr(auth, "linked", None),
    ):
        change()
        results.append(verify_session(mods, verifier))
    results.append(verify_session(mods, verifier, kinds=frozenset()))
    auth.fail.add("get_referenced_auth_context")
    results.append(verify_session(mods, verifier))
    results.append(verifier.verify(workload_evidence(mods, workload_token), admitted_kinds=KINDS))
    results.append(verifier.verify(workload_evidence(mods, workload_token, use="x"), admitted_kinds=KINDS))
    #
    for result in results:
        rendered = repr(result) + result.model_dump_json() + json.dumps(result.model_dump(mode="json"))
        assert not [secret for secret in secrets if secret in rendered]
        if type(result).__name__ == "TypedRejection":
            assert OID not in rendered and TENANT not in rendered and "secret-in-error-text" not in rendered
    #
    for evidence, secret in ((session_evidence(mods), COOKIE), (workload_evidence(mods, workload_token), workload_token)):
        assert secret not in repr(evidence) + evidence.model_dump_json()


def test_rejection_messages_are_fixed_per_code(mods, auth, verifier):
    auth.set_token(sign(session_claims(aud="api://one")))
    first = verify_session(mods, verifier)
    auth.set_token(sign(session_claims(aud="api://two")))

    assert verify_session(mods, verifier) == first
    codes = set(mods.identity.TypedRejection.model_fields["reason_code"].annotation.__args__)
    assert set(mods.verifier.MESSAGES) == codes


# --- types ----------------------------------------------------------------------------


def test_asserted_evidence_cannot_be_validated_as_verified(mods):
    asserted = mods.identity.AssertedUserEvidence(type="asserted_user", issuer="elitea:pat", subject="user:1")

    with pytest.raises(ValidationError):
        mods.identity.VerifiedUserEvidence.model_validate(asserted.model_dump())
    verified = mods.identity.VerifiedUserEvidence(type="verified_user", issuer="i", tid="t", oid="o", audience="a")
    with pytest.raises(ValidationError):
        mods.identity.AssertedUserEvidence.model_validate(verified.model_dump())


def test_models_are_frozen_and_strict(mods):
    evidence = mods.identity.LegacyPatEvidence(kind="legacy_pat", token_id=1)

    with pytest.raises(ValidationError):
        evidence.token_id = 2
    with pytest.raises(ValidationError):
        mods.identity.LegacyPatEvidence(kind="legacy_pat", token_id=1, extra_field=1)
    with pytest.raises(ValidationError):
        mods.identity.LegacyPatEvidence(kind="legacy_pat", token_id=True)
    with pytest.raises(ValidationError):
        mods.identity.EVIDENCE_ADAPTER.validate_python({"kind": "unknown"})


# --- Module.verify_identity / read_identity_epochs ---------------------------------------


def new_module(auth_module):
    return auth_module.Module(
        types.SimpleNamespace(rpc_manager=None, event_manager=None, url_prefix=""),
        types.SimpleNamespace(config={}),
    )


@pytest.fixture
def module(auth_module, mods, auth, clock):
    instance = new_module(auth_module)
    instance._read_epochs = auth.read_identity_epochs
    instance.get_referenced_auth_context = auth.get_referenced_auth_context
    instance.get_user_by_idp_subject = auth.get_user_by_idp_subject
    instance.identity_verifier = mods.verifier.IdentityVerifier(
        mods.verifier.load_verifier_settings(SETTINGS), auth_module=instance, clock=clock,
        key_sources={"session_user": mods.verifier.StaticKeySource({"k1": PUBLIC})},
    )
    return instance


def test_module_verify_identity_returns_a_json_dict(module, auth):
    result = module.verify_identity(
        {"kind": "session_user", "user_id": USER_ID, "auth_reference": COOKIE}, admitted_kinds=["session_user"],
    )

    assert result["ok"] is True
    assert result["principal"]["kind"] == "user"
    assert result["principal"]["evidence"]["type"] == "verified_user"
    assert isinstance(result["principal"]["expires_at"], str)
    rendered = json.dumps(result)
    assert COOKIE not in rendered
    assert auth.context["provider_attr"]["delegation"]["access_token"] not in rendered


def test_module_verify_identity_rejection_is_a_dict(module):
    result = module.verify_identity(
        {"kind": "session_user", "user_id": USER_ID, "auth_reference": COOKIE}, admitted_kinds=frozenset(),
    )

    assert set(result) == {"ok", "reason_code", "message"}
    assert (result["ok"], result["reason_code"]) == (False, "IDENTITY_KIND_NOT_ADMITTED")


@pytest.mark.parametrize("evidence", [
    {}, {"kind": "nope"}, None, "x", {"kind": "session_user", "user_id": "7", "auth_reference": COOKIE},
    {"kind": "session_user", "user_id": 7, "auth_reference": COOKIE, "extra": 1},
    {"kind": "workload", "token": "secret-token-value"},
])
def test_module_malformed_evidence_is_evidence_missing_without_echo(module, evidence):
    result = module.verify_identity(evidence, admitted_kinds=KINDS)

    assert (result["ok"], result["reason_code"]) == (False, "IDENTITY_EVIDENCE_MISSING")
    assert "secret-token-value" not in json.dumps(result) and COOKIE not in json.dumps(result)


def test_module_read_identity_epochs_wraps_read_epochs(auth_module):
    instance = new_module(auth_module)
    instance._read_epochs = lambda kind, auth_id: {"seen": (kind, auth_id)}

    assert instance.read_identity_epochs("user", 4) == {"seen": ("user", 4)}


def test_module_proxies_the_rpcs_the_verifier_needs(auth_module):
    proxies = dict(new_module(auth_module)._rpcs)

    assert proxies["get_referenced_auth_context"] == "auth_get_referenced_auth_context"
    assert proxies["get_user_by_idp_subject"] == "auth_get_user_by_idp_subject"


# --- PyJWT is only imported when something is configured -----------------------------------

NO_JWT_SCRIPT = textwrap.dedent(
    """
    import importlib.util, json, pathlib, sys, types

    root = pathlib.Path(sys.argv[1])

    def stub(name, **attrs):
        mod = types.ModuleType(name)
        mod.__dict__.update(attrs)
        return mod

    class Anything:
        def __getattr__(self, name):
            return Anything()
        def __call__(self, *a, **k):
            return Anything()

    class Log:
        def __getattr__(self, name):
            return lambda *a, **k: None

    class RpcCall:
        def __getattr__(self, name):
            def proxy(*a, **k):
                return None
            return proxy

    sys.modules.update({
        "flask": stub("flask", request=None, make_response=None), "redis": stub("redis"),
        "cachetools": stub("cachetools", TTLCache=lambda maxsize, ttl: {}, cached=lambda **k: (lambda f: f)),
        "pygeoip": stub("pygeoip"), "pylon": stub("pylon"), "pylon.core": stub("pylon.core"),
        "pylon.core.tools": stub("pylon.core.tools", log=Log(), module=stub("m", ModuleModel=object)),
        "pylon.core.tools.context": stub("pylon.core.tools.context", Context=types.SimpleNamespace),
    })
    package = types.ModuleType("auth_nojwt")
    package.__path__ = [str(root)]
    sys.modules["auth_nojwt"] = package
    spec = importlib.util.spec_from_file_location("auth_nojwt.module", root / "module.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    descriptor = types.SimpleNamespace(
        config={}, register_tool=lambda *a: None, init_rpcs=lambda: None,
    )
    context = types.SimpleNamespace(rpc_manager=types.SimpleNamespace(timeout=lambda seconds: RpcCall()), app=Anything(), event_manager=Anything(), url_prefix="")
    auth = module.Module(context, descriptor)
    auth.init()

    results = [
        auth.verify_identity({"kind": "session_user", "user_id": 1, "auth_reference": "c"}, admitted_kinds=["session_user"]),
        auth.verify_identity({"kind": "workload", "token": "t", "use": "u"}, admitted_kinds=["workload"]),
        auth.verify_identity({"kind": "bogus"}, admitted_kinds=["workload"]),
    ]
    print(json.dumps({"jwt_loaded": "jwt" in sys.modules, "codes": [r["reason_code"] for r in results]}))
    """
)


def test_jwt_is_not_imported_without_an_identity_verifier_section(tmp_path):
    script = tmp_path / "no_jwt_check.py"
    script.write_text(NO_JWT_SCRIPT)

    done = subprocess.run(
        [sys.executable, str(script), str(PLUGIN_ROOT)], capture_output=True, text=True, timeout=60, check=False,
    )

    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout.strip().splitlines()[-1]) == {
        "jwt_loaded": False,
        "codes": ["IDENTITY_KIND_NOT_ADMITTED", "IDENTITY_KIND_NOT_ADMITTED", "IDENTITY_EVIDENCE_MISSING"],
    }
