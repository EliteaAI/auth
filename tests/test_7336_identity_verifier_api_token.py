"""Scoped, expiring API tokens as identity evidence (C-1009, #7336).

``api_token`` evidence names a token, its owner and the scope its row carries. The verifier admits it only while the
token and its owner are live (their epochs), the owner is the evidence's user, and the row is still that scope with an
expiry; the platform vouches for the owner (an asserted user, issuer ``elitea:api_token``). An unscoped token stays
``legacy_pat``, admitted only when the operator admits legacy tokens.
"""
import datetime
import pathlib
import sys

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from test_6756_identity_verifier import FakeAuth, USER_ID, build, clock, mods, verifier  # noqa: E402,F401  pylint: disable=C0413,W0611

TOKEN_ID = 21
EXPIRES = datetime.datetime(2030, 1, 1, 12, 0)
SCOPED_ROW = {"id": TOKEN_ID, "user_id": USER_ID, "name": "ci", "expires": EXPIRES,
              "scope_projects": [5], "scope_operations": ["run"]}
ENFORCE_KINDS = frozenset({"session_user", "api_token"})   # what admission admits under enforce, legacy tokens off


class TokenAuth(FakeAuth):
    def __init__(self):
        super().__init__()
        self.epochs = {"user": 3, "token": 4, "user_id": USER_ID, "active": True, "reason": None}
        self.row = dict(SCOPED_ROW)

    def get_token(self, token_id):
        self._call("get_token", token_id)
        return self.row


@pytest.fixture
def auth():
    return TokenAuth()


def evidence(mods, **overrides):
    values = {"kind": "api_token", "token_id": TOKEN_ID, "user_id": USER_ID, "projects": [5], "operations": ["run"]}
    values.update(overrides)
    return mods.identity.ApiTokenEvidence(**values)


def code_of(result):
    assert type(result).__name__ == "TypedRejection", result
    return result.reason_code


def test_a_scoped_token_is_admitted_by_default_under_enforce_as_its_owner(mods, auth, verifier):
    principal = verifier.verify(evidence(mods), admitted_kinds=ENFORCE_KINDS)

    assert (principal.kind, principal.user_id, principal.subject_ref) == ("api_token", USER_ID, f"user:{USER_ID}")
    assert (principal.evidence.type, principal.evidence.issuer, principal.evidence.subject) == (
        "asserted_user", "elitea:api_token", f"user:{USER_ID}")
    assert principal.epochs == {"user": 3, "token": 4} and principal.expires_at == EXPIRES
    assert [name for name, _ in auth.calls] == ["read_identity_epochs", "get_token"]
    assert auth.calls[0] == ("read_identity_epochs", ("token", TOKEN_ID))


def test_it_needs_no_verifier_settings(mods, auth, build):
    plain = build(None)
    assert plain.configured("api_token")
    assert plain.verify(evidence(mods), admitted_kinds=ENFORCE_KINDS).kind == "api_token"


def test_it_is_refused_when_its_kind_is_not_admitted_and_nothing_is_read(mods, auth, verifier):
    assert code_of(verifier.verify(evidence(mods), admitted_kinds=frozenset({"session_user"}))) == \
        "IDENTITY_KIND_NOT_ADMITTED"
    assert auth.calls == []


@pytest.mark.parametrize("reason", ["token_missing", "token_expired", "user_suspended", "user_missing"])
def test_a_deleted_expired_or_suspended_token_is_revoked(mods, auth, verifier, reason):
    auth.epochs = dict(auth.epochs, active=False, reason=reason)

    assert code_of(verifier.verify(evidence(mods), admitted_kinds=ENFORCE_KINDS)) == "IDENTITY_REVOKED"
    assert auth.called("get_token") == []


def test_unreadable_epochs_or_row_are_dependency_unavailable(mods, auth, verifier):
    auth.epochs = None
    assert code_of(verifier.verify(evidence(mods), admitted_kinds=ENFORCE_KINDS)) == "DEPENDENCY_UNAVAILABLE"

    auth.epochs = {"user": 3, "token": 4, "user_id": USER_ID, "active": True, "reason": None}
    auth.fail.add("get_token")
    result = verifier.verify(evidence(mods), admitted_kinds=ENFORCE_KINDS)
    assert code_of(result) == "DEPENDENCY_UNAVAILABLE" and "secret-in-error-text" not in result.message


def test_a_token_of_another_user_is_unlinked(mods, auth, verifier):
    assert code_of(verifier.verify(evidence(mods, user_id=USER_ID + 1), admitted_kinds=ENFORCE_KINDS)) == \
        "IDENTITY_SUBJECT_UNLINKED"


@pytest.mark.parametrize("row_change, evidence_change", [
    ({"scope_projects": None, "scope_operations": None}, {}),   # the row is a legacy token
    ({"expires": None}, {}),                                      # a scope without an expiry is no scope
    ({"scope_projects": [5, 6]}, {}),                             # the evidence names less than the row
    ({}, {"projects": [5, 6]}),                                   # ... or more
    ({}, {"operations": ["run", "build"]}),
    ({"user_id": USER_ID + 1}, {}),
])
def test_evidence_that_is_not_the_rows_scope_is_refused(mods, auth, verifier, row_change, evidence_change):
    auth.row.update(row_change)

    assert code_of(verifier.verify(evidence(mods, **evidence_change), admitted_kinds=ENFORCE_KINDS)) == \
        "IDENTITY_EVIDENCE_MISSING"


def test_an_unscoped_token_stays_legacy_and_is_refused_unless_admitted(mods, auth, verifier):
    legacy = mods.identity.LegacyPatEvidence(kind="legacy_pat", token_id=TOKEN_ID)

    assert code_of(verifier.verify(legacy, admitted_kinds=ENFORCE_KINDS)) == "IDENTITY_KIND_NOT_ADMITTED"
    assert verifier.verify(legacy, admitted_kinds=ENFORCE_KINDS | {"legacy_pat"}).kind == "legacy_pat"


@pytest.mark.parametrize("overrides", [{"projects": []}, {"operations": []}, {"token_id": "21"}, {"user_id": None},
                                       {"extra": 1}])
def test_malformed_evidence_is_refused_by_its_type(mods, overrides):
    with pytest.raises(ValidationError):
        evidence(mods, **overrides)


@pytest.mark.parametrize("row, scope", [
    (SCOPED_ROW, {"projects": [5], "operations": ["run"], "user_id": USER_ID}),
    (dict(SCOPED_ROW, scope_operations=["run", "build", "admin"]),
     {"projects": [5], "operations": ["run", "build", "admin"], "user_id": USER_ID}),
    (dict(SCOPED_ROW, user_id=None), None),
    (dict(SCOPED_ROW, expires=None), None),
    (dict(SCOPED_ROW, scope_projects=None), None),
    (dict(SCOPED_ROW, scope_operations=None), None),
    (dict(SCOPED_ROW, scope_projects=[]), None),
    (dict(SCOPED_ROW, scope_operations=["root"]), None),
    (dict(SCOPED_ROW, scope_projects=["5"]), None),
    (dict(SCOPED_ROW, scope_projects=[True]), None),
    ({"id": 1, "expires": None, "name": "api"}, None),              # a token from before #7336
    (None, None),
])
def test_what_makes_a_token_scoped(mods, row, scope):
    assert mods.verifier.token_scope_of(row) == scope


def test_the_module_reads_the_scope_through_its_cached_token_read(auth_module):
    module = auth_module.Module.__new__(auth_module.Module)
    reads = []
    module.get_token = lambda token_id: reads.append(token_id) or SCOPED_ROW
    assert module.token_scope(TOKEN_ID) == {"projects": [5], "operations": ["run"], "user_id": USER_ID}
    assert reads == [TOKEN_ID]
    module.get_token = lambda token_id: {"id": token_id, "expires": None}
    assert module.token_scope(TOKEN_ID) is None


def test_verify_identity_accepts_api_token_evidence_as_a_dict(auth_module, auth, build):
    module = auth_module.Module.__new__(auth_module.Module)
    module.identity_verifier = build()
    result = module.verify_identity(
        {"kind": "api_token", "token_id": TOKEN_ID, "user_id": USER_ID, "projects": [5], "operations": ["run"]},
        admitted_kinds=ENFORCE_KINDS)

    assert result["ok"] is True and result["principal"]["kind"] == "api_token"
    assert result["principal"]["evidence"]["issuer"] == "elitea:api_token"
