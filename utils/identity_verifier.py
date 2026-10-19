""" Identity verifier (C-1009, #6756)

Turns identity evidence (a user session, a workload token, a legacy PAT) into a
VerifiedPrincipal or a TypedRejection. Nothing here is consulted unless the
operator configures the "identity_verifier" section; with the section absent
every kind that needs configuration is "not admitted" and PyJWT is never imported.

Rejection messages are fixed text per code. They never carry tokens, cookies,
auth references or claim values, and neither do the log lines written here.
"""

import re
import time
from datetime import datetime, timezone
from typing import Any, Literal, Mapping, Optional, Protocol, Union
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator

from pylon.core.tools import log  # pylint: disable=E0611,E0401

from ..models.pd.identity import (
    AssertedUserEvidence,
    Evidence,
    LegacyPatEvidence,
    SessionUserEvidence,
    TypedRejection,
    VerifiedPrincipal,
    VerifiedUserEvidence,
    WorkloadEvidence,
)

MESSAGES = {
    "IDENTITY_KIND_NOT_ADMITTED": "This kind of identity is not admitted here",
    "IDENTITY_REVOKED": "The identity is revoked or inactive",
    "DEPENDENCY_UNAVAILABLE": "The identity could not be verified right now",
    "IDENTITY_EVIDENCE_MISSING": "The identity evidence is missing or malformed",
    "IDENTITY_SIGNATURE_INVALID": "The identity token is not valid",
    "IDENTITY_EXPIRED": "The identity token is expired or not yet valid",
    "IDENTITY_AUDIENCE_MISMATCH": "The identity token is not meant for this audience",
    "IDENTITY_TENANT_MISMATCH": "The identity token is from an unexpected issuer or tenant",
    "IDENTITY_SUBJECT_UNLINKED": "The identity token subject is not linked to this user",
}

_GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_ASYMMETRIC_ALGORITHMS = Literal[
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512",
]


def rejection(code: str) -> TypedRejection:
    """ The rejection for a code, with its fixed message """
    return TypedRejection(reason_code=code, message=MESSAGES[code])


#
# Settings
#


class _Settings(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class _TokenSettings(_Settings):
    jwks_uri: str
    leeway_s: StrictInt = Field(default=60, ge=0, le=300)
    jwks_lifespan_s: StrictInt = Field(default=3600, ge=1)
    algorithms: tuple[_ASYMMETRIC_ALGORITHMS, ...] = Field(default=("RS256",), min_length=1)

    @field_validator("jwks_uri")
    @classmethod
    def _https(cls, value):
        parsed = urlparse(value)
        if parsed.scheme != "https" or not parsed.hostname or value != value.strip():
            raise ValueError("jwks_uri must be an https URL")
        return value


class SessionUserSettings(_TokenSettings):
    """ Entra ID delegated tokens of user sessions """
    tenant_id: str
    audience: str = Field(min_length=1)

    @field_validator("tenant_id")
    @classmethod
    def _guid(cls, value):
        # "common", "organizations" and "consumers" are multi-tenant authorities: refused
        if not _GUID.fullmatch(value):
            raise ValueError("tenant_id must be a tenant GUID")
        return value.lower()


class WorkloadSettings(_TokenSettings):
    """ Signed workload tokens """
    issuer: str = Field(min_length=1)
    audiences: dict[str, str] = Field(min_length=1)  # use -> audience

    @field_validator("audiences")
    @classmethod
    def _non_empty(cls, value):
        if any(not use or not audience for use, audience in value.items()):
            raise ValueError("audiences must map non-empty names to non-empty audiences")
        return value


class VerifierSettings(_Settings):
    """ The "identity_verifier" config section; a missing key means "not configured" """
    session_user: Optional[SessionUserSettings] = None
    workload: Optional[WorkloadSettings] = None


def load_verifier_settings(config_section) -> VerifierSettings:
    """ Validate the config section; raises ValueError on bad config, nothing when absent """
    if config_section is None:
        return VerifierSettings()
    if not isinstance(config_section, Mapping):
        raise ValueError("identity_verifier must be a mapping")
    return VerifierSettings.model_validate(dict(config_section))


#
# Key sources
#


class KeyUnavailable(Exception):
    """ The key could not be fetched (network, endpoint) """


class KeyNotFound(Exception):
    """ The token names a key that the source does not have """


class KeySource(Protocol):  # pylint: disable=R0903
    """ Where the verification key of a token comes from """

    def signing_key(self, token: str) -> Any:
        """ Key for this token; raises KeyUnavailable or KeyNotFound """


class JwksKeySource:  # pylint: disable=R0903
    """ Keys from a JWKS endpoint, cached by PyJWKClient """

    def __init__(self, jwks_uri: str, lifespan_s: int = 3600, timeout_s: int = 5):
        import jwt  # pylint: disable=C0415
        #
        self._client = jwt.PyJWKClient(
            jwks_uri, cache_keys=True, lifespan=lifespan_s, timeout=timeout_s,
        )

    def signing_key(self, token: str) -> Any:
        import jwt  # pylint: disable=C0415
        #
        try:
            return self._client.get_signing_key_from_jwt(token).key
        except jwt.PyJWKClientConnectionError as exc:
            raise KeyUnavailable() from exc
        except jwt.PyJWTError as exc:
            raise KeyNotFound() from exc


class StaticKeySource:  # pylint: disable=R0903
    """ Fixed {kid: public key PEM}; for tests and stubs """

    def __init__(self, keys: Mapping[str, str]):
        self._keys = dict(keys)

    def signing_key(self, token: str) -> Any:
        import jwt  # pylint: disable=C0415
        #
        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except jwt.PyJWTError as exc:
            raise KeyNotFound() from exc
        #
        if kid not in self._keys:
            raise KeyNotFound()
        return self._keys[kid]


#
# Verifier
#


class _Reject(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


# claim missing from the token -> code
_MISSING_CLAIM_CODES = {
    "exp": "IDENTITY_EXPIRED",
    "nbf": "IDENTITY_EXPIRED",
    "aud": "IDENTITY_AUDIENCE_MISMATCH",
    "iss": "IDENTITY_TENANT_MISMATCH",
    "tid": "IDENTITY_TENANT_MISMATCH",
}


class IdentityVerifier:
    """ Evidence -> VerifiedPrincipal | TypedRejection """

    def __init__(
            self, settings: VerifierSettings, *, auth_module, clock=time.time,
            key_sources: Optional[Mapping[str, KeySource]] = None,
    ):
        self.settings = settings
        self._auth = auth_module
        self._clock = clock
        self._key_sources = dict(key_sources or {})
        # One JwksKeySource per uri
        by_uri = {}
        for kind in ("session_user", "workload"):
            kind_settings = getattr(settings, kind)
            if kind_settings is None or kind in self._key_sources:
                continue
            if kind_settings.jwks_uri not in by_uri:
                by_uri[kind_settings.jwks_uri] = JwksKeySource(
                    kind_settings.jwks_uri, kind_settings.jwks_lifespan_s,
                )
            self._key_sources[kind] = by_uri[kind_settings.jwks_uri]

    def configured(self, kind: str) -> bool:
        """ Can this kind be verified at all? (legacy_pat needs no settings) """
        if kind == "legacy_pat":
            return True
        return kind in ("session_user", "workload") and getattr(self.settings, kind) is not None

    def verify(self, evidence: Evidence, *, admitted_kinds) -> Union[VerifiedPrincipal, TypedRejection]:
        """ Verify the evidence; the first failing step decides the rejection """
        kind = getattr(evidence, "kind", None)
        try:
            if kind not in admitted_kinds or not self.configured(kind):
                raise _Reject("IDENTITY_KIND_NOT_ADMITTED")
            #
            if isinstance(evidence, SessionUserEvidence):
                return self._verify_session_user(evidence)
            if isinstance(evidence, WorkloadEvidence):
                return self._verify_workload(evidence)
            if isinstance(evidence, LegacyPatEvidence):
                return self._verify_legacy_pat(evidence)
            raise _Reject("IDENTITY_EVIDENCE_MISSING")
        except _Reject as rejected:
            log.info("Identity rejected: kind=%s code=%s", kind, rejected.code)
            return rejection(rejected.code)
        except Exception as exc:  # pylint: disable=W0703
            # Fail closed; only the type is logged, the message may carry secrets
            log.error("Identity verification failed: kind=%s error=%s", kind, type(exc).__name__)
            return rejection("DEPENDENCY_UNAVAILABLE")

    #
    # Kinds
    #

    def _verify_session_user(self, evidence: SessionUserEvidence) -> VerifiedPrincipal:
        cfg = self.settings.session_user
        epochs = self._active_epochs("user", evidence.user_id)
        # The delegated token and the identity the session logged in with
        context = self._rpc(
            "get_referenced_auth_context", evidence.auth_reference.get_secret_value(),
        )
        provider_attr = context.get("provider_attr") if isinstance(context, dict) else None
        provider_attr = provider_attr if isinstance(provider_attr, dict) else {}
        delegation = provider_attr.get("delegation")
        token = delegation.get("access_token") if isinstance(delegation, dict) else None
        if not isinstance(token, str) or not token:
            raise _Reject("IDENTITY_EVIDENCE_MISSING")
        # The session must belong to the user the evidence names
        if context.get("user_id") != evidence.user_id:
            raise _Reject("IDENTITY_SUBJECT_UNLINKED")
        #
        claims = self._decode(
            "session_user", token, cfg,
            audience=cfg.audience,
            issuer=f"https://login.microsoftonline.com/{cfg.tenant_id}/v2.0",
            require=["exp", "nbf", "iss", "aud", "tid", "oid"],
        )
        if claims["tid"] != cfg.tenant_id:
            raise _Reject("IDENTITY_TENANT_MISMATCH")
        #
        tid, oid = claims["tid"], claims["oid"]
        if not isinstance(oid, str) or not oid:
            raise _Reject("IDENTITY_SUBJECT_UNLINKED")
        linked = self._rpc("get_user_by_idp_subject", claims["iss"], tid, oid)
        if not isinstance(linked, dict) or linked.get("id") != evidence.user_id:
            raise _Reject("IDENTITY_SUBJECT_UNLINKED")
        identity = provider_attr.get("identity")
        if not isinstance(identity, dict) or identity.get("tid") != tid or identity.get("oid") != oid:
            raise _Reject("IDENTITY_SUBJECT_UNLINKED")
        #
        return VerifiedPrincipal(
            kind="user",
            user_id=evidence.user_id,
            subject_ref=f"user:{evidence.user_id}",
            evidence=VerifiedUserEvidence(
                type="verified_user", issuer=claims["iss"], tid=tid, oid=oid,
                delegation_ref=_str_or_none(claims.get("uti") or claims.get("jti")),
                audience=cfg.audience,
            ),
            expires_at=_utc(claims["exp"]),
            epochs={"user": epochs.get("user"), "token": epochs.get("token")},
        )

    def _verify_workload(self, evidence: WorkloadEvidence) -> VerifiedPrincipal:
        cfg = self.settings.workload
        audience = cfg.audiences.get(evidence.use)
        if audience is None:
            raise _Reject("IDENTITY_AUDIENCE_MISMATCH")
        #
        claims = self._decode(
            "workload", evidence.token.get_secret_value(), cfg,
            audience=audience, issuer=cfg.issuer, require=["exp", "iss", "aud", "sub"],
        )
        return VerifiedPrincipal(
            kind="workload",
            subject_ref=f"workload:{claims['iss']}#{claims['sub']}",
            expires_at=_utc(claims["exp"]),
        )

    def _verify_legacy_pat(self, evidence: LegacyPatEvidence) -> VerifiedPrincipal:
        epochs = self._active_epochs("token", evidence.token_id)
        user_id = epochs.get("user_id")
        if isinstance(user_id, bool) or not isinstance(user_id, int):
            raise _Reject("IDENTITY_REVOKED")
        return VerifiedPrincipal(
            kind="legacy_pat",
            user_id=user_id,
            subject_ref=f"token:{evidence.token_id}",
            evidence=AssertedUserEvidence(
                type="asserted_user", issuer="elitea:pat", subject=f"user:{user_id}",
            ),
            epochs={"user": epochs.get("user"), "token": epochs.get("token")},
        )

    #
    # Steps
    #

    def _rpc(self, name, *args):
        """ A call into the auth module; any failure is "dependency unavailable" """
        try:
            return getattr(self._auth, name)(*args)
        except Exception as exc:  # pylint: disable=W0703
            log.warning("Identity dependency failed: %s %s", name, type(exc).__name__)
            raise _Reject("DEPENDENCY_UNAVAILABLE") from None

    def _active_epochs(self, auth_type, auth_id) -> dict:
        epochs = self._rpc("read_identity_epochs", auth_type, auth_id)
        if not isinstance(epochs, dict):
            raise _Reject("DEPENDENCY_UNAVAILABLE")  # unreadable: not provably active
        if not epochs.get("active"):
            raise _Reject("IDENTITY_REVOKED")
        return epochs

    def _decode(self, kind, token, cfg, *, audience, issuer, require) -> dict:  # pylint: disable=R0912
        """ Signature, algorithm, issuer, audience, required claims and time window """
        import jwt  # pylint: disable=C0415
        #
        try:
            algorithm = jwt.get_unverified_header(token).get("alg")
        except jwt.PyJWTError:
            raise _Reject("IDENTITY_SIGNATURE_INVALID") from None
        if algorithm not in cfg.algorithms:  # also refuses "none" and HMAC
            raise _Reject("IDENTITY_SIGNATURE_INVALID")
        #
        try:
            key = self._key_sources[kind].signing_key(token)
        except KeyNotFound:
            raise _Reject("IDENTITY_SIGNATURE_INVALID") from None
        except Exception:  # pylint: disable=W0703
            log.warning("Identity key source failed: kind=%s", kind)
            raise _Reject("DEPENDENCY_UNAVAILABLE") from None
        #
        try:
            # exp/nbf are checked below against the injected clock
            claims = jwt.decode(
                token, key, algorithms=list(cfg.algorithms), audience=audience, issuer=issuer,
                options={
                    "require": require, "verify_exp": False, "verify_nbf": False,
                    "verify_iat": False,
                },
            )
        except jwt.InvalidAudienceError:
            raise _Reject("IDENTITY_AUDIENCE_MISMATCH") from None
        except jwt.InvalidIssuerError:
            raise _Reject("IDENTITY_TENANT_MISMATCH") from None
        except jwt.MissingRequiredClaimError as exc:
            raise _Reject(_MISSING_CLAIM_CODES.get(exc.claim, "IDENTITY_SUBJECT_UNLINKED")) from None
        except jwt.PyJWTError:
            raise _Reject("IDENTITY_SIGNATURE_INVALID") from None
        #
        now = self._clock()
        for claim in ("exp", "nbf"):
            value = claims.get(claim)
            if value is None and claim not in require:
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise _Reject("IDENTITY_EXPIRED")
        if claims["exp"] <= now - cfg.leeway_s:
            raise _Reject("IDENTITY_EXPIRED")
        if claims.get("nbf") is not None and claims["nbf"] > now + cfg.leeway_s:
            raise _Reject("IDENTITY_EXPIRED")
        return claims


def _utc(timestamp) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def _str_or_none(value) -> Optional[str]:
    return value if isinstance(value, str) else None
