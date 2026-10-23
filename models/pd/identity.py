""" Identity evidence and verification result types (C-1009, #6756)

Evidence is what a caller presents; a VerifiedPrincipal is what the verifier
concluded from it. Asserted and verified user evidence are different types on
purpose: nothing converts one into the other.
"""

from datetime import datetime
from typing import Annotated, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, SecretStr, StrictInt, TypeAdapter


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# Evidence (input)


class SessionUserEvidence(_Frozen):
    """ A logged-in user, proven through the delegated token of their session """
    kind: Literal["session_user"]
    user_id: StrictInt
    auth_reference: SecretStr  # session cookie value; never logged, never returned


class WorkloadEvidence(_Frozen):
    """ A workload presenting a signed token for one of the configured audiences """
    kind: Literal["workload"]
    token: SecretStr
    use: str = Field(min_length=1)  # key into workload.audiences


class LegacyPatEvidence(_Frozen):
    """ A personal access token, identified by its id """
    kind: Literal["legacy_pat"]
    token_id: StrictInt


Evidence = Annotated[
    Union[SessionUserEvidence, WorkloadEvidence, LegacyPatEvidence],
    Field(discriminator="kind"),
]
EVIDENCE_ADAPTER = TypeAdapter(Evidence)


# Evidence about the user behind a principal (output)


class VerifiedUserEvidence(_Frozen):
    """ The IdP proved this user: signature, audience, tenant and link were checked """
    type: Literal["verified_user"]
    issuer: str
    tid: str
    oid: str
    delegation_ref: Optional[str] = None  # uti/jti claim of the delegated token
    audience: str


class AssertedUserEvidence(_Frozen):
    """ The platform vouches for this user; no IdP proof exists """
    type: Literal["asserted_user"]
    issuer: str
    subject: str
    mandate_ref: Optional[str] = None


# Result


class VerifiedPrincipal(_Frozen):
    """ Who the evidence proved """
    kind: Literal["user", "workload", "legacy_pat"]
    user_id: Optional[int] = None
    subject_ref: str
    evidence: Optional[
        Annotated[Union[VerifiedUserEvidence, AssertedUserEvidence], Field(discriminator="type")]
    ] = None
    expires_at: Optional[datetime] = None
    epochs: dict = Field(default_factory=dict)  # {user, token} as read at verification


class TypedRejection(_Frozen):
    """ Why the evidence was refused; the message is fixed text per code """
    reason_code: Literal[
        "IDENTITY_KIND_NOT_ADMITTED",
        "IDENTITY_REVOKED",
        "DEPENDENCY_UNAVAILABLE",
        "IDENTITY_EVIDENCE_MISSING",
        "IDENTITY_SIGNATURE_INVALID",
        "IDENTITY_EXPIRED",
        "IDENTITY_AUDIENCE_MISMATCH",
        "IDENTITY_TENANT_MISMATCH",
        "IDENTITY_SUBJECT_UNLINKED",
    ]
    message: str
