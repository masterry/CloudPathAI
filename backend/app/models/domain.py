from typing import Any, Literal

from pydantic import BaseModel, Field


class Statement(BaseModel):
    effect: Literal["Allow", "Deny"]
    actions: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    condition: dict[str, Any] | None = None
    unsupported_elements: list[str] = Field(default_factory=list)
    source_policy_arn: str | None = None


class Principal(BaseModel):
    id: str
    arn: str | None = None
    name: str
    kind: Literal["User", "Role"]
    policies: list[Statement] = Field(default_factory=list)
    trust: list[str] = Field(default_factory=list)
    attached_managed_policy_arns: list[str] = Field(default_factory=list)

    @property
    def resource(self) -> str:
        """Canonical IAM resource used for authorization checks."""
        return self.arn or self.id


class Dataset(BaseModel):
    account_id: str
    principals: list[Principal] = Field(default_factory=list)


class Finding(BaseModel):
    id: str
    primitive: str
    title: str
    source: str
    target: str
    severity: Literal["low", "medium", "high", "critical"]
    score: int
    evidence: list[str] = Field(default_factory=list)
    remediation: str
