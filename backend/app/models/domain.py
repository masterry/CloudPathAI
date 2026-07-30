from typing import Any, Literal

from pydantic import BaseModel, Field


class Statement(BaseModel):
    effect: Literal["Allow", "Deny"]
    actions: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    condition: dict[str, Any] | None = None


class Principal(BaseModel):
    id: str
    name: str
    kind: Literal["User", "Role"]
    policies: list[Statement] = Field(default_factory=list)
    trust: list[str] = Field(default_factory=list)


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