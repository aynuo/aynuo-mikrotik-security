from __future__ import annotations

import re

from pydantic import BaseModel, Field, SecretStr, field_validator


class SSHTargetRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    timeout: float = Field(default=10, ge=1, le=30)

    @field_validator("host")
    @classmethod
    def strip_host(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be blank")
        return value


class SSHAssessmentRequest(SSHTargetRequest):
    username: str = Field(min_length=1, max_length=64)
    password: SecretStr = Field(min_length=1, max_length=256)

    @field_validator("username")
    @classmethod
    def strip_username(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be blank")
        return value


class HostKeyEnrollmentRequest(SSHTargetRequest):
    fingerprint: str = Field(pattern=r"^SHA256:[A-Za-z0-9+/]{20,}$", max_length=128)


class VersionCVERequest(BaseModel):
    version: str = Field(min_length=3, max_length=40)

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        value = value.strip()
        if not re.fullmatch(r"\d+\.\d+(?:\.\d+)?(?:(?:beta|rc)\d+)?(?:\s+\([^)]+\))?", value):
            raise ValueError("Enter a RouterOS version such as 7.25.1")
        return value

