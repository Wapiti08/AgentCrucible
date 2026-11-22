from hashlib import sha256
from typing import Literal, Self
import base64
import binascii
from pydantic import BaseModel, ConfigDict, Field, model_validator


class FileReadResponse(BaseModel):
    model_config = ConfigDict(
        strict = True,
        extra = "forbid",
        frozen=True,
    )

    request_id: str = Field(min_length=1)

    policy_decision: Literal[
        "allowed",
        "blocked",
        "not_evaluated",
        "error",
    ]

    execution_status: Literal[
        "succeeded",
        "failed",
        "not_started",
    ]

    reason: str = Field(min_length=1)
    content_base64: str | None = Field(repr=False)
    returned_bytes: int = Field(ge=0)
    truncated: bool | None
    content_sha256: str | None = Field(
        pattern=r"^[0-9a-f]{64}$",
    )

    ## after means execution after all type transformation and verification
    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if (
            self.policy_decision != "allowed"
            and self.execution_status != "not_started"
        ):
            raise ValueError(
                "Execution requires an allowed policy decision."
            )

        if self.execution_status == "succeeded":
            if (
                self.content_base64 is None
                or self.truncated is None
                or self.content_sha256 is None
            ):
                raise ValueError(
                    "Successful reads require content, truncation "
                    "status, and a digest."
                )
        else:
            if (
                self.content_base64 is not None
                or self.truncated is not None
                or self.content_sha256 is not None
                or self.returned_bytes != 0
            ):
                raise ValueError(
                    "Unsuccessful reads must not contain content metadata."
                )

        return self

    @model_validator(mode="after")
    def validate_content(self) -> Self:
        if self.execution_status != "succeeded":
            return self

        # read encoded content
        content_base64 = self.content_base64
        if content_base64 is None:
            raise ValueError("Successful reads require content.")

        try:
            content = base64.b64decode(
                content_base64,
                validate=True,
            )
        except (binascii.Error, ValueError) as exc:
            raise ValueError(
                "content_base64 must be valid Base64."
            ) from exc

        # check with original content length
        if len(content) != self.returned_bytes:
            raise ValueError(
                "returned_bytes does not match decoded content."
            )

        # verify hash value
        if sha256(content).hexdigest() != self.content_sha256:
            raise ValueError(
                "content_sha256 does not match decoded content."
            )

        return self
