from pydantic import BaseModel, ConfigDict, Field, field_validator
import os

from langchain_openai import ChatOpenAI

class ModelConfig(BaseModel):
    model_config = ConfigDict(
        frozen = True,
        strict = True,
        extra = "forbid",
        allow_inf_nan = False,
    )
    # use openai as a default case
    model: str
    base_url: str = "https://api.openai.com/v1"
    api_key_env: str = "OPENAI_API_KEY"

    # limits to control request cost
    max_tokens: int = Field(default=256, gt=0)
    timeout_seconds: float = Field(default=20.0, gt=0)
    max_retries: int = Field(default=0, ge=0)

    @field_validator("model", "base_url", "api_key_env")
    @classmethod
    def validate_nonblank_string(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Value must not be blank.")

        if value != value.strip():
            raise ValueError(
                "Value must not contain leading or trailing whitespace."
            )

        return value


def create_chat_model(config: ModelConfig) -> ChatOpenAI:
    api_key = os.environ.get(config.api_key_env)

    if api_key is None or not api_key.strip():
        raise ValueError(
            f"Missing API key environment variable: {config.api_key_env}"
        )

    if api_key != api_key.strip():
        raise ValueError(
            "API key must not contain leading or trailing whitespace."
        )

    return ChatOpenAI(
        model=config.model,
        base_url=config.base_url,
        api_key=api_key,
        max_tokens=config.max_tokens,
        timeout=config.timeout_seconds,
        max_retries=config.max_retries,
        use_responses_api=False,
    )
