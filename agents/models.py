"""Reserved for provider-independent agent actions and tool feedback."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ReadFileCall:
    call_id: str
    path: str

    def __post_init__(self) -> None:
        if not isinstance(self.call_id, str):
            raise TypeError("call_id must be a string.")

        if not self.call_id.strip():
            raise ValueError("call_id must not be blank.")

        if not isinstance(self.path, str):
            raise TypeError("path must be a string.")


@dataclass(frozen=True)
class ReadFileFeedback:
    call_id: str
    succeeded: bool
    reason: str
    text: str | None
    truncated: bool | None

    def __post_init__(self) -> None:
        if not isinstance(self.call_id, str):
            raise TypeError("call_id must be a string.")

        if not self.call_id.strip():
            raise ValueError("call_id must not be blank.")

        if type(self.succeeded) is not bool:
            raise TypeError("succeeded must be a boolean.")

        if not isinstance(self.reason, str):
            raise TypeError("reason must be a string.")

        if not self.reason.strip():
            raise ValueError("reason must not be blank.")

        if self.succeeded:
            if not isinstance(self.text, str):
                raise TypeError(
                    "Successful feedback requires text."
                )

            if type(self.truncated) is not bool:
                raise TypeError(
                    "Successful feedback requires a truncation flag."
                )
        elif self.text is not None or self.truncated is not None:
            raise ValueError(
                "Failed feedback must not contain text or a truncation flag."
            )


@dataclass(frozen=True)
class AgentFinalAnswer:
    text: str

    def __post_init__(self) -> None:
        if not isinstance(self.text, str):
            raise TypeError("text must be a string.")


AgentAction = ReadFileCall | AgentFinalAnswer

AgentHistoryItem = ReadFileCall | ReadFileFeedback
