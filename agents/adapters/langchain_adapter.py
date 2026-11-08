from langchain_core.language_models.chat_models import BaseChatModel

from agents.base import AgentAdapter
from agents.models import AgentAction, AgentHistoryItem


class LangChainAgentAdapter(AgentAdapter):
    def __init__(
        self,
        model: BaseChatModel,
        *,
        system_prompt: str,
    ) -> None:
        if not isinstance(system_prompt, str):
            raise TypeError("system_prompt must be a string.")

        if not system_prompt.strip():
            raise ValueError("system_prompt must not be blank.")

        self._model = model
        self._system_prompt = system_prompt

    async def next_action(
        self,
        *,
        task: str,
        history: tuple[AgentHistoryItem, ...],
    ) -> AgentAction:
        raise NotImplementedError(
            "Message conversion and response parsing are not implemented yet."
        )
