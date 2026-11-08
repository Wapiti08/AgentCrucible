"""Reserved for the agent adapter contract; no SDK dependencies here."""

from abc import abstractmethod,  ABC

from .models import AgentAction, AgentHistoryItem


class AgentAdapter(ABC):
    @abstractmethod
    async def next_action(
        self,
        *,
        task: str,
        history: tuple[AgentHistoryItem, ...],
    ) -> AgentAction:
        """Propose one tool call or return a final answer."""
        raise NotImplementedError
