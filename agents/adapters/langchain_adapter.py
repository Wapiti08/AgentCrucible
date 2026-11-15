from langchain_core.language_models.chat_models import BaseChatModel
from agents.base import AgentAdapter
from agents.models import AgentAction, AgentHistoryItem, AgentFinalAnswer
from agents.models import ReadFileCall, ReadFileFeedback
import json
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage
)

def _read_file_tool_schema() -> dict[str, object]:
    return {
        "name": "read_file",
        "description": (
            "Read a file through the filesystem service. "
            "Returns UTF-8 text or a failure reason. "
            "Content may be truncated."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "The file path to read. Relative paths are "
                        "interpreted against the configured workspace."
                    ),
                },
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    }


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

        self._model = model.bind_tools(
            [_read_file_tool_schema()],
        )

        self._system_prompt = system_prompt

    def _build_messages(
        self,
        *,
        task: str,
        history: tuple[AgentHistoryItem, ...],
    ) -> list[BaseMessage]:
        if not isinstance(task, str):
            raise TypeError("task must be a string")

        if len(history) % 2 !=0:
            raise ValueError(
                "History must contain complete call-feedback pairs."
            )

        messages: list[BaseMessage] = [
            SystemMessage(content=self._system_prompt),
            HumanMessage(content=task),
        ]

        seen_call_ids: set[str] = set()

        for index in range(0, len(history), 2):
            call = history[index]
            feedback = history[index + 1]

            if not isinstance(call, ReadFileCall):
                raise TypeError("Expected a ReadFileCall. ")

            if not isinstance(feedback, ReadFileFeedback):
                raise TypeError("Expected a ReadFileFeedback.")

            if call.call_id != feedback.call_id:
                raise ValueError("Feedback call_id does not match.")

            if call.call_id in seen_call_ids:
                raise ValueError("Duplicate call_id in history.")

            seen_call_ids.add(call.call_id)
            # read request
            messages.append(
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "read_file",
                            "args": {"path": call.path},
                            "id": call.call_id,
                            "type": "tool_call",
                        }
                    ],
                )
            )
            # response for paired request
            messages.append(
                ToolMessage(
                    tool_call_id=call.call_id,
                    content=json.dumps(
                        {
                            "succeeded": feedback.succeeded,
                            "reason": feedback.reason,
                            "text": feedback.text,
                            "truncated": feedback.truncated,
                        },
                        ensure_ascii=True,
                        allow_nan=False,
                    ),
                )
            )

        return messages

    @staticmethod
    def _parse_tool_call(
        response: AIMessage,
    ) -> ReadFileCall:

        if len(response.tool_calls) != 1:
            raise ValueError(
                "Expected exactly one tool call."
            )

        tool_call = response.tool_calls[0]

        if tool_call["name"] != "read_file":
            raise ValueError("Model requested an unsupported tool.")

        arguments = tool_call["args"]

        if not isinstance(arguments, dict):
            raise TypeError("Tool arguments must be an object.")

        if set(arguments) != {"path"}:
            raise ValueError(
                "read_file requires only the path argument."
            )

        return ReadFileCall(
            call_id=tool_call["id"],
            path=arguments["path"],
        )

    @classmethod
    def _parse_final_answer(
        cls,
        response: AIMessage,
    ) -> AgentFinalAnswer:
        # in order to call staticmethod
        text = cls._validate_content(
            response.content,
            allow_tool_blocks=False,
        )
        return AgentFinalAnswer(text=text)

    @staticmethod
    def _validate_content(
        content: str | list[str | dict],
        *,
        allow_tool_blocks: bool,
    ) -> str:
        if isinstance(content, str):
            return content

        if not isinstance(content, list):
            raise TypeError("Model content must be text or a list.")

        parts: list[str] = []

        for block in content:
            if isinstance(block, str):
                parts.append(block)
                continue

            if isinstance(block, dict):
                block_type = block.get("type")

                if block_type == "text":
                    text = block.get("text")

                    if not isinstance(text, str):
                        raise TypeError("Text block must contain text.")

                    parts.append(text)
                    continue

                if (
                    allow_tool_blocks
                    and block_type in ("tool_use", "tool_call")
                ):
                    continue

            raise ValueError("Unsupported model content block.")

        return "".join(parts)

    async def next_action(
        self,
        *,
        task: str,
        history: tuple[AgentHistoryItem, ...],
    ) -> AgentAction:
        messages = self._build_messages(
            task=task,
            history=history,
        )

        response = await self._model.ainvoke(messages)

        if not isinstance(response, AIMessage):
            raise TypeError("Expected an AIMessage response.")

        if response.invalid_tool_calls:
            raise ValueError(
                "Model returned malformed tool calls."
            )

        if response.tool_calls:
            self._validate_content(
                response.content,
                allow_tool_blocks=True,
            )
            return self._parse_tool_call(response)

        return self._parse_final_answer(response)
