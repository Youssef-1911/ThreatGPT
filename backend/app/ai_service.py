import json
import os
from typing import Any
from urllib import error, request


class AIService:
    def __init__(self, api_url: str | None = None, model: str | None = None) -> None:
        self.api_key = os.getenv("AI_API_KEY") or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("AI_API_KEY (or OPENAI_API_KEY) environment variable is required")

        self.api_url = api_url or os.getenv("AI_API_URL", "https://api.openai.com/v1/chat/completions")
        self.model = model or os.getenv("AI_MODEL", "gpt-4.1-mini")

    def call_model(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float | None = None,
        seed: int | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        if temperature is not None:
            payload["temperature"] = temperature
        if seed is not None:
            payload["seed"] = seed

        http_request = request.Request(
            self.api_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with request.urlopen(http_request) as response:
                response_body = response.read().decode("utf-8")
        except error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"AI API request failed with status {exc.code}: {error_body}") from exc
        except error.URLError as exc:
            raise RuntimeError(f"AI API request failed: {exc.reason}") from exc

        response_json = json.loads(response_body)
        content = self._extract_content(response_json)

        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError("Model response was not valid JSON") from exc

        if not isinstance(parsed, dict):
            raise ValueError("Model response JSON must be an object")

        return parsed

    def _extract_content(self, response_json: dict[str, Any]) -> str:
        choices = response_json.get("choices")
        if not choices:
            raise ValueError("AI API response did not include choices")

        message = choices[0].get("message") or {}
        content = message.get("content")

        if isinstance(content, str):
            return content

        if isinstance(content, list):
            text_parts = [
                item.get("text", "")
                for item in content
                if isinstance(item, dict) and item.get("type") == "text"
            ]
            if text_parts:
                return "".join(text_parts)

        raise ValueError("AI API response did not include text content")
