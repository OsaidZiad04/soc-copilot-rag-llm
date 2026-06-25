from ..LLMInterface import LLMInterface
from ..LLMEnums import OpenAIEnums
from openai import OpenAI
import logging
from typing import List, Union
import hashlib
import math
import re
import time

class OpenAIProvider(LLMInterface):
    _remote_retry_after_by_url = {}

    def __init__(self, api_key: str, api_url: str=None,
                       default_input_max_characters: int=1000,
                       default_generation_max_output_tokens: int=1000,
                       default_generation_temperature: float=0.1):
        
        self.api_key = api_key
        self.api_url = api_url

        self.default_input_max_characters = default_input_max_characters
        self.default_generation_max_output_tokens = default_generation_max_output_tokens
        self.default_generation_temperature = default_generation_temperature

        self.generation_model_id = None

        self.embedding_model_id = None
        self.embedding_size = None

        self.is_local_ollama_endpoint = bool(
            api_url and ("11434" in api_url or "11436" in api_url)
        )
        self.remote_retry_key = api_url or "__default__"
        client_timeout = 20.0 if self.is_local_ollama_endpoint else 45.0
        client_options = {
            "api_key": self.api_key,
            "base_url": self.api_url if self.api_url and len(self.api_url) else None,
            "timeout": client_timeout,
        }
        if self.is_local_ollama_endpoint:
            client_options["max_retries"] = 0

        self.client = OpenAI(**client_options)

        self.enums = OpenAIEnums
        self.logger = logging.getLogger(__name__)

    def _remote_temporarily_unavailable(self):
        retry_after = self._remote_retry_after_by_url.get(self.remote_retry_key, 0.0)
        return self.is_local_ollama_endpoint and time.monotonic() < retry_after

    def _mark_remote_unavailable(self):
        if self.is_local_ollama_endpoint:
            self._remote_retry_after_by_url[self.remote_retry_key] = time.monotonic() + 30.0

    def set_generation_model(self, model_id: str):
        self.generation_model_id = model_id

    def set_embedding_model(self, model_id: str, embedding_size: int):
        self.embedding_model_id = model_id
        self.embedding_size = embedding_size

    def process_text(self, text: str):
        return text[:self.default_input_max_characters].strip()

    def _fallback_embed_single(self, text: str):
        size = self.embedding_size or 768
        vector = [0.0] * size
        tokens = re.findall(r"[a-zA-Z0-9_.:/\\-]+", (text or "").lower())

        if len(tokens) == 0:
            return vector

        for token in tokens:
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            idx = int.from_bytes(digest[:4], "big") % size
            sign = -1.0 if digest[4] % 2 else 1.0
            weight = 1.0 + ((digest[5] % 7) / 10.0)
            vector[idx] += sign * weight

        norm = math.sqrt(sum(value * value for value in vector))
        if norm == 0:
            return vector

        return [value / norm for value in vector]

    def _fallback_embed_text(self, text: List[str]):
        self.logger.warning("Using local fallback embeddings because remote embedding call is unavailable")
        return [self._fallback_embed_single(item) for item in text]

    def generate_text(self, prompt: str, chat_history: list=[], max_output_tokens: int=None,
                            temperature: float = None):
        
        if not self.client:
            self.logger.error("OpenAI client was not set")
            return None

        if not self.generation_model_id:
            self.logger.error("Generation model for OpenAI was not set")
            return None

        if self._remote_temporarily_unavailable():
            self.logger.warning("Skipping local generation request because the endpoint recently timed out")
            return None
        
        max_output_tokens = max_output_tokens if max_output_tokens else self.default_generation_max_output_tokens
        temperature = temperature if temperature is not None else self.default_generation_temperature

        # Ollama-hosted reasoning models can spend large token budgets on hidden reasoning
        # before returning visible content. Cap their output budget so fallbacks can trigger
        # quickly instead of blocking the entire request path for minutes.
        if (
            self.api_url
            and ("11434" in self.api_url or "11436" in self.api_url)
            and isinstance(self.generation_model_id, str)
            and self.generation_model_id.lower().startswith("qwen")
        ):
            max_output_tokens = min(max_output_tokens, 128)

        chat_history.append(
            self.construct_prompt(prompt=prompt, role=OpenAIEnums.USER.value)
        )

        try:
            request_options = {
                "model": self.generation_model_id,
                "messages": chat_history,
                "max_tokens": max_output_tokens,
                "temperature": temperature,
            }
            if self.is_local_ollama_endpoint:
                request_options["timeout"] = 15.0
            response = self.client.chat.completions.create(**request_options)
        except Exception as exc:
            self._mark_remote_unavailable()
            self.logger.error("Error while generating text with OpenAI: %s", exc)
            return None

        if not response or not response.choices or len(response.choices) == 0 or not response.choices[0].message:
            self.logger.error("Error while generating text with OpenAI")
            return None

        return response.choices[0].message.content


    def embed_text(self, text: Union[str, List[str]], document_type: str = None):
        
        if not self.client:
            self.logger.error("OpenAI client was not set")
            return None
        
        if isinstance(text, str):
            text = [text]

        if not self.embedding_model_id:
            self.logger.error("Embedding model for OpenAI was not set")
            return None

        if self._remote_temporarily_unavailable():
            return self._fallback_embed_text(text)

        try:
            request_options = {
                "model": self.embedding_model_id,
                "input": text,
            }
            if self.is_local_ollama_endpoint:
                request_options["timeout"] = 8.0
            response = self.client.embeddings.create(**request_options)
        except Exception as exc:
            self._mark_remote_unavailable()
            max_length = max([
                len(item)
                for item in text
                if isinstance(item, str)
            ], default=0)
            self.logger.error(
                "Embedding request failed for %s item(s), max_length=%s, type=%s: %s",
                len(text),
                max_length,
                document_type,
                exc,
            )
            return self._fallback_embed_text(text)

        if not response or not response.data or len(response.data) == 0 or not response.data[0].embedding:
            self.logger.error("Error while embedding text with OpenAI")
            return self._fallback_embed_text(text)

        return [ rec.embedding for rec in response.data ]

    def construct_prompt(self, prompt: str, role: str):
        return {
            "role": role,
            "content": prompt,
        }
    


    
