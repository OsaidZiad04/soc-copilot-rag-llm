from ..LLMInterface import LLMInterface
from ..LLMEnums import OpenAIEnums
from openai import OpenAI
import logging
from typing import List, Union
import re


class OllamaProvider(LLMInterface):

    def __init__(self, api_url: str,
                       default_input_max_characters: int = 1000,
                       default_generation_max_output_tokens: int = 1000,
                       default_generation_temperature: float = 0.1):

        self.api_key = "ollama"
        self.api_url = api_url

        self.default_input_max_characters = default_input_max_characters
        self.default_generation_max_output_tokens = default_generation_max_output_tokens
        self.default_generation_temperature = default_generation_temperature

        self.generation_model_id = None

        self.embedding_model_id = None
        self.embedding_size = None

        self.client = OpenAI(
            api_key=self.api_key,
            base_url=self.api_url,
            timeout=20.0,
            max_retries=0,
        )

        self.enums = OpenAIEnums
        self.logger = logging.getLogger(__name__)

    def set_generation_model(self, model_id: str):
        self.generation_model_id = model_id

    def set_embedding_model(self, model_id: str, embedding_size: int):
        self.embedding_model_id = model_id
        self.embedding_size = embedding_size

    def process_text(self, text: str):
        return text[:self.default_input_max_characters].strip()

    def _strip_think_tags(self, text: str):
        if not isinstance(text, str):
            return text

        return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE).strip()

    def generate_text(self, prompt: str, chat_history: list = [], max_output_tokens: int = None,
                      temperature: float = None):

        if not self.client:
            self.logger.error("Ollama client was not set")
            return None

        if not self.generation_model_id:
            self.logger.error("Generation model for Ollama was not set")
            return None

        max_output_tokens = max_output_tokens if max_output_tokens else self.default_generation_max_output_tokens
        temperature = temperature if temperature else self.default_generation_temperature

        chat_history.append(
            self.construct_prompt(prompt=prompt, role=OpenAIEnums.USER.value)
        )

        try:
            response = self.client.chat.completions.create(
                model=self.generation_model_id,
                messages=chat_history,
                max_tokens=max_output_tokens,
                temperature=temperature,
                timeout=15.0,
            )
        except Exception as exc:
            self.logger.error("Error while generating text with Ollama: %s", exc)
            return None

        if not response or not response.choices or len(response.choices) == 0 or not response.choices[0].message:
            self.logger.error("Error while generating text with Ollama")
            return None

        raw = response.choices[0].message.content
        return self._strip_think_tags(raw)

    def embed_text(self, text: Union[str, List[str]], document_type: str = None):

        if not self.client:
            self.logger.error("Ollama client was not set")
            return None

        if isinstance(text, str):
            text = [text]

        if not self.embedding_model_id:
            self.logger.error("Embedding model for Ollama was not set")
            return None

        try:
            response = self.client.embeddings.create(
                model=self.embedding_model_id,
                input=text,
                timeout=8.0,
            )
        except Exception as exc:
            self.logger.error("Error while embedding text with Ollama: %s", exc)
            return None

        if not response or not response.data or len(response.data) == 0 or not response.data[0].embedding:
            self.logger.error("Error while embedding text with Ollama")
            return None

        return [rec.embedding for rec in response.data]

    def construct_prompt(self, prompt: str, role: str):
        return {
            "role": role,
            "content": prompt,
        }
