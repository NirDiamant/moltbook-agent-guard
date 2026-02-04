"""
LLM Client - Unified interface for Anthropic and OpenAI.

Handles:
- Provider abstraction (Claude, GPT)
- Token counting and cost tracking
- System prompt management
"""

import os
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class LLMResponse:
    """Response from an LLM call."""
    content: str
    input_tokens: int
    output_tokens: int
    model: str
    cost: float


# Pricing per 1K tokens (as of 2026)
MODEL_PRICING = {
    # Anthropic
    "claude-3-5-sonnet": {"input": 0.003, "output": 0.015},
    "claude-3-opus": {"input": 0.015, "output": 0.075},
    "claude-3-haiku": {"input": 0.00025, "output": 0.00125},
    # OpenAI
    "gpt-4o": {"input": 0.005, "output": 0.015},
    "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
    "gpt-4-turbo": {"input": 0.01, "output": 0.03},
}

# Map friendly names to actual API model IDs
MODEL_ID_MAP = {
    # Anthropic - map to current production models
    "claude-3-5-sonnet": "claude-sonnet-4-20250514",
    "claude-3-opus": "claude-3-opus-20240229",
    "claude-3-haiku": "claude-3-haiku-20240307",
    # OpenAI - these names already work
    "gpt-4o": "gpt-4o",
    "gpt-4o-mini": "gpt-4o-mini",
    "gpt-4-turbo": "gpt-4-turbo",
}


class LLMClient:
    """
    Unified LLM client for Anthropic and OpenAI.

    Usage:
        client = LLMClient(
            provider="anthropic",
            model="claude-3-5-sonnet",
            api_key="your_key"
        )
        response = client.generate(
            system_prompt="You are a helpful assistant.",
            messages=[{"role": "user", "content": "Hello!"}]
        )
        print(response.content)
    """

    def __init__(self, provider: str, model: str, api_key: str = None):
        """
        Initialize the LLM client.

        Args:
            provider: "anthropic" or "openai"
            model: Model name (e.g., "claude-3-5-sonnet", "gpt-4o")
            api_key: API key (or set via environment variable)
        """
        self.provider = provider.lower()
        self.model = model
        self.api_key = api_key

        # Get API key from environment if not provided
        if not self.api_key:
            if self.provider == "anthropic":
                self.api_key = os.environ.get("ANTHROPIC_API_KEY")
            elif self.provider == "openai":
                self.api_key = os.environ.get("OPENAI_API_KEY")

        if not self.api_key:
            raise ValueError(f"No API key provided for {provider}")

        # Initialize the appropriate client
        if self.provider == "anthropic":
            self._init_anthropic()
        elif self.provider == "openai":
            self._init_openai()
        else:
            raise ValueError(f"Unknown provider: {provider}")

        # Track total usage
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cost = 0.0

    def _init_anthropic(self):
        """Initialize Anthropic client."""
        try:
            import anthropic
            self.client = anthropic.Anthropic(api_key=self.api_key)
        except ImportError:
            raise ImportError("Please install anthropic: pip install anthropic")

    def _init_openai(self):
        """Initialize OpenAI client."""
        try:
            import openai
            self.client = openai.OpenAI(api_key=self.api_key)
        except ImportError:
            raise ImportError("Please install openai: pip install openai")

    def _calculate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Calculate cost for token usage."""
        pricing = MODEL_PRICING.get(self.model, {"input": 0.01, "output": 0.03})
        input_cost = (input_tokens / 1000) * pricing["input"]
        output_cost = (output_tokens / 1000) * pricing["output"]
        return input_cost + output_cost

    def generate(self, system_prompt: str, messages: List[Dict],
                 max_tokens: int = 1024, temperature: float = 0.7) -> LLMResponse:
        """
        Generate a response from the LLM.

        Args:
            system_prompt: System/personality prompt
            messages: List of message dicts with "role" and "content"
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature (0-1)

        Returns:
            LLMResponse with content and usage stats
        """
        if self.provider == "anthropic":
            return self._generate_anthropic(system_prompt, messages, max_tokens, temperature)
        else:
            return self._generate_openai(system_prompt, messages, max_tokens, temperature)

    def _generate_anthropic(self, system_prompt: str, messages: List[Dict],
                            max_tokens: int, temperature: float) -> LLMResponse:
        """Generate using Anthropic's API."""
        # Map friendly model name to actual API model ID
        api_model = MODEL_ID_MAP.get(self.model, self.model)
        response = self.client.messages.create(
            model=api_model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_prompt,
            messages=messages,
        )

        input_tokens = response.usage.input_tokens
        output_tokens = response.usage.output_tokens
        cost = self._calculate_cost(input_tokens, output_tokens)

        # Track totals
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        self.total_cost += cost

        return LLMResponse(
            content=response.content[0].text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=self.model,
            cost=cost,
        )

    def _generate_openai(self, system_prompt: str, messages: List[Dict],
                         max_tokens: int, temperature: float) -> LLMResponse:
        """Generate using OpenAI's API."""
        # Prepend system message
        full_messages = [{"role": "system", "content": system_prompt}] + messages

        # Map friendly model name to actual API model ID
        api_model = MODEL_ID_MAP.get(self.model, self.model)
        response = self.client.chat.completions.create(
            model=api_model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=full_messages,
        )

        input_tokens = response.usage.prompt_tokens
        output_tokens = response.usage.completion_tokens
        cost = self._calculate_cost(input_tokens, output_tokens)

        # Track totals
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        self.total_cost += cost

        return LLMResponse(
            content=response.choices[0].message.content,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=self.model,
            cost=cost,
        )

    def get_usage(self) -> Dict:
        """Get total usage statistics."""
        return {
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_cost": round(self.total_cost, 4),
            "model": self.model,
            "provider": self.provider,
        }
