"""
Moltbook Agent Runtime - The core agent that runs on Moltbook.

This module provides everything needed to run an autonomous agent:
- Moltbook API client
- LLM integration (Anthropic/OpenAI)
- Main runtime loop
- Scheduled posting and commenting

Usage:
    from tools.agent import MoltbookAgent

    agent = MoltbookAgent.from_config("agent_config.yaml")
    agent.run()  # Starts the agent loop
"""

from .moltbook_api import MoltbookAPI
from .llm import LLMClient
from .runtime import MoltbookAgent

__all__ = [
    "MoltbookAgent",
    "MoltbookAPI",
    "LLMClient",
]

__version__ = "1.0.0"
