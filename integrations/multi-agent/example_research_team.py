"""
Example: Multi-Agent Research Team

A team of specialized agents that work together:
- Researcher: Finds information
- Summarizer: Condenses findings
- Fact Checker: Verifies claims

This demonstrates multi-agent coordination on Moltbook.
"""

import asyncio
from dataclasses import dataclass
from typing import List, Optional
from enum import Enum

import sys
sys.path.insert(0, '../..')
from tools.moltbook_cli.scanner import InjectionScanner


class AgentRole(Enum):
    RESEARCHER = "researcher"
    SUMMARIZER = "summarizer"
    FACT_CHECKER = "fact_checker"
    COORDINATOR = "coordinator"


@dataclass
class Finding:
    """A piece of information found by an agent."""
    content: str
    source: str
    confidence: float  # 0.0 to 1.0
    verified: bool = False


@dataclass
class ResearchResult:
    """The final output of the research team."""
    topic: str
    summary: str
    findings: List[Finding]
    fact_check_notes: str


class BaseAgent:
    """Base class for all agents in the team."""

    def __init__(self, name: str, role: AgentRole):
        self.name = name
        self.role = role
        self.scanner = InjectionScanner()

    def _check_security(self, content: str) -> bool:
        """Check content for injection attempts."""
        result = self.scanner.scan(content)
        return result["risk_level"] != "high"


class ResearcherAgent(BaseAgent):
    """Agent specialized in finding information."""

    def __init__(self, name: str = "Researcher"):
        super().__init__(name, AgentRole.RESEARCHER)

    async def research(self, topic: str) -> List[Finding]:
        """
        Research a topic and return findings.

        In a real implementation, this would:
        - Search Moltbook posts
        - Query external APIs
        - Analyze relevant content
        """
        if not self._check_security(topic):
            return []

        # Simulated research results
        # In production, this would query real sources
        findings = [
            Finding(
                content=f"Key insight about {topic}: [simulated finding 1]",
                source="m/research",
                confidence=0.85
            ),
            Finding(
                content=f"Additional context on {topic}: [simulated finding 2]",
                source="m/science",
                confidence=0.75
            ),
            Finding(
                content=f"Expert opinion on {topic}: [simulated finding 3]",
                source="m/experts",
                confidence=0.90
            ),
        ]

        return findings


class SummarizerAgent(BaseAgent):
    """Agent specialized in condensing information."""

    def __init__(self, name: str = "Summarizer"):
        super().__init__(name, AgentRole.SUMMARIZER)

    async def summarize(self, findings: List[Finding]) -> str:
        """
        Summarize a list of findings.

        In a real implementation, this would:
        - Use an LLM to synthesize information
        - Identify key themes
        - Create a coherent narrative
        """
        if not findings:
            return "No findings to summarize."

        # Simulated summarization
        # In production, this would use an LLM
        summary_parts = []
        for i, finding in enumerate(findings, 1):
            if self._check_security(finding.content):
                summary_parts.append(f"{i}. {finding.content}")

        return "Summary of findings:\n" + "\n".join(summary_parts)


class FactCheckerAgent(BaseAgent):
    """Agent specialized in verifying claims."""

    def __init__(self, name: str = "FactChecker"):
        super().__init__(name, AgentRole.FACT_CHECKER)

    async def verify(self, findings: List[Finding]) -> tuple[List[Finding], str]:
        """
        Verify findings and mark them as verified or not.

        In a real implementation, this would:
        - Cross-reference multiple sources
        - Check against known facts
        - Flag uncertain claims
        """
        notes = []

        for finding in findings:
            if not self._check_security(finding.content):
                finding.verified = False
                notes.append(f"- Skipped suspicious content")
                continue

            # Simulated verification
            # In production, this would actually verify claims
            if finding.confidence >= 0.8:
                finding.verified = True
                notes.append(f"- Verified: {finding.content[:50]}...")
            else:
                finding.verified = False
                notes.append(f"- Unverified (low confidence): {finding.content[:50]}...")

        return findings, "\n".join(notes)


class ResearchCoordinator(BaseAgent):
    """
    Coordinator that orchestrates the research team.
    """

    def __init__(self, name: str = "Coordinator"):
        super().__init__(name, AgentRole.COORDINATOR)
        self.researcher = ResearcherAgent()
        self.summarizer = SummarizerAgent()
        self.fact_checker = FactCheckerAgent()

    async def research_topic(self, topic: str) -> ResearchResult:
        """
        Coordinate a full research workflow.

        1. Researcher finds information
        2. Fact Checker verifies findings
        3. Summarizer creates summary
        """
        print(f"[{self.name}] Starting research on: {topic}")

        # Security check on topic
        if not self._check_security(topic):
            return ResearchResult(
                topic=topic,
                summary="Research blocked due to security concerns.",
                findings=[],
                fact_check_notes="Topic failed security check."
            )

        # Step 1: Research
        print(f"[{self.researcher.name}] Researching...")
        findings = await self.researcher.research(topic)
        print(f"[{self.researcher.name}] Found {len(findings)} items")

        # Step 2: Fact Check
        print(f"[{self.fact_checker.name}] Verifying...")
        verified_findings, fact_notes = await self.fact_checker.verify(findings)
        verified_count = sum(1 for f in verified_findings if f.verified)
        print(f"[{self.fact_checker.name}] Verified {verified_count}/{len(findings)}")

        # Step 3: Summarize
        print(f"[{self.summarizer.name}] Summarizing...")
        summary = await self.summarizer.summarize(verified_findings)

        return ResearchResult(
            topic=topic,
            summary=summary,
            findings=verified_findings,
            fact_check_notes=fact_notes
        )


async def main():
    """Demo the research team."""
    coordinator = ResearchCoordinator()

    # Research a topic
    result = await coordinator.research_topic("artificial intelligence safety")

    print("\n" + "=" * 50)
    print("RESEARCH COMPLETE")
    print("=" * 50)
    print(f"\nTopic: {result.topic}")
    print(f"\n{result.summary}")
    print(f"\nFact Check Notes:\n{result.fact_check_notes}")
    print(f"\nFindings verified: {sum(1 for f in result.findings if f.verified)}/{len(result.findings)}")


if __name__ == "__main__":
    asyncio.run(main())
