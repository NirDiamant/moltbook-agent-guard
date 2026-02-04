# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-02

### Added

#### CLI Tool (`moltbook`)
- `moltbook init` - Interactive setup wizard with archetype selection
- `moltbook deploy` - Docker-based secure deployment
- `moltbook status` - Agent and container status monitoring
- `moltbook scan` - Prompt injection scanning for posts
- `moltbook cost estimate` - Cost projection for different models
- `moltbook cost budget` - Set daily/monthly spending limits
- `moltbook cost usage` - View current API usage
- `moltbook observatory` - Real-time web monitoring dashboard

#### Injection Scanner
- 9 attack category detection:
  - Instruction Override
  - Role Hijacking
  - Credential Extraction
  - Hidden Content (HTML comments, zero-width chars)
  - Jailbreak Attempts
  - Data Exfiltration
  - Encoded Payloads (Base64, hex)
  - System Prompt Extraction
  - Subtle Manipulation
- Known attack string matching
- Base64 payload decoding and scanning
- Content sanitization (`defend` mode)

#### Agent Archetypes
- Teacher - Patient educator for learning
- Curator - Content discoverer and organizer
- Comedian - Witty entertainer with wholesome humor
- Philosopher - Deep thinker for thoughtful discourse
- Researcher - Fact-finder with verification focus
- Moderator - Community manager for healthy discussions

#### Security Framework
- `SECURITY_CHECKLIST.md` - Pre-deployment security checklist
- Hardened Docker configuration (non-root, dropped capabilities, read-only)
- Known attacks catalog with detection patterns

#### Tutorials
- Tutorial 01: Why Moltbook Matters
- Tutorial 02: Secure Setup with Docker
- Tutorial 03: Your First Agent
- Tutorial 04: Agent Personality with SOUL.md
- Tutorial 05: Building a Teacher Agent
- Tutorial 06: Prompt Injection Defense (NEW)
- Tutorial 07: Cost Management (NEW)
- Tutorial 08: Production-Ready Agent (NEW)

#### Documentation
- `docs/API.md` - Moltbook API and toolkit API reference
- `docs/ARCHITECTURE.md` - System architecture overview
- `docs/CONTRIBUTING.md` - Contribution guidelines

#### Integrations
- RAG integration guide
- MoltBrain integration guide
- Multi-agent systems guide

#### Infrastructure
- `pyproject.toml` for pip installation
- GitHub Actions CI/CD workflow
- Issue templates (bug, feature, security)
- Gallery structure for community agents

### Security
- Docker isolation with security hardening
- Budget controls to prevent runaway costs
- Real-time injection scanning
- Defensive system prompt templates

---

## [Unreleased]

### Planned
- Additional archetypes (analyst, creative writer)
- Scanner improvements based on new attack patterns
- Integration with more LLM providers
- Enhanced observatory with historical metrics
