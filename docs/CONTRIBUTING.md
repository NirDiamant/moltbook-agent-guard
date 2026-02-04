# Contributing to Building Moltbook Agents

Thank you for your interest in contributing! This guide will help you get started.

## Ways to Contribute

### 1. Report Security Issues

Found a new attack pattern? Please:
1. **Do not** publish it publicly first
2. Open a private security advisory or email the maintainer
3. Include a proof-of-concept if possible
4. We'll add it to the scanner and credit you

### 2. Improve the Scanner

The injection scanner can always be improved:
- Add new attack patterns
- Reduce false positives
- Improve detection logic
- Add new categories

**To add a new pattern:**
```python
# In scanner.py, add to PATTERNS dict:
"new_category": {
    "risk": "high",  # or "medium" or "low"
    "patterns": [
        r"your_regex_pattern_here",
    ]
}
```

### 3. Create New Archetypes

Have an idea for a new agent archetype? Each archetype needs:
- `SOUL.md` - Personality definition
- `AGENTS.md` - Security directives
- `config.json` - Configuration

See existing archetypes in `/archetypes` for examples.

### 4. Write Tutorials

Good tutorials:
- Follow the existing format (Overview, Why It Matters, Implementation, Try It Yourself)
- Include runnable code
- Build on previous tutorials
- Are tested and working

### 5. Share Your Agent

Built something cool? Add it to the gallery:
1. Create a folder in `/gallery/agents/your-agent/`
2. Include a README with description and screenshot
3. Link to your live agent on Moltbook

## Development Setup

```bash
# Clone the repo
git clone https://github.com/NirDiamant/moltbook-agent-guard.git
cd moltbook-agent-guard

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black .
ruff check .
```

## Code Style

- Use Black for formatting
- Use Ruff for linting
- Follow existing patterns
- Write docstrings for public functions
- Add type hints where reasonable

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Run tests: `pytest`
5. Format code: `black . && ruff check .`
6. Commit with clear message: `git commit -m "Add amazing feature"`
7. Push to your fork: `git push origin feature/amazing-feature`
8. Open a Pull Request

### PR Checklist

- [ ] Tests pass
- [ ] Code is formatted
- [ ] Documentation updated if needed
- [ ] No secrets or credentials in code
- [ ] Follows security best practices

## Questions?

Open an issue with the "question" label or reach out to the maintainer.

## Code of Conduct

Be respectful. Be helpful. Build cool things safely.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
