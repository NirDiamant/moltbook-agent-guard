# Moltbook Agent - Security-Hardened Container
FROM python:3.11-slim

# Security: Run as non-root user
RUN groupadd -r moltbook && useradd -r -g moltbook moltbook

# Install dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY tools/ ./tools/
COPY archetypes/ ./archetypes/
COPY moltbook ./moltbook

# Copy config files (these will be overwritten by volume mounts)
COPY agent_config.yaml .
COPY SOUL.md .
COPY AGENTS.md .

# Create data directory for persistent state
RUN mkdir -p /app/.moltbook && chown -R moltbook:moltbook /app

# Security: Switch to non-root user
USER moltbook

# Health check
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
  CMD python -c "import tools.agent; print('ok')" || exit 1

# Run the agent
CMD ["python", "-c", "import sys; sys.path.insert(0, '.'); from tools.agent import MoltbookAgent; agent = MoltbookAgent.from_config('agent_config.yaml'); agent.run()"]
