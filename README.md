<p align="center">
  <img src="assets/logo.svg" alt="Moltbook Agent Guard" width="400">
</p>

<h1 align="center">Moltbook Agent Guard</h1>

<p align="center">
  <strong>Real-time security for AI agents on Moltbook</strong>
</p>

<p align="center">
  <a href="https://moltbook.com"><img src="https://img.shields.io/badge/Moltbook-770K+_Agents-purple" alt="Moltbook"></a>
  <img src="https://img.shields.io/badge/Security-First-green" alt="Security First">
  <img src="https://img.shields.io/badge/License-Apache_2.0-blue" alt="License">
</p>

<p align="center">
  <a href="https://www.linkedin.com/in/nir-diamant-759323134/"><img src="https://img.shields.io/badge/LinkedIn-Connect-blue" alt="LinkedIn"></a>
  <a href="https://twitter.com/NirDiamantAI"><img src="https://img.shields.io/twitter/follow/NirDiamantAI?label=Follow&style=social" alt="Twitter"></a>
  <a href="https://discord.gg/cA6Aa4uyDX"><img src="https://img.shields.io/badge/Discord-Join-7289da" alt="Discord"></a>
</p>

---

## 📫 Stay Updated

<p align="center">
  <a href="https://diamantai.substack.com/?r=336pe4&utm_campaign=pub-share-checklist">
    <img src="images/subscribe-button.svg" alt="Subscribe to Newsletter">
  </a>
  <br>
  <em>Join 50,000+ AI enthusiasts for cutting-edge insights and tutorials</em>
</p>

[![DiamantAI Newsletter](images/substack_image.png)](https://diamantai.substack.com/?r=336pe4&utm_campaign=pub-share-checklist)

---

## Why This Toolkit?

[Moltbook](https://moltbook.com) is the world's largest social network for AI agents (770K+ agents). Research shows **2.6% of posts contain prompt injection attacks** targeting vulnerable agents.

This toolkit protects your agent from hijacking, credential theft, and manipulation.

<p align="center">
  <img src="assets/security_dashboard.png" alt="Security Dashboard" width="800">
  <br>
  <em>Real threats detected and blocked on Moltbook</em>
</p>

### Attacks Blocked

| Attack Type | Risk |
|-------------|------|
| Jailbreak attempts | 🔴 High |
| Credential extraction | 🔴 High |
| Data exfiltration | 🔴 High |
| System prompt extraction | 🔴 High |
| Role hijacking | 🟡 Medium |
| Encoded payloads | 🟡 Medium |

### How It Works

When your agent runs, the security scanner protects it **in real-time**:

<p align="center">
  <img src="assets/how-it-works.svg" alt="How It Works" width="700">
</p>

```python
# Inside the agent runtime (tools/agent/runtime.py)
def _process_post(self, post):
    is_safe, scan_result = self._scan_content(post.content)  # Every post is scanned
    if not is_safe:
        return None  # Malicious content never reaches your LLM
    # ... process safe content
```

**Without this toolkit:** Your agent processes malicious posts and risks leaking API keys or getting hijacked.

**With this toolkit:** Threats are detected and blocked before they ever reach your LLM.

---

## Quick Start

```bash
git clone https://github.com/NirDiamant/moltbook-agent-toolkit.git
cd moltbook-agent-toolkit
pip install -r requirements.txt

# Setup (interactive wizard)
export MOLTBOOK_API_KEY="your_key"
export ANTHROPIC_API_KEY="your_key"
./moltbook init

# Deploy
./moltbook deploy --direct
```

---

## Security Dashboard

Deploy your own dashboard to track threats in real-time.

**Streamlit Cloud (Free, 2 min):**
1. Fork this repo
2. Go to [share.streamlit.io](https://share.streamlit.io)
3. Set app path: `dashboard/streamlit_app.py`
4. Add secret: `MOLTBOOK_API_KEY = "your_key"`
5. Deploy

**Local:**
```bash
MOLTBOOK_API_KEY="your_key" streamlit run dashboard/streamlit_app.py
```

---

## CLI Commands

```bash
./moltbook init                    # Setup wizard
./moltbook deploy                  # Deploy agent
./moltbook security                # View security incidents
./moltbook security --scan         # Scan for threats
./moltbook security --html report.html  # Export report
```

---

## Security Modules

24 modules across 6 protection layers:

- **Critical**: Output scanner, error sanitizer, log redactor
- **AI Firewall**: Llama Guard + LLM Guard + pattern matching
- **Platform**: Memory sanitizer, egress firewall, credential monitor
- **Social**: Social engineering detection, reputation protection
- **Data**: Exfiltration prevention, financial safety
- **Infrastructure**: Docker isolation (cap_drop ALL, read-only fs)

```python
from tools.security import SecurityManager

security = SecurityManager(level="standard")
result = security.scan_input(user_content)
if result.blocked:
    print(f"Blocked: {result.reason}")
```

---

## Related Projects

- **[Agents Towards Production](https://github.com/NirDiamant/agents-towards-production)** — Production-grade GenAI agent tutorials
- **[GenAI Agents](https://github.com/NirDiamant/GenAI_Agents)** — AI agent implementations from simple to complex
- **[RAG Techniques](https://github.com/NirDiamant/RAG_Techniques)** — Comprehensive RAG guide
- **[Prompt Engineering](https://github.com/NirDiamant/Prompt_Engineering)** — Prompting strategies collection

---

## License

Apache 2.0 — see [LICENSE](LICENSE)
