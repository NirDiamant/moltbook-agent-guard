# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this toolkit, please report it responsibly.

### For Non-Critical Issues
- Open a GitHub issue using the "Security Pattern" template
- This is appropriate for new attack patterns that should be added to the scanner

### For Critical Vulnerabilities
- **Do NOT** open a public issue
- Email the maintainer directly at: diamantnir@gmail.com
- Include:
  - Description of the vulnerability
  - Steps to reproduce
  - Potential impact
  - Suggested fix (if any)

### What to Expect
- Acknowledgment within 48 hours
- Regular updates on progress
- Credit in the changelog (unless you prefer anonymity)

## Scope

This security policy covers:
- The `moltbook` CLI tool
- The injection scanner
- Docker configurations
- Example code and tutorials

## Known Limitations

### Scanner Limitations
The injection scanner is a defense-in-depth measure, not a guarantee:
- New attack patterns emerge constantly
- Sophisticated attacks may evade detection
- False negatives are possible

**Always combine with:**
- Strong system prompts (AGENTS.md)
- Docker isolation
- Budget controls
- Human monitoring

### What We Don't Cover
- Vulnerabilities in third-party dependencies (report to them directly)
- Moltbook platform vulnerabilities (report to Moltbook)
- LLM provider vulnerabilities (report to Anthropic/OpenAI)

## Security Best Practices

When using this toolkit:

1. **Never commit credentials**
   - Use `.moltbook/credentials.json` (gitignored)
   - Use environment variables in production

2. **Always use Docker isolation**
   - Don't run agents directly on your machine
   - Use the hardened Docker configuration

3. **Enable all security features**
   - Injection scanner: ON
   - Budget controls: ON
   - Rate limiting: ON

4. **Monitor your agent**
   - Use the observatory dashboard
   - Review logs regularly
   - Set up alerts for anomalies

5. **Keep updated**
   - Watch this repo for security updates
   - Update scanner patterns regularly

## Acknowledgments

Thanks to security researchers who have contributed patterns:
- (Your name could be here!)

## Resources

- [OWASP LLM Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [Prompt Injection Defenses](https://github.com/tldrsec/prompt-injection-defenses)
- [Simon Willison's Prompt Injection](https://simonwillison.net/series/prompt-injection/)
