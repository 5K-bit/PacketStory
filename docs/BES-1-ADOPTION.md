# BES-1 adoption: PacketStory

**State:** Proposed documentation-only adoption, not operational certification.  
**Scope:** standalone Blackfong engineering tool.  
**Project role:** pcap and pcapng flow analysis with narrative evidence.  
**Policy:** [Blackfong Engineering Standard BES-1](https://github.com/5K-bit/O.B.E.O.S/blob/main/docs/standards/BES-1.md).

## Baseline

Existing workflow files identified: `ci.yml, release.yml`. Presence alone does **not** prove a passing CI run, valid release artifact or real-world acceptance. This change does not replace current workflow, test commands or packaging.

## Lifecycle and evidence

- **Built:** commit, changed interfaces, repeatable criteria, threats and rollback recorded.
- **Verified:** applicable tests/CI linked for exact SHA; mocks, skips and absent external dependencies explicitly noted.
- **Released:** reproducible artifact or deployment with version, integrity, install verification and recovery instructions.
- **Operational:** dated acceptance in actual environment, with observed failure and recovery; no promotion from tests or a release badge alone.

### Project-specific checks

Correct parsing of pcaps, malformed/truncated captures and edge protocol cases; bounded resource use; packet-to-narrative evidence links; anonymization and redaction; replayable fixture-based reports.

**Evidence boundary:** Descriptive summaries cannot assert malicious intent without packet evidence.

## Follow-up execution gates

1. Record current automated tests and a real acceptance/failure scenario.
2. Introduce compatible task aliases only if they wrap existing inspected commands, with Linux/Windows validation as appropriate.
3. Keep security scans and dependency upgrades as separate, evaluated PRs; never silently change data access or external side effects.
4. Review the actual release job and rollback procedure before the next published version.

**AI assistance:** document generated/reviewed contributions.  
**Human verification:** include commands, host/browser versions, dates and evidence where performed; otherwise mark **not run**.
