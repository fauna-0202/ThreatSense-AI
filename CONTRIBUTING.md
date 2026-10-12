# Contributing to ThreatSense AI

Thank you for your interest in contributing to **ThreatSense AI**! We welcome contributions that enhance detection capabilities, improve explainability, optimize latency, or expand documentation.

---

## Code of Conduct & Responsible Security

ThreatSense AI is dedicated to defensive cybersecurity research and telemetry engineering. Contributions must uphold these principles:
- **Defensive & Passive Focus:** Contributions introducing intrusive packet injection, offensive probing, or active network disruptions will not be accepted.
- **Privacy First:** Never commit packet captures containing sensitive organizational data, credentials, or private personal data.
- **Reproducibility:** Code changes involving feature engineering or machine learning models must include unit tests and reproducible training commands.

---

## Development Workflow

1. **Fork & Clone:**
   ```bash
   git clone https://github.com/your-username/ThreatSense-AI.git
   cd ThreatSense-AI
   ```

2. **Environment Setup:**
   ```bash
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1   # On Windows
   # source .venv/bin/activate    # On Linux/macOS
   pip install --upgrade pip
   pip install -r requirements.txt
   pip install -e .
   cp .env.example .env
   ```

3. **Branching Strategy:**
   Create a focused feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

4. **Code Quality & Testing:**
   Ensure all tests pass before opening a Pull Request:
   ```bash
   pytest -v
   ```
   Add new tests in `tests/unit/`, `tests/integration/`, `tests/model/`, or `tests/security/` as appropriate for your changes.

5. **Commit Messages:**
   Use clear, conventional commit messages:
   - `feat(detection): add entropy-based rate limiting indicator`
   - `fix(parser): handle malformed timestamp edge-case in zeek TSV`
   - `docs(setup): clarify WSL2 capture capabilities`
   - `test(security): add test for oversized payload boundary`

6. **Pull Request Submission:**
   Push your branch and open a Pull Request describing:
   - The rationale for the change.
   - The testing performed and results.
   - Any modifications to configuration schemas or documentation.
