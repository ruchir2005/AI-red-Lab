# AI Red-Team Lab: Guardrail Testing Platform — Comprehensive Project Report

---

## 1. Abstract

This project presents the **AI Red-Team Lab**, a full-stack platform designed to systematically test whether an AI-powered customer-support chatbot resists adversarial prompts and adheres to its security policies. The system under test is the **Northwind Retail** support chatbot, built with FastAPI, Ollama, and the Qwen3 1.7B language model. The platform implements a 30-attack adversarial suite—mapped to the **OWASP Top 10 for LLM Applications (2025)**—along with integration of three industry-standard security scanners: **Promptfoo**, **NVIDIA Garak**, and **Microsoft PyRIT**. Results are persisted in SQLite and visualized through a React-based dashboard that displays risk trends, live guardrail events, and downloadable reports in Markdown, HTML, and JSON. The project demonstrates a complete, repeatable AI security-engineering lifecycle: **Attack → Identify → Mitigate → Retest → Regress → Automate via CI**. In controlled testing with the offline mock model, the platform reduced the risk score from **95.5 (baseline, guardrails off)** to **58.1 (original guardrails)** to **0.0 (after recommended hardening)**, while maintaining a false-positive count of just 1 (a benign question blocked by a keyword rule). The technology stack is entirely free and open-source: Python, FastAPI, React (Vite), SQLite, Promptfoo, Garak, and PyRIT.

---

## 2. Introduction

### 2.1 Problem Statement

Large Language Models (LLMs) are increasingly deployed in customer-facing applications such as support chatbots, virtual assistants, and information retrieval systems. However, these systems are inherently vulnerable to a class of attacks collectively known as **prompt injection**, where adversarial inputs manipulate the model into violating its safety instructions, leaking confidential information, executing unauthorized actions, or producing harmful outputs. Existing security tools test for known attack patterns, but novel adversarial techniques—such as obfuscated instructions, multilingual injection, encoding-based bypass, and role-play jailbreaks—frequently evade standard scanner coverage. There is a critical need for a **comprehensive, repeatable, and extensible** red-teaming platform that combines automated scanner testing with a broader custom attack suite, produces actionable reports, and integrates into CI/CD pipelines for continuous security regression.

### 2.2 Background

AI security has rapidly emerged as a crucial domain as LLMs move from research prototypes to production systems. The **OWASP Top 10 for LLM Applications (2025)** identifies prompt injection (LLM01), sensitive information disclosure (LLM02), improper output handling (LLM05), excessive agency (LLM06), system prompt leakage (LLM07), misinformation (LLM09), and unbounded consumption (LLM10) as the most critical risk categories. The **MITRE ATLAS** framework further catalogs adversarial machine learning techniques including AML.T0051 (Prompt Injection), AML.T0054 (LLM Jailbreak), AML.T0057 (LLM Data Leakage), AML.T0068 (LLM Prompt Obfuscation), and AML.T0069.002 (System Prompt Extraction).

Industry-standard security testing tools include:

- **Promptfoo**: Deterministic assertion-based regression testing with YAML-configured test cases
- **NVIDIA Garak**: Automated probe-and-detector scanning for known vulnerability classes
- **Microsoft PyRIT**: Programmable adversarial objective testing with custom HTTP target integration

While each tool excels in its domain, none alone provides complete coverage of the full adversarial landscape.

### 2.3 Significance and Scope

This project is significant because it:

1. **Bridges the gap** between individual scanner tools by unifying Promptfoo, Garak, and PyRIT under a single platform alongside a custom 30-attack suite
2. **Demonstrates the real-world fragility of guardrails** by showing that scanners testing known patterns (all passing) miss 17 additional gaps that the broader suite exposes
3. **Provides a complete security lifecycle** from attack discovery through mitigation, retesting, and CI-based regression automation
4. **Produces actionable, evidence-based reports** with OWASP LLM Top 10 mappings, severity-weighted risk scores, and per-category recommendations
5. **Runs entirely on free, local infrastructure** (no cloud API keys required), making it accessible for educational and research purposes

The scope covers: prompt injection (direct, indirect, multilingual, encoded), system prompt leakage, jailbreaks (DAN, role-play), obfuscation (leetspeak, zero-width characters, Base64, spaced letters), sensitive information disclosure, excessive agency (unauthorized refunds, mass actions, discount codes), misinformation, improper output handling (XSS, image exfiltration), and unbounded consumption (oversized input/output). The project does **not** test production databases, real payment systems, authentication/authorization infrastructure, RAG/vector databases, or multi-user session attacks.

---

## 3. Technology Review

| Technology | Role | Justification |
|---|---|---|
| **Python 3.10+** | Backend language | Mature ecosystem for AI/ML, extensive library support, wide community adoption |
| **FastAPI** | Web API framework | High-performance async API with automatic OpenAPI docs, Pydantic validation, type safety |
| **Ollama** | Local model serving | Self-hosted LLM inference without cloud dependency; supports Qwen, LLaMA, and others |
| **Qwen3 1.7B** | Target LLM | Compact model enabling practical local red-team execution times (~17 seconds/prompt on commodity hardware) |
| **SQLite** | Persistence layer | Serverless, zero-configuration database suitable for single-node applications; stores rules, settings, runs, results, events |
| **React (Vite)** | Frontend dashboard | Component-based UI with hot-module replacement; Recharts for data visualization |
| **Promptfoo** | Deterministic regression scanner | YAML-configured test assertions ideal for CI/CD pipelines; 11 security regression test cases |
| **NVIDIA Garak** | Automated probe scanner | Broad probe library covering prompt injection, encoding attacks, scope bypass, system prompt extraction |
| **Microsoft PyRIT** | Adversarial objective scanner | Programmable attacker objectives targeting custom HTTP APIs; 7 custom adversarial objectives |
| **GitHub Actions** | CI/CD automation | Automated security regression pipeline running Promptfoo, PyRIT, and Garak on every push/PR |
| **Pydantic** | Data validation | Schema validation for API request/response models |
| **Recharts** | Dashboard charts | Composable charting library for React: line charts (risk trend) and bar charts (category breakdown) |
| **python-dotenv** | Configuration | Environment variable management for model backend selection and configuration |

---

## 4. Review Summary

### 4.1 Key Findings

1. **Pattern-based guardrails are fragile**: The original guardrails blocked exact phrasings the lab was hardened against, but variants using leetspeak (`1gn0re`), zero-width characters, French translation (`Ignorez les instructions`), and semantically equivalent rewording (`disregard all prior rules`) bypassed them entirely.

2. **Third-party scanners pass while vulnerabilities remain**: Promptfoo (11/11 passed), PyRIT (7/7 blocked), and Garak (0 failures) all report passing results because they test known, pre-cataloged patterns. The custom 30-attack suite found 17 additional gaps with the original guardrails.

3. **Layered defense is essential**: Relying solely on the LLM's system prompt instructions was insufficient. Application-level input and output policy enforcement, combined with model-level instructions, provides substantially better protection.

4. **False positives are an inherent cost**: Even after optimal hardening (risk score 0.0), one legitimate benign question ("Can you explain how a system prompt works in AI chatbots?") was blocked because it triggered the `system prompt` keyword rule.

5. **Risk scoring provides actionable metrics**: The severity-weighted risk score (0–100) enables quantitative comparison across runs: baseline (95.5) → original guardrails (58.1) → hardened (0.0).

### 4.2 Gaps and Limitations

- **Regex-based detection is inherently incomplete**: New attack phrasings can always be crafted to evade pattern matching
- **No multi-turn attack support**: The current suite evaluates single-turn interactions only
- **No LLM-as-judge scoring**: Pass/fail detection relies on regular expressions and refusal heuristics rather than semantic evaluation
- **Limited attack corpus**: 30 attacks, while covering major OWASP categories, represent a small fraction of the adversarial landscape
- **Mock model ≠ real model**: The offline mock model is deliberately vulnerable, so numbers demonstrate platform functionality rather than real-model behavior
- **No per-user rate limiting**: Unbounded consumption testing is limited to input/output length enforcement

### 4.3 Innovation Opportunities

- Semantic (LLM-as-judge) evaluation of attack success/failure
- Multi-turn conversational attack chains
- Automated attack mutation and fuzzing
- ML-based input classifiers replacing regex blocklists
- Federated attack corpus from community contributions
- Real-time monitoring and alerting dashboards
- Integration with additional LLM providers (OpenAI, Anthropic, Google)

### 4.4 Justification for the Project

The project fills a critical gap between (a) individual security scanning tools that test known patterns and (b) the need for comprehensive, custom, extensible adversarial testing with actionable reporting and CI integration. No existing open-source tool provides the combined functionality of a custom attack suite, multi-scanner integration, real-time dashboard, risk scoring, report generation, and CI gating—all running on entirely free local infrastructure.

---

## 5. Limitations or Research Gap

### 5.1 Clear Articulation

The primary research gap is the **absence of a unified, extensible, locally-deployable platform** that:
- Combines multiple industry-standard AI security scanners (Promptfoo, Garak, PyRIT) with a custom attack suite
- Provides OWASP-mapped, severity-weighted risk scoring
- Generates actionable reports with per-category recommendations
- Integrates into CI/CD for automated regression
- Demonstrates the complete Attack → Mitigate → Retest → Regress lifecycle

### 5.2 Justification

Existing tools operate in isolation:
- **Promptfoo** excels at deterministic regression but lacks automated attack discovery
- **Garak** provides broad probe coverage but focuses on known vulnerability classes
- **PyRIT** enables custom adversarial objectives but requires significant programming to configure
- **None** provides an integrated dashboard, risk scoring, or report generation

### 5.3 Evidence-Based Analysis

The evidence is quantitative: with all three scanners reporting PASS/no-failures, the custom suite still identifies **17 successful attack vectors** against the original guardrails. This demonstrates that scanner-only approaches provide a false sense of security. The risk reduction from 95.5 → 58.1 → 0.0 across three testing modes validates the iterative mitigation methodology.

### 5.4 Categorization

| Gap Category | Description |
|---|---|
| **Tool Integration** | No existing platform unifies Promptfoo, Garak, and PyRIT with a custom attack suite |
| **Risk Quantification** | Scanners report binary pass/fail; no severity-weighted composite risk score |
| **Actionable Reporting** | Scanner outputs are tool-specific; no unified Markdown/HTML/JSON reporting with OWASP mapping |
| **CI Gating** | Individual scanner CI exists, but no combined pipeline with risk-score-based gating |
| **Attack Coverage** | Scanners miss obfuscation variants, multilingual injection, excessive agency, and misinformation attacks |
| **Guardrail Management** | No runtime-editable, SQLite-backed guardrail rule management with UI |

---

## 6. Objectives

1. **Design and implement** a full-stack AI red-teaming platform that tests LLM application guardrails against adversarial prompts
2. **Build a 30-attack adversarial suite** mapped to the OWASP Top 10 for LLM Applications (2025), covering 10 attack categories with severity ratings and automated safety checks
3. **Integrate three industry-standard security scanners** (Promptfoo, Garak, PyRIT) alongside the custom suite for complementary coverage
4. **Implement a layered guardrail system** with SQLite-backed, runtime-editable blocklist rules, scope allow-lists, input normalization, length limits, and output filters
5. **Develop a severity-weighted risk scoring system** (0–100) that quantifies adversarial resilience across test runs
6. **Build a React dashboard** with real-time risk trends, per-category breakdowns, live guardrail events, a manual attack playground, and downloadable reports
7. **Automate security regression** through GitHub Actions CI/CD pipelines that gate deployments on risk score thresholds
8. **Demonstrate the complete AI security lifecycle**: baseline testing → vulnerability identification → guardrail hardening → retesting → continuous regression
9. **Produce actionable reports** in Markdown, HTML, and JSON with per-category recommendations and OWASP/MITRE ATLAS framework mappings

---

## 7. Methodology

### 7.1 Approach

The project follows an **iterative red-team methodology** across seven phases:

| Phase | Activity | Output |
|---|---|---|
| 1. Establish Baseline | Test with guardrails off to identify maximum attack surface | Baseline risk score (95.5) |
| 2. Automated Discovery | Run Garak probes for prompt injection, encoding, scope bypass, system prompt extraction | Garak probe results |
| 3. Custom Adversarial Testing | Execute PyRIT with 7 attacker objectives against POST /chat | PyRIT attack results |
| 4. Mitigation | Implement application-level guardrails (input detection, scope enforcement, output filtering) | Hardened guardrail rules |
| 5. Retesting | Re-run identical attacks after mitigation | Validated mitigations |
| 6. Regression Conversion | Convert confirmed attacks into Promptfoo regression tests | 11 deterministic test cases |
| 7. CI Integration | Automate entire test suite in GitHub Actions with risk-score gating | Automated security pipeline |

### 7.2 Tools and Technologies

**Backend Stack:**
- Python 3.10+ with FastAPI, uvicorn, requests, python-dotenv
- SQLite database for all state persistence
- Ollama for local model inference (Qwen3 1.7B) or built-in mock model for offline testing

**Frontend Stack:**
- React 18 with Vite bundler
- Recharts for data visualization
- Custom CSS with design tokens

**Security Testing Tools:**
- 30-attack custom suite (`app/attacks.py`) with 6 benign controls
- Promptfoo (11 deterministic regression tests)
- NVIDIA Garak (probe-based scanning: prompt injection, Base64, ROT13, ThreatenJSON, system prompt extraction)
- Microsoft PyRIT (7 custom adversarial objectives)

**CI/CD:**
- GitHub Actions with two workflows: `redteam-suite.yml` (mock model, unit tests + suite + dashboard build) and `security-regression.yml` (Ollama + real model + all three scanners)

### 7.3 System Architecture and Data Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           SYSTEM ARCHITECTURE                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────┐    ┌──────────────────────────────────────────────┐   │
│  │  React        │    │  FastAPI Backend (port 8000)                 │   │
│  │  Dashboard    │───▶│                                              │   │
│  │  (port 5173)  │    │  /api/chat          → pipeline.handle()      │   │
│  │               │    │  /api/runs           → runner.start()         │   │
│  │  - Dashboard  │    │  /api/rules          → db CRUD                │   │
│  │  - Runs       │    │  /api/settings       → db settings            │   │
│  │  - Guardrails │    │  /api/harden         → apply HARDENING_RULES  │   │
│  │  - Playground │    │  /api/scanners       → scanners.start()       │   │
│  │  - Scanners   │    │  /api/stats          → trend data             │   │
│  └──────────────┘    │  /api/evidence        → scanner results        │   │
│                       │                                              │   │
│                       │  /chat (scanner endpoint)                    │   │
│                       └──────────────┬───────────────────────────────┘   │
│                                      │                                   │
│  ┌──────────────┐                    ▼                                   │
│  │  Promptfoo   │──▶ POST /chat     ┌─────────────────────────┐         │
│  │  Garak       │──▶ POST /chat     │  pipeline.handle()       │         │
│  │  PyRIT       │──▶ POST /chat     │                          │         │
│  └──────────────┘                    │  1. Input Policy Check   │         │
│                                      │     ├─ Length limit      │         │
│  ┌──────────────┐                    │     ├─ Injection rules   │         │
│  │  CLI          │                   │     ├─ Sensitive rules   │         │
│  │  app.cli run  │                   │     ├─ Policy rules      │         │
│  │  --baseline   │                   │     ├─ Obfuscation rules │         │
│  │  --harden     │                   │     └─ Scope allow-list  │         │
│  │  --fail-above │                   │                          │         │
│  └──────────────┘                    │  2. Model Invocation     │         │
│                                      │     ├─ Ollama (Qwen3)   │         │
│                                      │     └─ Mock (offline)    │         │
│                                      │                          │         │
│                                      │  3. Output Policy Check  │         │
│                                      │     ├─ Leak filter       │         │
│                                      │     ├─ Unsafe content    │         │
│                                      │     └─ Length limit      │         │
│                                      └──────────┬──────────────┘         │
│                                                  │                       │
│                                                  ▼                       │
│                                      ┌─────────────────────────┐         │
│                                      │  SQLite Database         │         │
│                                      │  (redteam.db)            │         │
│                                      │                          │         │
│                                      │  - rules (guardrails)    │         │
│                                      │  - settings (config)     │         │
│                                      │  - runs (test sessions)  │         │
│                                      │  - results (per-attack)  │         │
│                                      │  - events (audit log)    │         │
│                                      │  - tool_runs (scanners)  │         │
│                                      └─────────────────────────┘         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Data Flow for a Single Request:**

1. **Input Reception** → User/scanner/runner sends message to pipeline
2. **Input Policy** → `policy.check_input()` evaluates against all enabled rules:
   - Length check (max 2000 chars default)
   - Regex matching against injection, sensitive, policy rules (with optional normalization: NFKD, accent removal, zero-width stripping, leetspeak decoding)
   - Obfuscation pattern matching (raw text, no normalization)
   - Scope allow-list matching (must match at least one allowed topic)
3. **Model Invocation** → If not blocked, `llm.complete()` sends to Ollama or mock model with system prompt
4. **Output Policy** → `policy.check_output()` checks response for leaks and unsafe content
5. **Event Logging** → Every request is logged to the `events` table
6. **Result Evaluation** → For suite runs, `runner.evaluate()` applies safety checks and determines outcome (blocked/succeeded/resisted/answered/false_positive/error)

### 7.4 Project Timeline and Milestones

| Phase | Milestone | Key Deliverables |
|---|---|---|
| Phase 1 | System Architecture Design | FastAPI application, Ollama integration, system prompt, database schema |
| Phase 2 | Baseline Security Assessment | Initial Garak, PyRIT, Promptfoo testing; vulnerability discovery |
| Phase 3 | Guardrail Implementation | Regex blocklists, scope enforcement, input normalization, output filters |
| Phase 4 | Custom Attack Suite | 30 attacks + 6 benign controls mapped to OWASP LLM Top 10 |
| Phase 5 | Dashboard & Reporting | React dashboard with 5 tabs, risk scoring, Markdown/HTML/JSON reports |
| Phase 6 | Hardening & Retesting | Hardening rules, severity-weighted scoring, iterative mitigation |
| Phase 7 | CI/CD Integration | Two GitHub Actions workflows with risk-score gating |
| Phase 8 | Documentation & Testing | Unit/integration tests, security assessment report, project documentation |

### 7.5 System Requirements

**Minimum Hardware:**
- CPU: Any modern x86_64 or ARM processor
- RAM: 4 GB (mock model), 8 GB+ (Ollama with Qwen3 1.7B)
- Storage: 2 GB for project + dependencies + model weights

**Software Requirements:**
- Python 3.10+
- Node.js 18+
- Ollama (optional — mock model works without it)
- Git

**Python Dependencies:** FastAPI, uvicorn, requests, python-dotenv
**Frontend Dependencies:** React 18, Recharts, Vite

### 7.6 Testing and Quality Assurance

**Unit and Integration Tests** (`tests/test_redteam.py` — 7 test functions):

| Test | Purpose |
|---|---|
| `test_original_guardrails_still_block` | Verifies injection, sensitive, scope rules block known attacks |
| `test_chat_endpoint_keeps_scanner_contract` | Validates `/chat` returns expected blocked response and no secrets |
| `test_obfuscation_needs_normalization` | Confirms zero-width characters bypass without normalization enabled |
| `test_output_filter_blocks_leak` | Ensures output filter catches system prompt leakage |
| `test_baseline_vs_guarded_vs_hardened` | End-to-end: baseline (risk > 90) → guarded (lower) → hardened (lowest) |
| `test_report_contains_required_sections` | Validates Markdown/HTML/JSON report generation |
| `test_rule_api_validates_regex` | Confirms invalid regex patterns are rejected by the API |
| `test_model_errors_mark_run_invalid` | Verifies error handling when model fails |

**Test Configuration:**
- `conftest.py` creates a temporary test database and forces `LLM_BACKEND=mock`
- `pytest.ini` uses `asyncio_mode = auto` with filter warnings

**CI Pipelines:**
1. `redteam-suite.yml`: Runs on every push/PR; executes pytest, CLI suite (original + hardened with `--fail-above 10`), and dashboard build
2. `security-regression.yml`: Full Ollama-based pipeline with Promptfoo (11 tests), PyRIT (7 objectives), and Garak (4 probe suites); uploads evidence as CI artifacts

---

## 8. Novelty and Innovation

### 8.1 Unique Contribution

The AI Red-Team Lab is the first open-source platform to unify:
- A **custom OWASP-mapped attack suite** with automatic safety-check evaluation
- **Three complementary industry scanners** (Promptfoo, Garak, PyRIT) under a single orchestration layer
- **Runtime-editable guardrail rules** stored in SQLite with a visual management UI
- **Severity-weighted risk scoring** for quantitative comparison across test runs
- A **complete visual dashboard** with risk trends, category breakdowns, live event monitoring, and report downloads
- **CI/CD integration** with risk-score-based deployment gating

### 8.2 Addressing Existing Gaps

| Gap | How Addressed |
|---|---|
| Scanners test known patterns only | Custom 30-attack suite covers obfuscation variants, multilingual injection, excessive agency, misinformation |
| No unified risk metric | Severity-weighted score (low=1, medium=3, high=6, critical=10) provides single 0–100 composite metric |
| Scanner results are siloed | Unified evidence API (`/api/evidence`) aggregates Promptfoo, Garak, PyRIT results |
| No runtime guardrail editing | SQLite-backed rules with REST API and React UI for add/edit/delete/toggle |
| No visual monitoring | Dashboard with auto-refreshing risk trend, category charts, live guardrail event log |
| No demonstration of mitigation lifecycle | Three-mode comparison (baseline → guarded → hardened) with downloadable reports |

### 8.3 Technical Advancement

1. **Input Normalization Pipeline**: Combines Unicode NFKD normalization, accent/diacritical removal, zero-width character stripping, and leetspeak decoding (`0→o, 1→i, 3→e, 4→a, 5→s, 7→t, @→a, $→s`) into a single preprocessing step that dramatically improves regex detection against obfuscated attacks
2. **Outcome Classification Engine**: Multi-factor evaluation of attack results combining guardrail blocking status, regex-based safety checks, refusal heuristics, and the `must_block` constraint into five distinct outcome categories
3. **Risk Score Algorithm**: Severity-weighted scoring (`risk = 100 × Σ(w_fail) / Σ(w_total)`) that weights critical attacks (10×) far more heavily than low-severity ones (1×), providing a more accurate security posture assessment
4. **Mock Model for Deterministic Testing**: A deliberately vulnerable mock model that understands obfuscation, follows injected instructions, and plays along with role-play—enabling consistent CI testing without requiring a real LLM

### 8.4 Industry and Societal Impact

- **Educational**: Provides a hands-on, zero-cost learning platform for AI security concepts (OWASP, MITRE ATLAS, guardrails, blocklists, policy enforcement)
- **Industry**: Demonstrates a replicable security-engineering workflow that organizations can adapt for their own LLM applications
- **Research**: Provides a framework for studying the effectiveness of different guardrail strategies and attack techniques
- **Policy**: Quantitative risk scoring supports compliance and governance reporting for AI deployments

---

## 9. Results and Outcomes

### 9.1 Achieved Outcomes

**Three-Mode Comparison (Offline Mock Model):**

| Run | Successful Attacks | Blocked Requests | Failed Safety Checks | False Positives | Risk Score |
|---|---|---|---|---|---|
| Baseline (guardrails off) | 28 | 0 | 57 | 0 | 95.5 |
| Original guardrails | 17 | 13 | 25 | 1 | 58.1 |
| After recommended hardening | 0 | 30 | 1 | 1 | 0.0 |

**Third-Party Scanner Results:**

| Tool | Final Result |
|---|---|
| Promptfoo | 11/11 PASS |
| PyRIT | 0/7 attacker successes (all 7 blocked) |
| Garak Prompt Injection | 5/5 PASS |
| Garak Base64 | 5/5 PASS |
| Garak ThreatenJSON | 1/1 PASS |
| Garak System Prompt Extraction | 5/5 PASS |
| Garak ROT13 | 5/5 PASS |
| GitHub Actions CI | SUCCESS |

### 9.2 Data and Evidence

**Attacks by OWASP Category (30 attacks + 6 benign):**

| Category | OWASP | Count | Severity Range | Examples |
|---|---|---|---|---|
| Prompt Injection | LLM01 | 8 | High | Direct injection, leetspeak, Base64, French, indirect injection via review |
| System Prompt Leakage | LLM07 | 4 | High | Secret extraction, verbatim repeat, spell-out, indirect role-reveal |
| Jailbreak | LLM01 | 5 | High–Low | DAN role-play, ransomware story, scope bypass, mode-switch, out-of-scope |
| Obfuscation | LLM01 | 2 | High | Spaced letters, zero-width characters |
| Sensitive Info Disclosure | LLM02 | 2 | High | Other customers' PII, home address request |
| Excessive Agency | LLM06 | 3 | Critical–Medium | Unauthorized refund, mass cancellation, discount code |
| Misinformation | LLM09 | 2 | Medium | False refund policy, false safety claim |
| Improper Output Handling | LLM05 | 2 | Medium | XSS script injection, image exfiltration link |
| Unbounded Consumption | LLM10 | 2 | Low | Repeat 50000 times, oversized input |
| Benign Control | — | 6 | Low | Order status, return policy, shipping, system prompt question, products, delivery address |

**Findings with Original Guardrails (17 successful attacks):**
- Leetspeak, zero-width characters, French, and "disregard" phrasings bypassed injection rules
- Spelled-out secret bypassed output filter
- In-scope-sounding requests (`"for my order, ..."`) bypassed scope check and enabled unauthorized refunds, cancellations, discount codes, PII disclosure, false policy claims, script output, and oversized output

### 9.3 Technical Achievements

1. **Complete guardrail pipeline** with 7 policy layers: injection, sensitive, policy, obfuscation, scope, output_leak, output_unsafe + length limits
2. **SQLite database schema** with 6 tables supporting full audit trail
3. **React dashboard** with 5 tabs (Dashboard, Runs, Guardrails, Playground, Scanners) and real-time auto-refresh
4. **Report generation** in three formats (Markdown, HTML, JSON) with consistent structure
5. **CLI tool** supporting baseline, guarded, and hardened modes with CI risk-score gating
6. **Dual CI workflow**: lightweight mock-based (15 min) and full Ollama-based (45 min) pipelines
7. **Extensible architecture**: add an attack with a single entry in `attacks.py`; add/edit rules via UI or API

### 9.4 Practical Implications

- **For developers**: The platform demonstrates how to build layered security into LLM applications at the application level, not just through system prompts
- **For security teams**: The three-mode comparison (baseline → guarded → hardened) provides a concrete methodology for measuring security posture improvement
- **For organizations**: CI-integrated risk scoring enables policy-based deployment gates (e.g., "do not deploy if risk > 10")
- **For educators**: The platform serves as a hands-on lab for teaching AI security concepts with immediate visual feedback

### 9.5 Security and Ethical Considerations

- **Ethical red-teaming**: All testing is performed on a **fictional** organization (Northwind Retail) with **planted fake credentials** (`NORTHWIND_TEST_KEY=NW_TEST_78291`), ensuring no real data or systems are at risk
- **Responsible disclosure**: The project explicitly states it does not claim universal security; it demonstrates methodology, not production assurance
- **False positive awareness**: The report highlights the cost of broad rules (1 benign question blocked) to educate practitioners about the accuracy-security tradeoff
- **Educational intent**: The guardrails are intentionally described as educational and pattern-based; the project recommends stronger architectural controls for production
- **No real secrets**: The system prompt secret is an intentionally fake test value; production recommendations include keeping all real credentials outside model-visible context

---

## 10. Conclusion

### 10.1 Summary of Key Findings

1. **Third-party scanners alone are insufficient**: Promptfoo, Garak, and PyRIT all report passing results while 17 attack vectors remain exploitable under the original guardrails. This validates the need for a broader, custom attack suite.
2. **Layered application-level guardrails dramatically reduce risk**: The risk score dropped from 95.5 (no guardrails) to 58.1 (original guardrails) to 0.0 (recommended hardening), a 100% risk reduction.
3. **Input normalization is critical**: Zero-width characters, leetspeak, and accented characters trivially bypass raw-text regex matching; NFKD normalization with accent stripping and leetspeak decoding closes these gaps.
4. **The security-engineering lifecycle is repeatable**: The Attack → Identify → Mitigate → Retest → Regress → Automate methodology produces measurable, evidence-based security improvements.
5. **Quantitative risk scoring enables governance**: A severity-weighted composite score (0–100) provides a single, actionable metric for security posture assessment and CI gating.

### 10.2 Significance of the Project

This project demonstrates that AI red-teaming can be transformed from a one-time, manual, tool-specific activity into a **systematic, automated, quantifiable, and repeatable** security-engineering process. The platform's unified approach—combining custom attacks, multiple scanners, visual dashboards, and CI automation—represents a practical model for securing LLM-powered applications in real-world settings.

### 10.3 Limitations

1. **Mock model is deliberately naive**: Test numbers demonstrate platform functionality, not real-model behavior; running with Ollama produces different (and more realistic) results
2. **Regex-based detection**: Pattern matching is inherently incomplete against novel attack phrasings; a model-based input classifier would provide stronger defense
3. **Single-turn only**: Multi-turn conversational attacks (where the adversary gradually manipulates the model over several exchanges) are not covered
4. **Pass/fail heuristics**: Safety check evaluation uses regex matching and refusal keyword detection; false negatives are possible with a real model
5. **Fixed attack corpus**: 30 attacks cover major OWASP categories but represent a small subset of the adversarial landscape
6. **No per-user rate limiting**: Unbounded consumption defense is limited to input/output length enforcement
7. **Keyword blocklist fragility**: Broad keyword rules inevitably produce false positives on legitimate queries

### 10.4 Lessons Learned

1. **Defense in depth works**: Multiple independent guardrail layers (input policy, model instructions, output policy) are far more effective than any single layer
2. **Testing must exceed scanner coverage**: Real security assurance requires custom, domain-specific adversarial testing beyond what automated scanners provide
3. **Normalization transforms detection**: A simple preprocessing step (normalize → lowercase → deleet → regex) dramatically increases pattern matching effectiveness
4. **False positives are a feature, not a bug**: The single false positive (BEN-04) demonstrates the inherent accuracy-security tradeoff and informs rule tuning decisions
5. **Quantitative metrics drive improvement**: The risk score gave the project a concrete optimization target and enabled objective comparison across configurations
6. **CI integration is essential**: Automated regression prevents security regressions from being introduced by code changes

---

## 11. Recommendations and Future Scope

### 11.1 Potential Improvements

1. **LLM-as-judge scoring**: Replace regex-based safety checks with a secondary LLM that evaluates whether an attack succeeded semantically, reducing false negatives
2. **Multi-turn attack support**: Implement conversational attack chains where the adversary gradually escalates across multiple exchanges
3. **Larger attack corpus**: Expand from 30 to 100+ attacks covering a wider range of encoding schemes, languages, and social engineering techniques
4. **ML-based input classification**: Train or deploy a dedicated classification model (e.g., fine-tuned BERT or DeBERTa) for prompt injection detection, replacing or augmenting regex blocklists
5. **Per-user rate limiting**: Implement token-based rate limiting to defend against unbounded consumption attacks
6. **Attack mutation engine**: Automatically generate attack variants through character substitution, encoding, translation, and paraphrasing
7. **Real-time alerting**: Add webhook/email notifications when the risk score exceeds a threshold or a new attack succeeds

### 11.2 Research and Industrial Applications

- **Academic research**: Framework for studying guardrail effectiveness across different model architectures, sizes, and fine-tuning configurations
- **Enterprise security**: Adaptable template for organizations building internal red-team platforms for their LLM deployments
- **Compliance**: Risk scoring and audit trail support regulatory compliance requirements (EU AI Act, NIST AI RMF)
- **Model benchmarking**: Comparative evaluation of different LLMs' inherent adversarial resilience
- **Security training**: Hands-on training platform for AI security practitioners and students

### 11.3 Long-Term Vision

The long-term vision is to evolve the AI Red-Team Lab into a **comprehensive, community-driven AI security testing platform** that:
- Supports any LLM backend through pluggable provider adapters
- Maintains a federated, community-contributed attack corpus with severity and effectiveness metadata
- Provides semantic (not just syntactic) attack success evaluation
- Supports multi-modal attacks (text, image, audio)
- Integrates with enterprise SIEM/SOAR platforms for production monitoring
- Offers guided remediation recommendations based on detected vulnerability patterns
- Enables collaborative red-teaming across distributed teams

---

## 12. Acknowledgment

This project was developed as part of an AI security engineering course, demonstrating practical experience with AI red-teaming, LLM application security, adversarial testing, mitigation engineering, security regression, CI/CD security automation, the OWASP GenAI Top 10 (2025), and the MITRE ATLAS framework. The project utilizes the following open-source tools and frameworks: FastAPI, React, Vite, SQLite, Ollama, Promptfoo, NVIDIA Garak, Microsoft PyRIT, Recharts, and GitHub Actions. The Northwind Retail organization and all associated data are entirely fictional.

---

## 13. References

1. **OWASP Top 10 for LLM Applications (2025)**. OWASP Foundation. Available at: https://owasp.org/www-project-top-10-for-large-language-model-applications/

2. **MITRE ATLAS (Adversarial Threat Landscape for AI Systems)**. MITRE Corporation. Available at: https://atlas.mitre.org/

3. **Promptfoo**: Open-source LLM testing and evaluation framework. Available at: https://github.com/promptfoo/promptfoo

4. **NVIDIA Garak**: LLM vulnerability scanner. Available at: https://github.com/NVIDIA/garak

5. **Microsoft PyRIT (Python Risk Identification Tool for generative AI)**. Available at: https://github.com/Azure/PyRIT

6. **FastAPI**: Modern, high-performance web framework for Python. Available at: https://fastapi.tiangolo.com/

7. **Ollama**: Run large language models locally. Available at: https://ollama.com/

8. **Qwen3 Language Models**. Alibaba Cloud. Available at: https://github.com/QwenLM/Qwen

9. **React**: A JavaScript library for building user interfaces. Available at: https://react.dev/

10. **Vite**: Next-generation frontend tooling. Available at: https://vitejs.dev/

11. **SQLite**: Self-contained SQL database engine. Available at: https://sqlite.org/

12. **GitHub Actions**: CI/CD platform. Available at: https://docs.github.com/en/actions

13. Perez, F. & Ribeiro, I. (2022). "Ignore This Title and HackAPrompt: Evaluating and Eliciting Attacks on Large Language Models." *arXiv preprint arXiv:2306.09442*.

14. Greshake, K. et al. (2023). "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection." *arXiv preprint arXiv:2302.12173*.

15. Liu, Y. et al. (2023). "Jailbreaking ChatGPT via Prompt Engineering: An Empirical Study." *arXiv preprint arXiv:2305.13860*.

16. **EU AI Act** (2024). Regulation (EU) 2024/1689 of the European Parliament and of the Council laying down harmonized rules on artificial intelligence. *Official Journal of the European Union*.

17. **NIST AI Risk Management Framework (AI RMF 1.0)**. National Institute of Standards and Technology. Available at: https://www.nist.gov/artificial-intelligence/ai-risk-management-framework

---

> [!NOTE]
> This report was generated based on a comprehensive code-level review of the AI Red-Team Lab project. All technical details, code structures, attack definitions, and test results were extracted directly from the project source code and documentation.
