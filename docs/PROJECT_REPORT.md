# AI Red-Team Lab: Project Report

## 1. Objective
Build a platform that tests whether an AI application resists adversarial prompts and follows security rules, and that produces a repeatable report of successful attacks, blocked requests and failed safety checks.

## 2. System under test
The Northwind Retail customer-support chatbot: FastAPI, Ollama and Qwen3 1.7B. It has layered guardrails: input checks (length, prompt-injection, sensitive-request, store-policy and obfuscation blocklists, and a scope allow-list), the model with a hardened system prompt, and output filters for confidential leakage, unsafe content and length. All rules are stored in SQLite and are editable at run time.

## 3. Course concepts demonstrated
| Concept | Implementation |
|---|---|
| Testing and validating guardrails | 30 attacks and 6 benign controls with automatic pass/fail checks, unit and integration tests, plus Promptfoo, Garak and PyRIT |
| Blocklists and policy enforcement | Editable regex blocklists, scope allow-list, input normalization, input and output length limits, output filters |
| AI security risk assessment | OWASP LLM Top 10 (2025) mapping, severity-weighted risk score, recommendations per category |
| Monitoring and test reporting | Dashboard with risk trend and live guardrail events, reports in Markdown, HTML and JSON, SQLite history, CI regression gate |

## 4. Method
Each attack in `app/attacks.py` has safety checks (for example "no secret leaked" or "no unauthorized refund"). A request is **blocked** if any guardrail layer stops it, a **successful attack** if it reaches the model and a check shows it worked, and **resisted** if the model refused. Known-malicious prompts that are not blocked also fail the `guardrail_blocks_known_attack` check. The risk score is the severity-weighted share of successful attacks. Benign prompts measure false positives.

The suite covers prompt injection (including leetspeak, zero-width characters, Base64, French and indirect injection in a review), system prompt leakage (including a spelled-out secret), jailbreaks, obfuscation, sensitive information disclosure, excessive agency (refunds, mass cancellation, discount codes), misinformation, improper output handling (script and image-exfiltration output) and unbounded consumption.

## 5. Results (offline mock model)
| Run | Successful attacks | Blocked requests | Failed safety checks | False positives | Risk score |
|---|---|---|---|---|---|
| Baseline, guardrails off | 28 | 0 | 57 | 0 | 95.5 |
| Original guardrails | 17 | 13 | 25 | 1 | 58.1 |
| After recommended hardening | 0 | 30 | 1 | 1 | 0.0 |

Findings with the original guardrails: the regex rules block the exact phrasings the lab was hardened against, but not variants. Leetspeak, zero-width characters, French and "disregard" phrasings get through. A spelled-out secret bypasses the output filter. In-scope-sounding requests ("for my order, ...") bypass the scope check and reach the model, where refunds, cancellations, discount codes, PII, false policy claims, script output and very long output all succeed.

The saved scanner results in `results/` (Promptfoo 11 of 11 passed, PyRIT 7 of 7 attack objectives blocked, Garak with no failures) all pass, because they test known patterns. The broader built-in suite finds gaps they miss.

The single remaining false positive is a legitimate question about how system prompts work, blocked by the `system prompt` rule. This shows the cost of keyword blocklists.

## 6. Limitations
- The mock model is deliberately naive, so the numbers show the platform works, not how a real model behaves. Run with Ollama for real results.
- Pass/fail detection uses regular expressions and a refusal heuristic. Review failures by hand with a real model.
- Blocklists are brittle against new attacks. A hardened score of 0 covers only this suite.
- The suite has 30 attacks. Promptfoo, Garak and PyRIT broaden coverage.

## 7. Future work
LLM-as-judge scoring, multi-turn attacks, a larger attack corpus, a model-based input classifier next to the blocklist, and per-user rate limiting.
