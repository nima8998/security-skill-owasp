# LLM applications and AI agents — supplementary checklist

> Sources: OWASP Top 10 for LLM Applications 2025, https://genai.owasp.org/llm-top-10/ and OWASP Top 10 for Agentic
> Applications 2026, https://genai.owasp.org/ — © OWASP Foundation / OWASP GenAI Security Project, licensed under
> CC BY-SA 4.0. Condensed for code auditing; the "In code" notes and mappings are additions of this skill. As an
> adaptation, this file is distributed under CC BY-SA 4.0 as well.

Use this file when reconnaissance finds LLM or agent code: SDK imports (`anthropic`, `@anthropic-ai/sdk`, `openai`,
`google.genai`, `langchain`, `llama_index`, `ai` (Vercel AI SDK), `semantic-kernel`, `autogen`, `crewai`), MCP servers or
clients (`@modelcontextprotocol/sdk`, `mcp`), tool/function definitions, vector stores (`pgvector`, `pinecone`,
`chromadb`, `weaviate`, `qdrant`), or prompt templates.

## The core idea

Treat the model as an **untrusted, confusable component**. Anything that reaches its context — user messages,
retrieved documents, web pages, emails, tool results, file contents — can steer it (prompt injection is not fully
preventable today). Security therefore comes from what surrounds the model:

- **Its output is untrusted input** to whatever consumes it (shell, SQL, HTML, URLs, file paths, other agents).
- **Its privileges are the blast radius**: the tools it can call, with whose credentials, without whose approval.
- **Secrets in its context can leak**: anything in the system prompt or retrieved data can be echoed back.

The OWASP Top 10:2025 notes the overlap explicitly: injection into an LLM is LLM01, while the downstream damage
usually lands in the classic categories. **Report under the A0X:2025 category of the impact** and cite the LLM/ASI ID
in the text; use A06 Insecure Design when the problem is the architecture itself (e.g. an agent with unrestricted
tools and no human approval).

## OWASP Top 10 for LLM Applications 2025

| ID | Risk | Maps to | In code, look for |
|---|---|---|---|
| LLM01 | Prompt Injection | A06 / A05 | User or external text concatenated into system/developer prompts; retrieved documents, web pages, emails or tool outputs fed to a model that can call tools; no separation of instructions and data; relying on "ignore malicious instructions" in the prompt as the control. |
| LLM02 | Sensitive Information Disclosure | A01 / A04 | API keys, DB credentials, internal URLs or other users' data placed in prompts or RAG context; conversation history shared across users/tenants; model responses logged with PII. |
| LLM03 | Supply Chain | A03 | Models/adapters pulled from hubs by name without pinning a revision/hash; `trust_remote_code=True`; unvetted plugins, MCP servers or LangChain community tools. |
| LLM04 | Data and Model Poisoning | A08 | Fine-tuning or RAG ingestion from user-editable or public sources without provenance or review. |
| LLM05 | Improper Output Handling | A05 | Model output passed to `exec`/`eval`/`subprocess`/`child_process`, interpolated into SQL, rendered with `innerHTML`/`dangerouslySetInnerHTML`/`v-html`/Markdown-to-HTML without sanitizing, used as a URL (SSRF, data-exfiltration through image links), file path or redirect target. |
| LLM06 | Excessive Agency | A06 / A01 | Tools with more functionality than needed (generic `run_shell`, `execute_sql`, `http_request`, file write anywhere); tools running with admin/service credentials instead of the end user's; destructive or financial actions without human confirmation. |
| LLM07 | System Prompt Leakage | A04 / A06 | Secrets, credentials or authorization rules living only in the system prompt ("never reveal the admin password: …", "only answer for user 42"). The prompt must be assumed public; authorization must be enforced in code. |
| LLM08 | Vector and Embedding Weaknesses | A01 | One vector index for all tenants without a metadata filter enforced server-side; retrieval that ignores the caller's document permissions; embeddings of sensitive data exposed through similarity search. |
| LLM09 | Misinformation | A06 | Model output used for security or high-stakes decisions without verification (auto-merging code, approving refunds, medical/legal advice without disclaimers or review). Rarely a code finding; mention under Insecure Design when it is. |
| LLM10 | Unbounded Consumption | A10 / A06 | No `max_tokens`, no per-user rate/budget limits, unbounded agent loops or recursion, user-controlled model choice, huge context stuffing — cost and availability attacks ("denial of wallet"). |

## OWASP Top 10 for Agentic Applications 2026

Apply when the code runs an **agent**: a loop where the model chooses tools, plans, keeps memory or talks to other
agents.

| ID | Risk | Maps to | In code, look for |
|---|---|---|---|
| ASI01 | Agent Goal Hijack | A06 | Agents that read external content (email, tickets, web, repositories, PR descriptions) and also hold write/exfiltration-capable tools. Indirect prompt injection turns the content into instructions. |
| ASI02 | Tool Misuse and Exploitation | A06 / A05 | Tool arguments taken from the model without schema validation, allow-lists or path/URL restrictions; tools that wrap a shell or raw SQL. |
| ASI03 | Identity and Privilege Abuse | A01 / A07 | Agents acting with a shared service identity or long-lived high-privilege tokens; no per-user delegation (OAuth on-behalf-of, scoped tokens); credentials passed through the prompt. |
| ASI04 | Agentic Supply Chain Vulnerabilities | A03 | MCP servers, tools, prompts or agent cards loaded dynamically from untrusted registries or URLs; unpinned versions; tool descriptions not reviewed (tool poisoning). |
| ASI05 | Unexpected Code Execution | A05 / A08 | Code-interpreter or "run this snippet" features outside a real sandbox (no container/VM, network and filesystem open); `eval` of generated code; `pickle`/`torch.load` of model files. |
| ASI06 | Memory and Context Poisoning | A08 | Long-term memory, conversation summaries or shared scratchpads writable from untrusted input and read back as trusted context; no per-user memory isolation. |
| ASI07 | Insecure Inter-Agent Communication | A07 / A08 | Agent-to-agent messages without authentication or integrity; one agent's output used as another's instructions; spoofable agent identities. |
| ASI08 | Cascading Failures | A10 / A06 | No circuit breakers, step limits, timeouts or budget caps across chained agents; one compromised or erroring agent propagating to others. |
| ASI09 | Human-Agent Trust Exploitation | A06 | Approval prompts that show a summary written by the model instead of the actual action/diff/command; auto-approve modes enabled by default. |
| ASI10 | Rogue Agents | A09 / A06 | No logging of tool calls with arguments and identity; no kill switch; agents that can modify their own configuration, prompts or permissions. |

## Grep starting points

```
# SDKs and agent frameworks
from anthropic|@anthropic-ai/sdk|from openai|import openai|google\.genai|langchain|llama_index|from ai import|"ai":|semantic_kernel|autogen|crewai|@modelcontextprotocol/sdk|from mcp
# Prompts: locate every definition, then READ IT WHOLE — prompts are usually multi-line, so a
# line-based grep for secrets inside them misses most cases (use -i)
(system_?prompt|systemPrompt|instructions|system)\s*[:=]\s*(f?"""|f?'''|`|f?["'])
(system|system_prompt|instructions)\s*[:=].*(\$\{|f["']|\.format\(|\+\s*\w)|role["']?\s*:\s*["']system
# ripgrep multiline (rg -U -i): a secret inside a prompt literal (LLM07)
(system_?prompt|systemPrompt|instructions)\s*[:=]\s*(f?"""|`)[\s\S]{0,2000}?(api[_ -]?key|password|secret|token|bearer)
# Tool dispatch: where model-chosen arguments enter your code — follow each argument to its sink (LLM05/ASI02)
block\.input|tool_use|tool_calls|function\.arguments|tool_input|\.arguments\b
# Output handling (LLM05 / ASI05)
(exec|eval|execSync|spawn|subprocess\.\w+|os\.system|child_process)\([^)]*(completion|response|output|message|content|result|command|cmd)
(innerHTML|dangerouslySetInnerHTML|v-html|marked\(|markdown\()[^\n]*(completion|response|output|message|content|answer|reply)
trust_remote_code\s*=\s*True|torch\.load\(|pickle\.load
# Tools and agency (LLM06 / ASI02 / ASI03) (use -i)
tools\s*[:=]|@tool|tool\(|function_call|tool_choice|bash|shell|run_command|execute_sql|http_request|write_file
auto_?approve|dangerously|skip_?permissions|requireApproval:\s*false
# Limits (LLM10 / ASI08)
max_tokens|max_output_tokens|max_iterations|max_steps|recursion_limit|timeout
```

## Common false positives

- Prompt templates that only interpolate **trusted** values (static instructions, server-side IDs) — check the source.
- Model output rendered as plain text by a framework that escapes by default (React text nodes, Jinja autoescape).
- Tools that are read-only, narrowly scoped and run with the end user's own credentials — still mention LLM06 if they
  can reach other users' data.
- Code-execution features that run inside a documented, isolated sandbox (separate container/VM, no network,
  resource limits) — verify the isolation is real before dismissing.

## Suggested fixes (patterns)

- Keep instructions and untrusted data apart (separate messages/blocks, clear delimiters), and **never** rely on the
  prompt as a security boundary.
- Validate tool arguments against a strict schema and an allow-list; run tools with the end user's permissions;
  require human confirmation for irreversible, financial or externally visible actions, showing the real action.
- Treat model output like user input at every sink: parameterize SQL, use argument arrays without a shell, sanitize
  HTML (DOMPurify / bleach) and block remote images/links if exfiltration matters.
- Keep secrets out of prompts; enforce authorization and tenant filters in code and in the retrieval query.
- Set `max_tokens`, step and recursion limits, timeouts, and per-user budgets; log tool calls with arguments.

## References

- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/
- OWASP Top 10 for Agentic Applications 2026: https://genai.owasp.org/
- OWASP LLM Prompt Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html
- OWASP AI Agent Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html
- Model Context Protocol — Security best practices: https://modelcontextprotocol.io/specification/draft/basic/security_best_practices
