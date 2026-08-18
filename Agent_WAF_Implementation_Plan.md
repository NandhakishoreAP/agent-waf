# Agent WAF — Full Implementation Plan
### PS-5.1 · Aivar Innovations Agentic AI Task
**Stack:** Python 3.11 + FastAPI · SQLite/Postgres · Groq (OpenAI-compatible LLM) · Docker → AWS (Lambda or ECS)
**Time budget:** 1 day (solo build)
**Use this file as:** the single source of truth to paste into any AI tool, IDE, or teammate as context. Every section below is self-contained.

---

## 1. Problem Restated (from the brief)

> Build an Agent WAF — a policy-enforcing proxy between an agent and its tools that inspects, filters, and logs every tool invocation in real time.

**Must-have components:**
1. A transparent proxy layer intercepting all tool calls from a sample agent.
2. A rule engine with 4 rule types: **rate limit**, **parameter validation**, **data scope**, **sequence rules**.
3. Logging of every call: timestamp, agent ID, tool, sanitized params, rule outcome, final disposition.
4. A real-time dashboard of traffic and block events.

**Success criteria (must all pass):**
- [ ] Rate limit fires correctly after N calls within the window.
- [ ] Parameter blocklist catches a simulated injection attempt in a tool parameter.
- [ ] Out-of-scope data access is blocked.
- [ ] Sequence rule enforcement blocks a tool called out of expected order.
- [ ] Dashboard updates in real time as calls flow through.

**Bonus:** Shadow mode — log what *would* have been blocked without blocking, for safe rule calibration.

**Production-readiness bar (from the intro, applies to grading):**
- Deployed on AWS (not just localhost).
- Handles concurrent requests, persists state, exposes a usable API.
- Has logging, error handling, a health check.
- Connects to a real LLM provider (not mocked).

---

## 2. Why This Stack

| Concern | Choice | Reason |
|---|---|---|
| Language/Framework | Python 3.11 + FastAPI | Async-native, matches agent ecosystem (LangChain/MCP/OpenAI SDK), fast to build, auto-generates OpenAPI docs for free "usable API" credit |
| DB | SQLite for local dev → Postgres (AWS RDS or local Postgres via Docker Compose) for "production" | Persists state cheaply; swapping is a 1-line connection string change if using SQLAlchemy |
| LLM | Groq (`llama-3.1-8b-instant`, OpenAI-SDK compatible) | Free, fast, real LLM call — satisfies "connects to at least one real LLM provider" |
| Real-time dashboard | FastAPI + WebSocket + a single HTML/JS page (or Streamlit if time-constrained) | WebSocket push = genuinely "real time"; no heavy frontend framework needed |
| Rule storage | YAML file loaded into memory + reloadable via endpoint | Simple, declarative, matches "policy manifest" language used across the whole problem set |
| Containerization | Docker + docker-compose (local) → AWS ECS Fargate (prod) | ECS Fargate is the fastest path to "deployed on AWS" without managing servers; Lambda is viable alt (see §9) |
| Auth (light) | Static API key header for admin endpoints | Enough for a 1-day scope; documented as a "next step" for OIDC |

---

## 3. Architecture Overview

```
┌─────────────┐        ┌──────────────────────────────────────────┐        ┌─────────────┐
│  Sample      │ tool   │              AGENT WAF (FastAPI)          │ tool   │  Mock Tools  │
│  Agent       │ call   │                                            │ call   │  (CRM, DB,   │
│  (Groq LLM)  │ ─────► │  1. Auth/Agent Identity check              │ ─────► │  Email API,  │
│              │        │  2. Rule Engine (rate/param/scope/seq)     │        │  File Read)  │
│              │ ◄───── │  3. Decision: ALLOW / BLOCK / SHADOW-LOG   │ ◄───── │              │
└─────────────┘  resp   │  4. Audit Logger  →  DB (calls table)      │  resp  └─────────────┘
                         │  5. WebSocket broadcaster → Dashboard      │
                         └──────────────────────────────────────────┘
                                          │
                                          ▼
                              ┌───────────────────────┐
                              │  Dashboard (HTML/JS)    │
                              │  live traffic + blocks  │
                              └───────────────────────┘
```

**Key design decision:** The WAF is a **library + service**, not just a service. The sample agent imports a `WAFClient` (or calls the WAF's `/invoke` endpoint) instead of calling tools directly. This mirrors how a real proxy would sit "between an agent and its tools" — every tool call is forced through `/waf/invoke`.

---

## 4. Repository Structure

```
agent-waf/
├── app/
│   ├── main.py                  # FastAPI app entrypoint
│   ├── config.py                # env vars, settings
│   ├── db.py                    # SQLAlchemy engine/session
│   ├── models.py                # ORM models: Agent, ToolCallLog, RuleConfig
│   ├── schemas.py                # Pydantic request/response models
│   ├── deps.py                   # dependency-injected auth, db session
│   ├── rules/
│   │   ├── __init__.py
│   │   ├── engine.py             # RuleEngine — orchestrates all rule types
│   │   ├── rate_limit.py
│   │   ├── param_validation.py
│   │   ├── data_scope.py
│   │   └── sequence.py
│   ├── proxy/
│   │   ├── __init__.py
│   │   ├── router.py             # /waf/invoke endpoint — the interception point
│   │   └── tools_mock.py         # mock CRM/DB/email/file tools being "protected"
│   ├── audit/
│   │   ├── __init__.py
│   │   └── logger.py             # writes to DB + pushes to WebSocket
│   ├── dashboard/
│   │   ├── ws.py                 # WebSocket connection manager
│   │   └── static/
│   │       └── index.html        # single-page live dashboard (vanilla JS + fetch/WS)
│   └── policies/
│       └── waf_policy.yaml       # declarative rule definitions
├── sample_agent/
│   ├── agent.py                  # Groq-powered agent that decides which tool to call
│   └── scenarios.py              # scripted scenarios to prove each success criterion
├── tests/
│   ├── test_rate_limit.py
│   ├── test_param_validation.py
│   ├── test_data_scope.py
│   ├── test_sequence.py
│   └── test_end_to_end.py
├── Dockerfile
├── docker-compose.yml            # app + postgres, for local "prod-like" run
├── requirements.txt
├── .env.example
├── infra/
│   ├── ecs-task-def.json         # AWS ECS Fargate task definition
│   └── deploy.sh                 # aws cli deploy script
└── README.md
```

---

## 5. Data Model

### `agents` table
| column | type | notes |
|---|---|---|
| agent_id | string (PK) | e.g. `support-agent-01` |
| name | string | |
| declared_scope | JSON | list of tool:operation:data_scope the agent is allowed |
| created_at | datetime | |

### `tool_call_logs` table (the audit trail — core deliverable)
| column | type | notes |
|---|---|---|
| id | UUID (PK) | |
| timestamp | datetime | UTC |
| agent_id | string (FK) | |
| session_id | string | groups calls into a session for sequence rules |
| tool_name | string | e.g. `crm.read`, `email.send`, `db.delete` |
| parameters_sanitized | JSON | secrets/PII redacted before storage |
| rule_evaluations | JSON | list of `{rule_type, rule_name, outcome, reason}` |
| final_disposition | enum | `ALLOWED`, `BLOCKED`, `SHADOW_BLOCKED` |
| latency_ms | int | proxy overhead, nice-to-have metric |

### `rule_configs` (loaded from YAML at boot, optionally hot-reloadable)
Stored in-memory as parsed objects; **not required in DB** for day-1 scope, but log which policy version was active per call (`policy_version` string) for traceability.

---

## 6. Policy File — `waf_policy.yaml`

This is the declarative rule manifest referenced everywhere in the brief. Design it once, reuse the pattern.

```yaml
policy_version: "v1"
mode: enforce          # enforce | shadow  (bonus: shadow mode toggle)

rate_limits:
  - tool: "crm.read"
    max_calls: 5
    window_seconds: 60
  - tool: "db.delete"
    max_calls: 2
    window_seconds: 60

parameter_validation:
  - tool: "*"                     # applies to all tools
    blocklist_patterns:
      - "(?i)ignore (all|previous) instructions"
      - "(?i)DROP TABLE"
      - "(?i)<script"
      - "(?i)system:|assistant:|<\\|im_start\\|>"   # prompt-injection style payloads
    max_param_length: 2000

data_scope:
  - tool: "crm.read"
    rule: "customer_id == session.customer_id"
  - tool: "crm.write"
    rule: "customer_id == session.customer_id"
  - tool: "db.delete"
    rule: "record_count <= 100"

sequence_rules:
  - tool: "email.send"
    requires_prior: ["crm.read"]     # must have read the customer before emailing them
  - tool: "db.delete"
    requires_prior: ["db.backup_check"]
```

**Why YAML, not hardcoded Python:** matches how every other unit in the brief (PS-3.1, PS-3.3, PS-10.1) expects declarative policy — reusable pattern, easy to demo "add a rule live" during defense.

---

## 7. Rule Engine — Component Design

`app/rules/engine.py` exposes:

```python
class RuleEngine:
    def evaluate(self, call: ToolCallRequest, session: SessionContext) -> RuleDecision:
        """
        Runs all 4 rule categories in order. Short-circuits on first BLOCK
        unless mode == 'shadow', in which case it evaluates all and logs
        what WOULD have blocked.
        Returns RuleDecision(disposition, evaluations=[...])
        """
```

### 7.1 Rate Limit (`rate_limit.py`)
- Sliding window counter per `(agent_id, tool_name)` kept in an in-memory dict (or Redis if you want extra credit — optional, not required for 1 day).
- On each call: purge timestamps older than `window_seconds`, check `len(remaining) >= max_calls` → BLOCK.
- **Test scenario:** call `crm.read` 6 times in <60s with limit 5 → 6th call blocked.

### 7.2 Parameter Validation (`param_validation.py`)
- Regex blocklist match against all string values in the `parameters` dict (recursively, for nested JSON).
- Length check.
- **Test scenario:** call `db.delete` with `reason="'; DROP TABLE customers;--"` → blocked, log reason = "blocklist_pattern_matched: DROP TABLE".

### 7.3 Data Scope (`data_scope.py`)
- Evaluate a tiny safe expression against `session.customer_id` etc. **Do NOT use raw `eval()`** — implement a minimal safe comparator (parse `"customer_id == session.customer_id"` into a structured check, or use a whitelist-based expression evaluator like `simpleeval` package).
- **Test scenario:** Agent's session is bound to `customer_id=42`; agent calls `crm.read(customer_id=99)` → blocked.

### 7.4 Sequence Rules (`sequence.py`)
- Maintain `session_id → ordered list of tool names called so far` in memory (or DB-backed for persistence across restarts).
- Check `requires_prior` list is a subset of calls already made in this session.
- **Test scenario:** Agent calls `email.send` without a prior `crm.read` in the same session → blocked.

---

## 8. The Proxy Endpoint (the interception point)

`POST /waf/invoke`

**Request:**
```json
{
  "agent_id": "support-agent-01",
  "session_id": "sess-abc123",
  "tool_name": "crm.read",
  "parameters": { "customer_id": 42 }
}
```

**Flow:**
1. Validate agent exists & is active (ties into identity — reuse pattern from PS-2.1 if you want extra depth, optional).
2. Run `RuleEngine.evaluate(...)`.
3. If `ALLOWED` (or `shadow` mode): forward the call to the actual mock tool in `tools_mock.py`, capture the tool's response.
4. If `BLOCKED`: do not call the tool; return `403` with reason.
5. Write full record to `tool_call_logs` (redact sensitive params first — simple regex mask on keys like `ssn`, `password`, `token`).
6. Broadcast the new log entry over WebSocket to any connected dashboard clients.
7. Return response to the agent.

**Response (allowed):**
```json
{ "disposition": "ALLOWED", "tool_response": {...}, "rule_evaluations": [...] }
```
**Response (blocked):**
```json
{ "disposition": "BLOCKED", "reason": "rate_limit_exceeded", "rule_evaluations": [...] }
```

### Mock tools to implement (`tools_mock.py`)
Minimum viable set to demonstrate all 4 rule types meaningfully:
- `crm.read(customer_id)` — returns fake customer record
- `crm.write(customer_id, field, value)`
- `db.delete(table, record_count)` — simulate bulk delete
- `db.backup_check(table)` — dummy tool used only to satisfy sequence rule
- `email.send(to_domain, body)`

---

## 9. Real LLM Integration (Groq) — the "sample agent"

`sample_agent/agent.py`:
- Uses `openai` Python SDK pointed at Groq's base URL (`https://api.groq.com/openai/v1`), model `llama-3.1-8b-instant`.
- Agent receives a natural-language task ("Look up customer 42 and email them a summary"), and via **function calling / tool schema**, decides which tool to invoke.
- Every tool call the LLM decides to make is **not executed directly** — it's routed through `POST /waf/invoke` instead of a direct function call. This is what makes it a real proxy interception, not a fake demo.
- This satisfies the brief's "connects to at least one real LLM provider" requirement non-negotiably — it's the decision-maker generating the tool calls the WAF governs.

**Env var:** `GROQ_API_KEY` (get from console.groq.com, free, 2 min signup).

---

## 10. Dashboard (Real-Time)

- `GET /dashboard` serves a static HTML page (`app/dashboard/static/index.html`).
- Page opens a WebSocket to `ws://<host>/ws/dashboard`.
- On each new log entry (from step 6 in §8), server pushes a JSON event; JS appends a row to a live table + increments counters (Total calls / Allowed / Blocked / Shadow-blocked).
- Minimal styling is fine — a table + 4 stat cards. Use plain HTML/CSS/JS, no build step, to keep this fast.
- Also expose `GET /api/logs?agent_id=&tool=&limit=` for querying history (satisfies "queryable API" production-readiness bullet).

---

## 11. API Surface (full list — build this as your FastAPI router map)

| Method | Path | Purpose |
|---|---|---|
| POST | `/waf/invoke` | Core proxy interception endpoint |
| GET | `/api/logs` | Query audit logs (filter by agent/tool/time) |
| GET | `/api/agents` | List registered agents & their declared scope |
| POST | `/api/agents` | Register a new agent (name, declared_scope) |
| GET | `/api/policy` | Return current active policy (YAML → JSON) |
| POST | `/api/policy/reload` | Hot-reload policy file (admin, API-key protected) |
| POST | `/api/policy/mode` | Toggle `enforce` / `shadow` mode (bonus feature) |
| GET | `/dashboard` | Serves the live dashboard HTML |
| WS | `/ws/dashboard` | Live event stream for dashboard |
| GET | `/health` | Health check — DB connectivity + policy loaded status |
| GET | `/docs` | Auto-generated OpenAPI docs (free from FastAPI) |

---

## 12. Logging & Error Handling (production-readiness credit)

- Use Python's `logging` module with structured (JSON) log output to stdout — this is what ECS/CloudWatch expects.
- Wrap `/waf/invoke` in try/except; on unexpected errors return `500` with a generic message, log full stack trace internally, never leak internals to the client.
- `/health` endpoint checks: DB reachable, policy file loaded successfully, Groq key present → returns `200 {"status": "ok", "checks": {...}}` or `503`.
- Add request-ID middleware (UUID per request) included in logs for traceability.

---

## 13. Concurrency & State Persistence (production-readiness credit)

- FastAPI is async by default — use `async def` endpoints, async DB driver (`asyncpg` for Postgres, or `aiosqlite` for SQLite dev).
- Rate-limit counters and sequence-state: for a 1-day build, in-memory dict guarded by `asyncio.Lock` is acceptable and honestly noted as a scaling limitation in the README (real prod would use Redis). This is fine to state explicitly — graders reward honesty about trade-offs.
- All audit logs persist to the DB (not memory) — this is the actual "state persistence" the brief cares about.
- Test concurrency: fire 20 simultaneous requests via a small `asyncio.gather` load test script; confirm no race conditions in log counts.

---

## 14. Testing Plan — Mapped Directly to Success Criteria

Build `sample_agent/scenarios.py` as a runnable script that executes all 5 scenarios end-to-end and prints a PASS/FAIL summary. This becomes your demo script.

| # | Scenario | Expected Result | Success Criterion |
|---|---|---|---|
| 1 | Call `crm.read` 6x in 60s (limit=5) | 6th call → `BLOCKED, reason=rate_limit_exceeded` | Rate limit fires |
| 2 | Call `db.delete` with SQLi-style string in `reason` param | `BLOCKED, reason=blocklist_pattern_matched` | Parameter blocklist |
| 3 | Session bound to customer 42, call `crm.read(customer_id=99)` | `BLOCKED, reason=data_scope_violation` | Out-of-scope blocked |
| 4 | Call `email.send` before any `crm.read` in session | `BLOCKED, reason=sequence_violation` | Sequence rule |
| 5 | Run scenario 1–4 with dashboard open | Table + counters update live via WS, no refresh needed | Dashboard real-time |

Also write `pytest` unit tests per rule module (`tests/test_*.py`) hitting the `RuleEngine` directly (no HTTP layer) for fast, isolated coverage — good defensibility signal in interview.

---

## 15. Deployment Plan (AWS) — pick ONE path, ECS Fargate recommended for 1-day scope

### Option A — ECS Fargate (recommended)
1. `Dockerfile` — multi-stage build, `python:3.11-slim` base, installs `requirements.txt`, runs `uvicorn app.main:app --host 0.0.0.0 --port 8000`.
2. Push image to **Amazon ECR**.
3. Create an ECS Fargate service (1 task, 0.5 vCPU / 1GB is plenty) behind an **Application Load Balancer** for a public URL.
4. Use **RDS Postgres (free tier / db.t3.micro)** or keep SQLite on an EFS mount if you want to avoid RDS setup time — Postgres is cleaner for "handles concurrent requests, persists state."
5. Store `GROQ_API_KEY` and DB credentials in **AWS Secrets Manager**, injected as task env vars.
6. `infra/deploy.sh` — scripted `aws ecr`, `aws ecs update-service` calls so deployment is repeatable, not manual clicking (extra credit: shows real DevOps competence).

### Option B — Lambda (if ECS setup risks eating your day)
- Wrap FastAPI with `Mangum` adapter for Lambda + API Gateway.
- Faster to deploy, but WebSocket dashboard needs **API Gateway WebSocket API** instead of plain FastAPI WS — more moving parts. Only choose this path if you're confident with Mangum already.

**Recommendation given your 1-day constraint: go with ECS Fargate.** It keeps your FastAPI app unmodified (no Mangum shim, no WS API Gateway complexity), and "governs agents also hosted on AWS" reads more naturally as a long-running service.

### Minimum viable AWS checklist
- [ ] Image builds and runs locally via `docker-compose up`
- [ ] ECR repo created, image pushed
- [ ] ECS cluster + Fargate service + task definition (`infra/ecs-task-def.json`)
- [ ] ALB with public DNS, health check pointed at `/health`
- [ ] Secrets Manager holding `GROQ_API_KEY` + DB creds
- [ ] Confirm `/docs`, `/dashboard`, and `/waf/invoke` all reachable via the public ALB URL

---

## 16. Bonus Feature — Shadow Mode

- Policy YAML has `mode: enforce | shadow` at the top level (see §6).
- In `shadow` mode: `RuleEngine.evaluate()` still runs every rule and records what *would* have happened (`SHADOW_BLOCKED` disposition), but the proxy always forwards the call to the real tool.
- Dashboard shows a distinct counter for "Would-have-blocked (shadow)" so a policy author can calibrate new rules safely before flipping to `enforce`.
- Toggle via `POST /api/policy/mode {"mode": "shadow"}` — demoable live.

---

## 17. One-Day Execution Timeline (suggested hour-by-hour)

| Time | Task |
|---|---|
| Hr 0–0.5 | Repo scaffold, `requirements.txt`, FastAPI hello-world, `/health` endpoint, Docker Compose skeleton |
| Hr 0.5–1.5 | DB models (SQLAlchemy) + migrations, `agents` & `tool_call_logs` tables, DB session wiring |
| Hr 1.5–2 | Policy YAML loader (`app/config.py`), Pydantic schema for `RuleDecision` |
| Hr 2–3.5 | Rule engine: rate limit → param validation → data scope → sequence (build + unit-test each as you go) |
| Hr 3.5–4.5 | Mock tools + `/waf/invoke` endpoint wiring everything together |
| Hr 4.5–5 | Audit logger (redaction + DB write) + WebSocket broadcaster |
| Hr 5–5.5 | Dashboard HTML/JS page |
| Hr 5.5–6.5 | Groq-powered sample agent + tool-calling wiring through `/waf/invoke` |
| Hr 6.5–7 | `scenarios.py` end-to-end test script proving all 5 success criteria |
| Hr 7–7.5 | Shadow mode bonus |
| Hr 7.5–9 | Dockerize, docker-compose local run-through, fix bugs |
| Hr 9–10.5 | AWS deploy: ECR push, ECS service, ALB, secrets — the highest-risk step, start it with buffer time remaining |
| Hr 10.5–11 | README with architecture diagram, setup steps, demo script, trade-offs documented |
| Hr 11–12 | Buffer / rehearse demo / fix whatever AWS breaks (it will) |

**Risk mitigation:** If AWS deployment runs long, have a fallback — `docker-compose up` running on a cloud VM (even a $5 Lightsail instance) still satisfies "deployed... in a cloud environment" far better than localhost, and is a 15-minute fallback vs. ECS's longer setup.

---

## 18. requirements.txt (starting point)

```
fastapi
uvicorn[standard]
sqlalchemy
asyncpg          # or aiosqlite for local dev
pydantic
pyyaml
python-dotenv
openai            # used against Groq's OpenAI-compatible endpoint
simpleeval        # safe expression evaluation for data_scope rules
websockets
pytest
pytest-asyncio
httpx             # for async test client
```

---

## 19. .env.example

```
GROQ_API_KEY=your_key_here
GROQ_BASE_URL=https://api.groq.com/openai/v1
DATABASE_URL=postgresql+asyncpg://waf:waf@db:5432/waf
WAF_ADMIN_API_KEY=changeme
POLICY_FILE=app/policies/waf_policy.yaml
```

---

## 20. README.md contents to include (for graders/interviewers)

1. Architecture diagram (reuse §3 ASCII or redraw).
2. How to run locally (`docker-compose up`).
3. Public AWS URL + how to hit `/docs`, `/dashboard`.
4. How each of the 5 success criteria is demonstrated (link to `scenarios.py`).
5. Known limitations / what you'd do with more time (Redis for rate limiting, real IAM/OIDC agent identity, OPA policy compilation, multi-provider guardrails).
6. Explicit mapping of bonus feature (shadow mode) to how to demo it.

---

## 21. Final Pre-Submission Checklist

- [ ] All 4 rule types implemented and unit-tested
- [ ] `/waf/invoke` is the only path to the mock tools (no bypass)
- [ ] Audit log captures timestamp, agent ID, tool, sanitized params, rule outcome, disposition
- [ ] Dashboard updates live via WebSocket, no polling/refresh needed
- [ ] Real Groq LLM call in the loop generating actual tool-call decisions
- [ ] `docker-compose up` works from a clean clone
- [ ] Deployed and reachable on AWS (ECS Fargate + ALB, public URL)
- [ ] `/health` reflects real dependency checks
- [ ] Shadow mode bonus implemented and demoable
- [ ] `scenarios.py` runs end-to-end and prints PASS for all 5 criteria
- [ ] README complete with architecture, run instructions, demo walkthrough, limitations
