# Consent Layer for AI Agents

A narrow, revocable, auditable permission that a human grants to an AI agent — and
that any service can verify without trusting the agent.

Today an agent acting on your behalf gets either broad access (an API key, a card
on file) or nothing. There is no middle ground: a scoped, expiring, plain-language
*"yes, you can do exactly this"* that a merchant can check independently.

This is that middle ground, end to end.

```
agent ──1. request scope──▶ consent layer ──2. ask──▶ you
                                  │                    │
                                  ◀──3. approve/deny────┘
                                  │
                            4. mint signed token (SDL)
                                  │
agent ──5. present token──▶ merchant + Verify SDK ──6. allow/deny──▶ agent
                                  │
                                  └──7. log──▶ hash-chained audit trail
```

---

## Quickstart

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn consent_layer.app:app --reload
```

Then open <http://127.0.0.1:8000> for the consent UI, or run the narrated CLI demo
in a second terminal:

```powershell
.\.venv\Scripts\python.exe agent\demo_agent.py --pause
```

`--pause` waits for <kbd>enter</kbd> between beats, which is what you want when
narrating it to a room. API docs are at `/docs`. Tests: `python -m pytest`.

---

## The demo, in seven beats

1. The agent asks to **buy up to $30 of books from one store, 3 times, within 24
   hours**. The request is shown in plain English, not JSON.
2. You approve. A signed Ed25519 token is minted encoding exactly that — nothing
   more.
3. The agent presents the token to the merchant. The merchant verifies it
   **independently**, runs eight checks, and allows the purchase.
4. The agent tries to stretch it: a $48 book (over the per-transaction cap),
   headphones (wrong category), and an edited token with the cap raised to $5000
   (signature no longer matches). All three denied, each with a reason.
5. You revoke the permission.
6. The agent tries again. Denied immediately.
7. The audit trail shows every step. Editing one historic entry breaks the hash
   chain, and the UI says which entry and why.

Click **Tamper with an entry** in the audit panel for beat 7 in the web version.

---

## Scope Definition Language (SDL v1)

The intellectual core. A token looks like this:

```json
{
  "token_id": "tok_fbf8a1003bfe",
  "version": "sdl/1",
  "issuer": "user:priya@domain.com",
  "issued_to": "agent:consent-agent-7f3a",
  "issued_at": "2026-08-04T16:17:57Z",
  "expires_at": "2026-08-05T16:17:57Z",
  "scope": {
    "action_type": "purchase",
    "constraints": {
      "merchant_allowlist": ["demo-bookstore.com"],
      "category": ["books"],
      "max_single_transaction_usd": 30,
      "max_amount_usd": 50,
      "max_uses": 3,
      "currency": "USD"
    }
  },
  "revocable": true,
  "audit_required": true,
  "signature": { "alg": "Ed25519", "key_id": "user:priya@domain.com#key1", "value": "…" }
}
```

which renders as:

> Let agent:consent-agent-7f3a **spend your money** — only merchant
> demo-bookstore.com; only category books; currency USD; at most $30.00 in any one
> action; $50.00 in total across all uses; at most 3 times.

### Built from primitives, not an enum of permissions

The design goal is a small set of composable pieces rather than a long list of
specific permissions. There are six primitives — `Allowlist`, `MaxPerAction`,
`MaxCumulative`, `MaxUses`, `RateLimit`, `Equals` — and each knows how to do
exactly three things: validate its own value, check an attempted action, and
render itself as an English clause.

A *constraint* is a named binding of a primitive to a field of the action.
`max_single_transaction_usd` is `MaxPerAction` bound to `amount_usd`. An *action
type* is just a declaration of which constraint names are legal and which are
mandatory.

So adding a permission is one row in `CONSTRAINTS` and one row in `ACTION_TYPES` —
not new verifier code. All four action types from the proposal are implemented,
because with this structure the other three cost about twenty lines:

| Action type | Constraints |
|---|---|
| `purchase` | merchant allowlist, category, per-transaction cap, budget, currency, uses, rate limits |
| `send_message` | recipient allowlist, channel, uses, rate limits |
| `edit_resource` | resource allowlist, allowed operations, size cap, uses, rate limit |
| `api_call` | endpoint allowlist, method allowlist, uses, rate limits |

### Two principles enforced by the code, not by convention

**Human-renderable or it doesn't ship.** A primitive cannot be registered without
a renderer, and [a test](tests/test_sdl.py) asserts this across the whole registry.
If a field can't be explained to the person approving it, it can't enter the
language.

**Deny by default, including forwards.** A constraint name the verifier doesn't
recognise is a *denial*, never a shrug. This matters more than it first looks:
constraints only ever *narrow* permission, so an old merchant silently ignoring a
new restriction always *widens* it — while still reporting a successful
verification. Same for unknown signature algorithms, unparseable timestamps, and
an unreachable revocation service.

---

## Verification

The whole SDK a merchant integrates:

```python
verifier = Verifier("demo-bookstore.com", keyring, revocation_source, store)
decision = verifier.verify(grant, action)
if not decision.allowed:
    return 403, decision.reason
```

Eight checks, in order — the UI shows each one pass or fail:

| # | Check | Fails when |
|---|---|---|
| 0 | Grant is well-formed | missing fields, unknown SDL version, no `action_id` |
| 1 | Signature is valid | any edit to the token; wrong key; `alg: none` |
| 2 | Within its validity window | expired, or not yet valid |
| 3 | Not revoked | revoked, unknown to the issuer, or revocation service unreachable |
| 4 | Action type matches | a purchase token used to send a message |
| 5 | All restrictions understood | token carries a constraint this verifier can't enforce |
| 6 | Action fits what you approved | wrong merchant/category, over the per-action cap |
| 7 | Within its usage limits | uses exhausted, over budget, rate limited |

Steps 0–6 are stateless — everything needed is in the token. Only step 3 is a live
callout and only step 7 touches the ledger, which is what makes offline
verification a tractable next step rather than a rewrite.

### Details that are easy to get wrong

**Signing is over canonical JSON.** `json.dumps` doesn't guarantee key order or
float formatting, so signer and verifier can disagree byte-for-byte on what was
signed. Everything signed goes through [`canonical.py`](consent_layer/canonical.py):
sorted keys, no whitespace, floats *rejected outright*. Money crosses the wire as
integers or decimal strings (`"12.99"`), never floats. Payloads are domain-tagged
so a signature can't be replayed as a different kind of object.

**Redemption is atomic.** Checking "used 2 of 3?" and then recording a third use
as two statements is a time-of-check/time-of-use bug — two concurrent requests
both read 2, both proceed, and a `max_uses: 3` grant gets spent four times. Every
redemption runs the usage checks *and* the write inside one `BEGIN IMMEDIATE`
transaction.

**Retries aren't second purchases.** Actions carry an `action_id`; replaying one
returns the original decision instead of spending the grant again.

**Denials don't consume uses.** A rejected attempt is logged but doesn't burn one
of your three.

**The merchant prices the action, not the agent.** `/merchant/purchase` takes an
item id and fills in the amount and its own domain from its own catalogue. An
agent that could assert its own `amount_usd` could under-report it and walk
straight past the spending cap. Constrained fields have to be filled in by the
party that actually knows them.

---

## Audit trail

Every request, approval, denial, revocation and verification is appended to a
hash-chained log:

```
row_hash = sha256( canonical({ seq, ts, event, actor, token_id, payload, prev_hash }) )
```

Altering, deleting or inserting a row breaks every hash from that point on, and
`GET /api/audit/verify` reports *which* entry broke and how.

This is tamper-**evident**, not tamper-proof: someone with write access can still
rewrite the chain from the edit forward. Closing that needs an external anchor —
publishing the head hash somewhere you don't control, or countersigning each head.
Listed below as future work rather than papered over.

---

## What's real and what's scaffolding

Honest accounting, matching the proposal's scope table.

| Real | Mocked |
|---|---|
| Ed25519 signing over canonical JSON | One hardcoded keypair; no rotation or custody |
| The SDL, all four action types | — |
| The verification algorithm, fail-closed throughout | — |
| Atomic redemption, budgets, rate limits, idempotency | — |
| Hash-chained audit log + integrity checking | No external anchoring |
| Revocation, enforced at verification time | A shared DB row, not a distributed network |
| The consent UI | — |
| — | The agent: a script, no LLM |
| — | The merchant: one hardcoded store, in-process |
| — | Payments: logs `would have charged $18.00` |

The merchant lives in the same process purely so the demo is one command.
Architecturally it's a separate party: nothing under `/merchant/*` imports the
minting code, and it reaches the issuer only through the `RevocationSource`
interface.

---

## Layout

```
consent_layer/
  sdl.py         the language — primitives, vocabulary, plain-language rendering
  verifier.py    the Verify SDK — the eight checks
  consent.py     request → human decision → signed grant
  crypto.py      Ed25519 signing and key resolution
  canonical.py   deterministic JSON for signing
  audit.py       hash chaining and integrity verification
  db.py          SQLite storage; atomic redemption lives here
  app.py         HTTP: consent API, demo merchant, audit, UI
ui/              the consent screen (no build step)
agent/           simulated agent — the narrated CLI demo
tests/           68 tests, mostly "can this grant more authority than was agreed?"
```

## API

| | |
|---|---|
| `POST /api/requests` | agent asks for a scope |
| `POST /api/requests/{id}/approve` | human approves — the only place a grant is minted |
| `POST /api/requests/{id}/deny` | human declines |
| `GET  /api/grants` | active permissions with remaining budget and uses |
| `POST /api/grants/{id}/revoke` | revoke |
| `GET  /api/revocations/{id}` | the live check a verifier makes |
| `GET  /api/vocabulary` | what SDL v1 can express |
| `POST /api/preview` | render a scope as English without creating anything |
| `POST /merchant/purchase` | attempt a purchase against a grant |
| `POST /merchant/preview` | would this be allowed? consumes nothing |
| `GET  /api/audit` | the log plus chain status |
| `GET  /api/audit/verify` | recompute the chain |
| `POST /api/demo/tamper/{seq}` | **demo only** — corrupt an entry to show detection |
| `POST /api/demo/reset` | wipe, for rehearsing |

---

## Known limits and future work

Ordered roughly by how much they'd bother a security reviewer.

- **Revocation is a central callout.** Verification is otherwise offline-capable,
  but step 3 phones home. The real answer is probably short-lived grants plus
  signed revocation lists, so revocation only matters for the long-lived ones.
- **The audit log isn't externally anchored.** Tamper-evident against edits, not
  against a full rewrite by someone with database access.
- **One hardcoded keypair, no rotation.** `key_id` is in the token and the keyring
  resolves it, so the shape for rotation is there; the custody story isn't.
- **No authentication at all.** One user, one agent, one merchant, hardcoded. Any
  caller can approve a request.
- **Revocation isn't instant across replicas** — one DB row, read at verify time.
- **Rate-limit windows are wall-clock** and would drift under clock skew between
  issuer and verifier.
- Not started: decentralised verification via multi-party signatures, regulatory
  compliance tooling, cross-platform scope portability between AI providers.
