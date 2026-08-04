/* Consent Layer — demo UI logic.
   Plain DOM, no framework: the interesting part of this project is the protocol,
   and a build step would only get between a reader and it. */

const AGENT = "agent:consent-agent-7f3a";

/* The last scenario is there on purpose: it does not describe a permission the
   language is willing to express, and the server rejects it. "You cannot write
   down a blank cheque" is easier to show than to argue. */
const SCENARIOS = [
  {
    id: "books",
    label: "Buy the book you mentioned",
    note: "The canonical narrow scope: one merchant, one category, capped and expiring.",
    purpose: "You asked me to pick up a copy of the book we discussed.",
    ttl_seconds: 86400,
    scope: {
      action_type: "purchase",
      constraints: {
        merchant_allowlist: ["demo-bookstore.com"],
        category: ["books"],
        max_single_transaction_usd: 30,
        max_amount_usd: 50,
        max_uses: 3,
        currency: "USD",
      },
    },
  },
  {
    id: "broad",
    label: "Buy anything, up to $500",
    note: "Still expressible — but read how it sounds when written in plain English.",
    purpose: "It would be easier if I could just handle purchases for you.",
    ttl_seconds: 604800,
    scope: {
      action_type: "purchase",
      constraints: {
        merchant_allowlist: ["demo-bookstore.com"],
        max_single_transaction_usd: 500,
        max_amount_usd: 500,
        currency: "USD",
      },
    },
  },
  {
    id: "message",
    label: "Email your team lead",
    note: "A different action type — same language, same consent screen, same audit.",
    purpose: "I would like to send the summary we drafted.",
    ttl_seconds: 3600,
    scope: {
      action_type: "send_message",
      constraints: {
        recipient_allowlist: ["lead@acme.com"],
        channel: "email",
        max_uses: 1,
      },
    },
  },
  {
    id: "files",
    label: "Read one file (no writes)",
    note: "Operations are an allowlist, so 'read but not delete' is expressible.",
    purpose: "I need to read your notes to answer the question.",
    ttl_seconds: 3600,
    scope: {
      action_type: "edit_resource",
      constraints: {
        resource_allowlist: ["/notes/roadmap.md"],
        allowed_operations: ["read"],
        max_uses: 5,
      },
    },
  },
  {
    id: "blank-cheque",
    label: "Spend without naming a merchant  ⚠",
    note: "The language refuses this one. A spend scope with no merchant list is a blank cheque.",
    purpose: "Just let me buy things.",
    ttl_seconds: 86400,
    scope: {
      action_type: "purchase",
      constraints: { max_single_transaction_usd: 30, currency: "USD" },
    },
  },
];

const $ = (id) => document.getElementById(id);

const state = { grants: [], catalog: [], lastVerdict: null };

/* ── plumbing ─────────────────────────────────────────────────────────── */

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const body = await response.json().catch(() => ({}));
  return { ok: response.ok, status: response.status, body };
}

const escapeHtml = (value) =>
  String(value).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );

const shortHash = (hash) => (hash ? `${hash.slice(0, 10)}…` : "");

const clockTime = (iso) => {
  try {
    return new Date(iso).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return iso;
  }
};

/* ── the agent panel ──────────────────────────────────────────────────── */

function currentScenario() {
  return SCENARIOS.find((s) => s.id === $("scenario").value) || SCENARIOS[0];
}

function initScenarios() {
  $("scenario").innerHTML = SCENARIOS.map(
    (s) => `<option value="${s.id}">${escapeHtml(s.label)}</option>`
  ).join("");
  $("scenario").addEventListener("change", showPreview);
  showPreview();
}

async function showPreview() {
  const scenario = currentScenario();
  $("scenario-note").textContent = scenario.note;

  const { body } = await api("/api/preview", {
    method: "POST",
    body: { scope: scenario.scope },
  });

  $("scenario-preview").innerHTML = body.valid
    ? `<ul>${body.clauses.map((c) => `<li>${escapeHtml(c)}</li>`).join("")}</ul>`
    : `<strong>Not expressible in SDL v1.</strong><br>${escapeHtml(body.error)}`;
}

async function requestScope() {
  const scenario = currentScenario();
  const { ok, body } = await api("/api/requests", {
    method: "POST",
    body: {
      requested_by: AGENT,
      purpose: scenario.purpose,
      scope: scenario.scope,
      ttl_seconds: scenario.ttl_seconds,
    },
  });
  if (!ok) {
    $("scenario-preview").innerHTML =
      `<strong>The consent layer refused to record this request.</strong><br>${escapeHtml(
        body.detail || "unknown error"
      )}`;
    return;
  }
  await refresh();
}

/* ── the consent panel ────────────────────────────────────────────────── */

function consentCard(request) {
  const clauses = request.clauses
    .map((c) => `<li><span class="tick">✓</span><span>${escapeHtml(c)}</span></li>`)
    .join("");

  return `
    <article class="consent" data-request="${request.request_id}">
      <div class="consent-head">Permission requested</div>
      <div class="consent-body">
        <p class="consent-ask">${escapeHtml(request.summary)}</p>
        ${request.purpose ? `<p class="purpose">“${escapeHtml(request.purpose)}”</p>` : ""}
        <ul class="clauses">${clauses}</ul>
        <div class="consent-meta">
          <span class="tag">Expires after ${escapeHtml(request.duration)}</span>
          <span class="tag">Revocable at any time</span>
          <span class="tag">Every use logged</span>
        </div>
        <div class="consent-actions">
          <button class="btn btn-primary" data-approve="${request.request_id}">Approve</button>
          <button class="btn" data-deny="${request.request_id}">Deny</button>
        </div>
      </div>
    </article>`;
}

function meter(entry) {
  const pct = Math.round((entry.fraction || 0) * 100);
  return `
    <div class="meter">
      <div class="meter-label">
        <span>${escapeHtml(entry.label)}</span>
        <span>${escapeHtml(entry.display)}</span>
      </div>
      <div class="meter-track">
        <div class="meter-fill ${pct >= 100 ? "full" : ""}" style="width:${pct}%"></div>
      </div>
    </div>`;
}

function grantCard(grant) {
  const revocable = grant.state === "active";
  return `
    <article class="card" data-grant="${grant.token_id}">
      <div class="grant-head">
        <span class="state state-${grant.state}">${grant.state}</span>
        <span class="token-id">${escapeHtml(grant.token_id)}</span>
      </div>
      <p style="font-size:14px;margin-bottom:10px">${escapeHtml(grant.summary)}</p>
      ${grant.remaining.map(meter).join("")}
      <div class="consent-meta" style="margin:12px 0 0">
        <span class="tag">${escapeHtml(grant.expiry_phrase)}</span>
        ${
          grant.revoked_reason
            ? `<span class="tag">revoked: ${escapeHtml(grant.revoked_reason)}</span>`
            : ""
        }
      </div>
      ${
        revocable
          ? `<button class="btn btn-danger btn-sm block" data-revoke="${grant.token_id}">
               Revoke this permission
             </button>`
          : ""
      }
    </article>`;
}

/* ── the merchant panel ───────────────────────────────────────────────── */

function verdictCard(payload) {
  const { decision, receipt, action } = payload;
  const checks = decision.checks
    .map(
      (c) => `
      <li>
        <span class="${c.passed ? "mark-ok" : "mark-bad"}">${c.passed ? "✓" : "✕"}</span>
        <span>
          ${escapeHtml(c.name)}
          ${c.detail ? `<span class="detail">${escapeHtml(c.detail)}</span>` : ""}
        </span>
      </li>`
    )
    .join("");

  // Steps after the failure never ran — say so rather than implying they passed.
  const total = 8;
  const notRun =
    decision.checks.length < total
      ? `<li><span class="skipped">·</span><span class="skipped">
           ${total - decision.checks.length} later check(s) not reached
         </span></li>`
      : "";

  return `
    <article class="verdict ${decision.allowed ? "verdict-allowed" : "verdict-denied"}">
      <div class="verdict-head">
        <span class="verdict-icon"><span>${decision.allowed ? "✓" : "✕"}</span></span>
        ${decision.allowed ? "Allowed" : "Denied"}
        ${decision.replayed ? " · replay of an earlier decision" : ""}
      </div>
      <div class="verdict-reason">
        <span class="code">${escapeHtml(decision.code)}</span><br>
        ${escapeHtml(decision.reason)}
      </div>
      ${
        receipt
          ? `<div class="receipt">
               <strong>${escapeHtml(receipt.description)}</strong><br>
               ${escapeHtml(receipt.charged)} — payments are mocked in this demo.
             </div>`
          : ""
      }
      <ul class="checks">${checks}${notRun}</ul>
      ${
        action
          ? `<div class="receipt" style="margin-top:0">
               <span class="hash">action: ${escapeHtml(
                 `${action.type} · ${action.merchant} · $${action.amount_usd} · ${action.category}`
               )}</span>
             </div>`
          : ""
      }
    </article>`;
}

async function buy(itemId) {
  // Must match what renderCatalog() gates the shop on: an *active purchase*
  // grant. Picking any active grant would send a messaging token to a merchant.
  const grant = state.grants.find(
    (g) => g.state === "active" && g.action_type === "purchase"
  );
  if (!grant) return;

  const { body } = await api("/merchant/purchase", {
    method: "POST",
    body: {
      grant: grant.grant,
      item_id: itemId,
      action_id: `act_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    },
  });
  state.lastVerdict = body;
  await refresh();
}

async function loadCatalog() {
  const { body } = await api("/merchant/catalog");
  state.catalog = body.items || [];
}

function renderCatalog() {
  const purchaseGrant = state.grants.find(
    (g) => g.state === "active" && g.action_type === "purchase"
  );
  $("shop-card").hidden = !purchaseGrant;
  if (!purchaseGrant) return;

  $("catalog").innerHTML = state.catalog
    .map(
      (item) => `
      <li>
        <div>
          <div class="title">${escapeHtml(item.title)}</div>
          <div class="cat">${escapeHtml(item.category)}</div>
        </div>
        <div style="display:flex;align-items:center;gap:10px">
          <span class="price">$${escapeHtml(item.price_usd)}</span>
          <button class="btn btn-sm" data-buy="${item.id}">Buy</button>
        </div>
      </li>`
    )
    .join("");
}

/* ── audit ────────────────────────────────────────────────────────────── */

function auditDetail(entry) {
  const p = entry.payload || {};
  if (p.reason && p.code) return `${p.code} — ${p.reason}`;
  if (p.summary) return p.summary;
  if (p.action) return p.action.description || `${p.action.type} $${p.action.amount_usd}`;
  if (p.note) return p.note;
  if (p.purpose) return p.purpose;
  if (p.reason) return p.reason;
  return "";
}

function renderAudit(entries, chain) {
  $("audit-rows").innerHTML = entries.length
    ? entries
        .map(
          (entry) => `
        <tr class="${chain.broken_at && entry.seq >= chain.broken_at ? "broken" : ""}">
          <td class="hash">${entry.seq}</td>
          <td class="hash">${clockTime(entry.ts)}</td>
          <td><span class="event event-${entry.event}">${escapeHtml(entry.event)}</span></td>
          <td class="hash">${escapeHtml(entry.actor)}</td>
          <td class="audit-detail">${escapeHtml(auditDetail(entry))}</td>
          <td class="hash">${shortHash(entry.row_hash)}</td>
        </tr>`
        )
        .join("")
    : `<tr><td colspan="6" style="padding:20px;text-align:center;color:var(--ink-3)">
         Nothing logged yet.
       </td></tr>`;

  const pill = $("chain-pill");
  pill.className = `pill ${chain.intact ? "pill-ok" : "pill-bad"}`;
  $("chain-pill-text").textContent = chain.intact
    ? `audit chain intact (${chain.length})`
    : "audit chain broken";

  const banner = $("chain-banner");
  banner.hidden = chain.intact;
  banner.className = "banner banner-bad";
  if (!chain.intact) {
    banner.innerHTML = `<strong>Tampering detected.</strong> ${escapeHtml(chain.detail)}
      Entry ${chain.broken_at} and everything after it can no longer be trusted.`;
  }
}

async function tamper() {
  const { body } = await api("/api/audit");
  const entries = body.entries || [];
  if (!entries.length) return;
  // Edit the approval itself — the entry someone would most want to rewrite.
  const target = entries.find((e) => e.event === "consent_granted") || entries[0];
  await api(`/api/demo/tamper/${target.seq}`, { method: "POST" });
  await refresh();
}

/* ── refresh ──────────────────────────────────────────────────────────── */

async function refresh() {
  const [pending, grants, audit] = await Promise.all([
    api("/api/requests?status=pending"),
    api("/api/grants"),
    api("/api/audit"),
  ]);

  state.grants = grants.body || [];

  $("pending").innerHTML = (pending.body || []).map(consentCard).join("");
  $("grants").innerHTML = state.grants.map(grantCard).join("");
  $("human-empty").hidden = (pending.body || []).length > 0 || state.grants.length > 0;

  $("verdict").innerHTML = state.lastVerdict
    ? verdictCard(state.lastVerdict)
    : `<p class="empty">No verification attempted yet.</p>`;

  renderCatalog();
  renderAudit(audit.body.entries || [], audit.body.chain || { intact: true, length: 0 });
}

/* ── wiring ───────────────────────────────────────────────────────────── */

document.addEventListener("click", async (event) => {
  const target = event.target.closest("button");
  if (!target) return;

  const { approve, deny, revoke, buy: buyId } = target.dataset;

  if (approve) {
    await api(`/api/requests/${approve}/approve`, { method: "POST", body: { note: "approved" } });
    await refresh();
  } else if (deny) {
    await api(`/api/requests/${deny}/deny`, { method: "POST", body: { note: "not this time" } });
    await refresh();
  } else if (revoke) {
    await api(`/api/grants/${revoke}/revoke`, {
      method: "POST",
      body: { reason: "changed my mind" },
    });
    await refresh();
  } else if (buyId) {
    await buy(buyId);
  }
});

$("request").addEventListener("click", requestScope);
$("verify-chain").addEventListener("click", refresh);
$("tamper").addEventListener("click", tamper);
$("reset").addEventListener("click", async () => {
  await api("/api/demo/reset", { method: "POST" });
  state.lastVerdict = null;
  await refresh();
});

initScenarios();
loadCatalog().then(refresh);
