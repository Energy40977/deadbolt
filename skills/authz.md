# Lens: authz — Breaking Access Control

## Mandate

Attack the authorisation layer like an attacker. This is the class automated
tooling finds worst: the syntax is correct, the logic is wrong.

Priority: **object-level authorisation (IDOR)** — ahead of everything else.

## Phase 1 — Find The Project's Defence Standard

Learn the *correct* pattern first, then look for what departs from it:

```
Grep: "Depends\(|@login_required|@permission|IsAuthenticated|middleware|guard|before_action|authorize"
Grep: "current_user|request\.user|getCurrentUser|ctx\.user|principal|claims"
```

What you have to answer: **how** is authorisation expressed in this project? A
decorator? Dependency injection? Middleware? A manual check?

## Phase 2 — Enumerate The Attack Surface

```
Grep: "@(app|router|blueprint)\.(get|post|put|patch|delete)|@(Get|Post|Put|Delete)Mapping"
Grep: "router\.(get|post|put|delete)|app\.(get|post|put|delete)|path\(|url\("
Grep: "def (get|post|put|patch|delete)|async def "
```

Build a table per endpoint: **path · method · parameters · authorisation · resource touched**

## Phase 3 — Attack Tree

### A. IDOR — Ownership Never Verified *(most important)*

For every endpoint that accepts an identifier:

```
Grep: "(get|find|filter|findOne|findById|first)\([^)]*id\s*="
Grep: "get_object_or_404|findOrFail|findByPk|\.query\.get\("
```

**Question:** is the query constrained by `owner_id`, `user_id` or `tenant_id`?

Steps to break it:
1. If the query filters on `id` alone, ownership is not verified
2. Confirm with Grep whether the check lives in middleware
3. If it is still absent, this is **CRITICAL, CWE-639**
4. Scenario: `User A -> GET /resource/<B's id> -> B's data`

### B. Unauthenticated Endpoint

Which endpoints from Phase 2 lack the pattern you found in Phase 1?
Pay particular attention to recently added paths and to anything named
"internal", "debug", "health", "webhook", "callback" or "admin".

### C. Vertical Privilege Escalation

```
Grep: "is_admin|is_staff|role\s*==|hasRole|require_role|superuser"
```

Is the role check present on **every** administrative endpoint, or only on some?
One exception opens the whole administrative layer.

### D. Mass Assignment

```
Grep: "\*\*request\.|\.update\(request|Object\.assign|\.\.\.(req|request)\.body|setattr"
```

If a user submits `role`, `is_admin`, `balance` or `owner_id`, does the schema
strip it?

### E. Multi-Tenant Leakage

```
Grep: "tenant|organization|workspace|account_id|company_id"
```

Is the owner filter mandatory at the query layer, or added by hand on every
call? Where it is manual, one omission exposes every tenant.

### F. Decision Made On The Client

```
Grep: "user\.(isAdmin|role)|hasPermission" -> in .tsx/.jsx/.vue/.dart only
```

Is there a matching server-side check, or is this only interface hiding?

### G. Enumerable Identifier

A sequential integer `id` in a public interface makes IDOR easy to automate.
On its own it is MEDIUM; combined with a missing ownership check it amplifies a
CRITICAL.

## Phase 4 — Verification

Do not report a finding before confirming all of this:

- [ ] The endpoint really is registered (wired into the router)
- [ ] No protection exists at the middleware or decorator layer (checked with Grep)
- [ ] The parameter is user-controlled
- [ ] The query runs without an ownership filter

## False-Positive Traps

| Trap | Check |
|---|---|
| The protection is in middleware | Read the router registration and the middleware chain |
| The `id` is internal, not user-supplied | Trace the call site |
| The endpoint genuinely should be public (login, health) | Judge its purpose |
| The ORM applies an owner filter by default (row-level security) | Look at the database configuration |
| It is a test file | Check the path |
