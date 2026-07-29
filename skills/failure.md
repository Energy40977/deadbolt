# Lens: failure — Abusing Failure Behaviour

## Mandate

What happens when the system **goes wrong**? An attacker's favourite instrument is
not the happy path but the failure path: that is where controls are frequently
switched off.

Priority: **fail-open** — behaviour that grants access on failure.

## Phase 1 — Find The Control Points

Enumerate **every** security decision that can fail:

```
Grep: "verify|validate|authenticate|authorize|check_|is_valid|confirm"
Grep: "jwks|introspect|userinfo|oauth|saml|ldap|2fa|otp|captcha"
```

If any of these decisions depends on an external service, a database or a cache,
ask what happens when that dependency is down.

## Phase 2 — Attack Tree

### A. Fail-Open Control *(most severe)*

```
Grep: "except.*:\s*return True|catch.*return true|\|\| true|or True"
Grep: "except.*:\s*pass|rescue.*nil|if err != nil \{\s*\}"
```

The pattern: the verification service is unreachable, the exception is caught, the
function returns `True` or the check is skipped — and **access is granted**.

How it breaks: if the attacker can make the verification service unreachable
(load, DNS, timeout), the control is switched off entirely.

Example scenario: `The JWKS endpoint stops answering for 5s -> signatures are not
verified -> any token is accepted`

### B. Silently Swallowed Error

```
Grep: "except[^\n:]*:\s*pass|catch\s*\([^)]*\)\s*\{\s*\}|\.catch\(\(\)\s*=>\s*\{?\s*\}?\)"
```

The error is swallowed and the caller treats it as success. The result: the system
carries on in a wrong state and the incident is never noticed.

**Pay particular attention** in payment, write, delete and notification operations.

### C. No Timeout Or Circuit Breaker

```
Grep: "requests\.|httpx\.|fetch\(|urlopen|HttpClient" -> check the timeout argument
```

If the remote service stops answering, the request waits indefinitely, worker
processes are exhausted and **the whole service stalls**. This is denial of
service through a single dependency.

### D. No Idempotency — Financial Impact

```
Grep: "charge|payment|refund|transfer|order|purchase|subscribe"
```

Does a repeated request — a network retry, a user's second click, a webhook retry
— create a second operation? Is there an idempotency key?

Scenario: `POST /refund twice -> the money is refunded twice`

### E. Transaction Boundaries

```
Grep: "commit|transaction|atomic|begin|savepoint"
```

If a multi-step operation fails halfway, is a partially written state left behind?
Scenario: `the balance was debited, the order was never created`

### F. Loss In The Queue

```
Grep: "queue|celery|sidekiq|bull|sqs|kafka|rabbitmq|task"
```

What happens to a failed message? Is there a dead-letter queue, a retry limit,
monitoring? Otherwise the message disappears silently.

### G. Bypassing Rate Limits

```
Grep: "ratelimit|throttle|limiter" -> what is the key?
```

If the limit is per IP, can it be forged with a proxy header (`X-Forwarded-For`)?
If it is per account, is the registration endpoint unlimited?

### H. A Feature That Cannot Be Turned Off

If a new feature is not behind a flag, the only remedy for a defect is a new
release. On a mobile client that means days.

## Phase 3 — Verification

- [ ] The failure path is genuinely reachable (the attacker can trigger it)
- [ ] The post-failure state **grants** rather than denies
- [ ] No compensating check exists at a higher layer

## False-Positive Traps

| Trap | Check |
|---|---|
| `except: pass` is deliberate and commented | Read the comment, look at the layer above |
| The timeout is configured at the HTTP client level | Check the client configuration |
| The retry targets an idempotent endpoint | Judge the nature of the operation |
| Fail-open only affects a non-critical feature | Establish what it protects |
