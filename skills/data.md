# Lens: data — Tracing Data-Leak Paths

## Mandate

Trace **where sensitive data flows**. The attacker does not have to break into the
database — a log, an error response, an analytics call or an admin panel has
already exported it.

Classification: **C3** = personal data, payment details, authentication secrets,
private content, cryptographic keys.

## Phase 1 — C3 Inventory

```
Grep: "class .*(User|Customer|Profile|Account|Payment|Card|Patient|Order)"
Grep: "national_id|passport|fin|pin_code|iban|card_number|cvv|ssn|tax_id"
Grep: "birth|dob|address|phone|email|latitude|longitude|device_id"
```

Read the database models and schemas. **Build the list of C3 fields** — the rest
of the phases work from that list.

## Phase 2 — Flow Map

Look in four directions for every C3 field:

```
1. LOGS       Grep: "log|logger|print|console\.|Timber|NSLog|capture"
2. ANALYTICS  Grep: "track|analytics|gtag|mixpanel|amplitude|posthog|segment"
3. RESPONSES  Grep: "serializer|schema|to_dict|toJSON|response_model|Marshal"
4. OUTBOUND   Grep: "requests\.|httpx|fetch\(|axios|webhook|publish|producer"
```

## Phase 3 — Attack Tree

### A. Leak Through Logs *(most common)*

Does a C3 field reach a log call? Note that logging **an entire object** is the
most dangerous form — `logger.info(f"user={user}")` exposes every field.

```
Grep: "log[^(]*\((?:f?['\"][^'\"]*\{|.*(user|payload|request|body|payment)\b"
```

Impact: logs are accessible to a wider audience, retained longer, rarely
encrypted, and frequently shipped to a third-party service.

### B. Leak In An Error Response

```
Grep: "except.*:\s*return|traceback|str\(e\)|e\.stack|getMessage|\.message\}"
```

Does the user-visible response contain a stack trace, the query text, a file path
or a version? That hands the attacker the internal structure and skips their
reconnaissance phase.

### C. Over-Broad Response Schema

`fields = "__all__"`, the use of `exclude`, or returning the model directly means
a C3 field added later is exposed **automatically**.

```
Grep: "__all__|exclude\s*=|model_dump\(\)|\.dict\(\)|jsonify\(.*\.__dict__"
```

This is a time bomb: safe today, leaking after the next migration.

### D. C3 Stored Unencrypted

For the fields from Phase 1: is the column type a plain `String` or `Text`? Is
there field-level encryption (`EncryptedField`, `pgcrypto`, envelope encryption)?

**Get the impact argument right:** disk encryption does not protect against a
leaked database dump — a dump taken from a running system is plaintext.

### E. Real Data In Tests And Fixtures

```
Grep: "@(gmail|mail|yandex|icloud)|\+994|fixtures/|seed|demo_data"
```

Sample emails and phone numbers may not be synthetic; they may belong to a real
person.

### F. Bulk Export Without An Audit Trail

```
Grep: "export|download|csv|xlsx|dump|report" -> on endpoints
```

Who exported what, when, and how much — is it written to a log? If not, internal
misuse is undetectable.

### G. Unmasked Display In The Admin Panel

Do admin list and detail views show C3 fields in the clear? Is the act of viewing
them logged?

### H. Personal Data In The URL

```
Grep: "\?(email|phone|token|user)=|/users/[^/]*@"
```

A URL parameter ends up in logs, in the `Referer` header and in browser history.

## Phase 4 — Verification

- [ ] The field really is C3 (model or schema read)
- [ ] The flow path is a real call chain
- [ ] No central masking filter exists (checked with Grep)
- [ ] It is not test or mock code

## False-Positive Traps

| Trap | Check |
|---|---|
| The logger has a masking processor | Read the logging configuration |
| The field is already hashed or tokenised | Look at the write site |
| `email` is only a variable name, not a value | Read the context |
| It was produced by a synthetic generator | Check for Faker or factory use |
