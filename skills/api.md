# Lens: api — Breaking The Contract And The Input Boundary

## Mandate

Two targets: **(1)** API changes that break older clients, and **(2)** data that
crosses the input boundary unvalidated.

## Phase 1 — Map The Surface

```
Grep: "@(app|router)\.(get|post|put|patch|delete)|@(Get|Post)Mapping|router\."
Glob: "**/schemas/**", "**/serializers/**", "**/dto/**", "**/models/**", "**/openapi*"
```

Is there versioning (`/v1/`, `Accept-Version`)? Without it, every change hits
every client at once.

## Phase 2 — Attack Tree

### A. Breaking Contract Change

Every change that breaks an older client:

| Change | Consequence |
|---|---|
| Field removed or renamed | the client receives `null`, or a parse error |
| Type changed (`int` -> `string`) | deserialisation error |
| Required field added | the older client's request gets a 422 |
| Response shape changed (object -> array) | complete breakage |
| Error code changed | the client's error handling stops working |
| Endpoint removed or path changed | 404 |
| New enum value | the older client does not recognise it |
| Default value changed | silent behaviour change |

**Mobile context:** because a release cannot be rolled back, this means a broken
user base for days or weeks.

### B. Unvalidated Input

```
Grep: "request\.(json|body|form|args|GET|POST)|req\.body|ctx\.request\.body"
```

Is there schema-based validation (Pydantic, zod, Joi, a DTO), or a raw dictionary?
A raw dictionary means type confusion, mass assignment and an injection entry point.

Check for **length limits**, **ranges**, **format**, **allowed values** and
**rejection of unknown fields** (`extra="forbid"` or `strict()`).

### C. No Pagination Limit

```
Grep: "limit|per_page|page_size|take|top" -> is there a maximum?
```

If `?limit=1000000` is accepted, one request can strangle the database and export
everything.

### D. Request Body Size

```
Grep: "max_content_length|bodyLimit|client_max_body_size|MAX_UPLOAD"
```

With no limit, memory exhaustion becomes a denial of service.

### E. File Upload

```
Grep: "upload|multipart|FileField|createReadStream|save\("
```

Check: a size limit, type checking **by content** (an extension alone is not
enough), renaming the file, no execute permission, a separate storage location.

### F. Mass Assignment

```
Grep: "\*\*data|\*\*payload|Object\.assign|\.\.\.body|setattr|update\(request"
```

Can `role`, `is_admin`, `price` or `owner_id` be set from outside?

### G. Webhook Forgery

```
Grep: "webhook|callback|/hooks/|signature|X-Hub|Stripe-Signature"
```

Is the signature verified? With a **constant-time** comparison? Is there replay
protection through a timestamp? Otherwise anyone can send a payment confirmation.

### H. Enumeration

Do response codes reveal whether a user exists?
`/login` returning "user not found" versus "wrong password" enables account
enumeration. `/api/users/1..n` with sequential ids and no ownership check enables
full extraction.

### I. GraphQL Specifics *(if present)*

```
Grep: "graphql|typeDefs|resolver|introspection"
```

Is introspection enabled in production? Are query depth and complexity bounded?
Can batched queries bypass the rate limit?

## Phase 3 — Verification

- [ ] The endpoint is publicly reachable
- [ ] The change really breaks the existing contract (compare against git history or the OpenAPI document)
- [ ] No validation exists at a higher layer (gateway, middleware)

## False-Positive Traps

| Trap | Check |
|---|---|
| The endpoint is new, so no older client knows it | Check when it was added |
| The field was already optional | Check the schema history |
| Validation happens at the gateway | Look at the infrastructure configuration |
| It is an internal API, not a public one | Check the routing |
