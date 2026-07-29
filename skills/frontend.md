# Lens: frontend — Exploiting The Client Side

## Mandate

Client code is under the attacker's **complete control**: they read it, modify it
and replay it. Every secret there is public and every check there is bypassable.

## Phase 1 — Map The Surface

```
Glob: "**/*.tsx", "**/*.jsx", "**/*.vue", "**/*.svelte", "**/*.dart", "**/*.swift", "**/*.kt"
Grep: "process\.env|import\.meta\.env|NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_"
```

## Phase 2 — Attack Tree

### A. Secret Shipped In The Client Bundle *(immediately exploitable)*

```
Grep: "NEXT_PUBLIC_[A-Z_]*(KEY|SECRET|TOKEN|PASSWORD)"
Grep: "VITE_[A-Z_]*(KEY|SECRET|TOKEN)|EXPO_PUBLIC_[A-Z_]*(KEY|SECRET)"
Grep: "apiKey|api_key|serviceRole|service_role|admin.*key" -> in client files
```

A `NEXT_PUBLIC_`, `VITE_` or `EXPO_PUBLIC_` prefix means the value is **injected
into the build**, so it is public in the browser. A `service_role` key there
exposes the entire database.

How it breaks: `curl <site>/_next/static/chunks/*.js | grep -o 'sk_live_[A-Za-z0-9]*'`

### B. Token In `localStorage`

```
Grep: "localStorage|sessionStorage|AsyncStorage" -> together with token/auth/refresh
```

`localStorage` is fully readable by JavaScript, so **one XSS means every session**.
An `httpOnly` cookie cannot be read by XSS. This is the cross-cutting risk that
sharply raises the impact of any XSS.

### C. XSS — Injection Points

```
Grep: "innerHTML|dangerouslySetInnerHTML|v-html|\[innerHTML\]|document\.write"
Grep: "\.html\(|insertAdjacentHTML|outerHTML|createContextualFragment"
```

For each one: does the inserted value come from a user? Is there sanitisation
(DOMPurify)? Is the sanitiser **configured** correctly (if `ALLOWED_TAGS` includes
`a[href]`, `javascript:` still gets through)?

Also: `href={userValue}` allows the `javascript:` scheme, and `<a target="_blank">`
without `rel="noopener"` allows tabnabbing through `window.opener`.

### D. Prototype Pollution And Template Injection

```
Grep: "JSON\.parse\(.*location|merge\(|extend\(|deepMerge|lodash\.merge"
Grep: "eval\(|new Function\(|setTimeout\(['\"]|v-if=\"|{{.*}}"
```

### E. Open Redirect

```
Grep: "location\.(href|assign|replace)\s*=|router\.push\(|redirect\(|window\.open\("
```

If the target URL comes from a parameter, `?next=https://evil.tld` turns your
domain into a phishing vehicle.

### F. Business Logic On The Client

```
Grep: "price|total|amount|discount|balance|quantity" -> wherever a calculation happens
```

If a price or amount is computed on the client and sent to the server, the attacker
changes it. Does the server recompute it?

### G. Authorisation On The Client

```
Grep: "isAdmin|role\s*===|hasPermission|can\(|ability"
```

This is interface hiding only. Is there a matching server-side check? Without one,
the `/admin` route is reachable through a direct API call.

### H. SRI And Third-Party Scripts

```
Grep: "<script src=\"https://|cdn\.|unpkg|jsdelivr"
```

Without an `integrity` attribute, a CDN compromise is code execution on your site.

### I. Mobile Specifics

```
Grep: "WebView|loadUrl|evaluateJavascript|JavascriptInterface|allowFileAccess"
Grep: "UserDefaults|SharedPreferences|shared_preferences" -> with a sensitive key
Grep: "screenshot|FLAG_SECURE|isSecureTextEntry"
```

In a WebView, `JavascriptInterface` is a bridge into native code and
`allowFileAccess` allows local file reads. Do sensitive screens set `FLAG_SECURE`?

### J. Source Maps In Production

```
Grep: "sourceMap|devtool|\.map$"
```

`.map` files in production expose the complete source.

## Phase 3 — Verification

- [ ] The code is part of the production build (not dev-only)
- [ ] The value really is user-controlled
- [ ] No compensating check exists server-side
- [ ] CSP does not block the attack (read the CSP configuration)

## False-Positive Traps

| Trap | Check |
|---|---|
| `dangerouslySetInnerHTML` renders static JSON-LD | Read where the value comes from |
| The `NEXT_PUBLIC_` value genuinely is public (an analytics id) | Establish the type of key |
| `localStorage` only holds a UI preference | Read the key name and the value |
| The redirect allows internal paths only | Read the validation |
