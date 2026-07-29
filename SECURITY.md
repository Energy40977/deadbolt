# Security Policy

## Reporting a vulnerability

Do not open a public issue for a vulnerability in `deadbolt` itself.

Use GitHub's private reporting: **Security → Report a vulnerability** on this
repository. That channel is visible only to the maintainers.

| | |
|---|---|
| First response | 3 business days |
| Fix target | critical 7 days · high 30 days |
| Disclosure | coordinated, after the fix ships. Reporters are credited with their consent |

## Scope

In scope: the `deadbolt` binary, its rules and skill files, the report renderers,
and anything in this repository.

Out of scope: findings that `deadbolt` reports about *your* code — those are the
tool working. A false positive or a false negative is a normal issue, not a
security report, and it is welcome as such.

## What this tool does with your code

`deadbolt` is read-only. It never modifies a file except through `fix --apply`,
which only writes additive files it names first.

The AI layer shells out to the `claude` CLI with `--allowedTools "Read,Grep,Glob"`.
The agent therefore cannot write, execute or reach the network — the tools are
absent rather than discouraged. Deep dependency research adds `WebSearch` and
`WebFetch`, and never receives repository contents beyond a package name.

Paths listed under `[paths] ai_forbidden` are excluded from the listing handed to a
lens and declared out of scope in the prompt. The lens still holds `Read`, so treat
that key as a boundary you assert, not a sandbox: material that must never be seen
belongs under `[paths] ignore`, which removes it from the inventory entirely.

Secret values are masked in every output. A finding gives the rule and the
location, never the credential.
