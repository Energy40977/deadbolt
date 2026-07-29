use regex::Regex;

use crate::discover::{Inventory, SourceFile};
use crate::model::{Category, Confidence, Evidence, Finding, Origin, Severity};

/// Every repo-level rule id, so compliance packs can tell what was assessable.
pub const REPO_RULE_IDS: &[&str] = &[
    "DB-REPO-001",
    "DB-REPO-002",
    "DB-REPO-003",
    "DB-REPO-010",
    "DB-REPO-011",
    "DB-REPO-020",
    "DB-REPO-021",
    "DB-REPO-022",
    "DB-REPO-023",
    "DB-REPO-030",
    "DB-REPO-031",
    "DB-REPO-032",
    "DB-REPO-033",
    "DB-REPO-040",
    "DB-REPO-050",
    "DB-REPO-051",
    "DB-REPO-052",
    "DB-REPO-053",
    "DB-REPO-060",
    "DB-REPO-061",
    "DB-REPO-062",
    "DB-REPO-070",
    "DB-REPO-071",
    "DB-REPO-072",
    "DB-REPO-073",
    "DB-REPO-074",
    "DB-REPO-075",
    "DB-REPO-076",
    "DB-REPO-077",
    "DB-REPO-078",
    "DB-REPO-079",
    "DB-REPO-080",
];

/// Every argument maps one-to-one onto a `Finding` field; bundling them into a
/// struct would only add a second name for the same thing.
#[allow(clippy::too_many_arguments)]
fn finding(
    id: &str,
    category: Category,
    severity: Severity,
    title: &str,
    impact: &str,
    remediation: &str,
    confidence: Confidence,
    policy: &[&str],
) -> Finding {
    let mut builder = Finding::builder(id, category, severity)
        .title(title)
        .impact(impact)
        .remediation(remediation)
        .origin(Origin::Static)
        .confidence(confidence)
        .evidence(Evidence::new("<project>", None, ""));
    for reference in policy {
        builder = builder.policy(*reference);
    }
    builder.build()
}

fn content_contains(inventory: &Inventory, needles: &[&str]) -> bool {
    inventory.files.iter().any(|file| {
        !file.content.is_empty()
            && needles
                .iter()
                .any(|needle| file.content.to_lowercase().contains(&needle.to_lowercase()))
    })
}

/// Does the project contain one of these files?
///
/// The inventory holds source files, and documentation is not source: `SECURITY.md`,
/// `LICENSE` and `CODEOWNERS` never appear in it. A check that consulted the
/// inventory alone therefore reported "no security policy" on every project,
/// including one with the file sitting in its root. The filesystem is the authority
/// for existence questions.
fn has_file(inventory: &Inventory, names: &[&str]) -> bool {
    let in_inventory = inventory.files.iter().any(|file| {
        let base = file.rel_path.rsplit('/').next().unwrap_or("");
        names
            .iter()
            .any(|name| base.eq_ignore_ascii_case(name) || file.rel_path.eq_ignore_ascii_case(name))
    });
    in_inventory || names.iter().any(|name| inventory.root.join(name).exists())
}

/// Small helper so a rule can compile a pattern inline without polluting the
/// module with lazily-initialised statics.
fn regex_lite(pattern: &str) -> Regex {
    Regex::new(pattern).expect("A built-in pattern must be valid")
}

fn root_has(inventory: &Inventory, name: &str) -> bool {
    inventory.root.join(name).exists()
}

pub fn audit(inventory: &Inventory) -> Vec<Finding> {
    let mut out = Vec::new();
    let stack = &inventory.stack;

    let env_files: Vec<&SourceFile> = inventory
        .files
        .iter()
        .filter(|f| {
            let base = f.rel_path.rsplit('/').next().unwrap_or("");
            base == ".env" || (base.starts_with(".env.") && !base.ends_with(".example"))
        })
        .collect();

    if !env_files.is_empty() {
        let mut builder = Finding::builder("DB-REPO-001", Category::Secrets, Severity::Critical)
            .title("Environment File (.env) Committed To The Repository")
            .description("An unencrypted .env file is under version control.")
            .impact("These files usually hold database passwords, API keys and signing keys. Removing them from git history completely is practically impossible.")
            .remediation("Untrack it with `git rm --cached`, add it to .gitignore, rotate EVERY value, and move them into an encrypted secret store (SOPS or a vault).")
            .origin(Origin::Static)
            .confidence(Confidence::Confirmed)
            .cwe(798)
            .policy("SEC-03, b.3.1/2");
        for file in env_files.iter().take(5) {
            builder = builder.evidence(Evidence::new(&file.rel_path, None, ""));
        }
        out.push(builder.build());
    }

    let gitignore = inventory.read_root_file(".gitignore").unwrap_or_default();
    if !root_has(inventory, ".gitignore") {
        out.push(finding(
            "DB-REPO-002",
            Category::Configuration,
            Severity::Medium,
            "No .gitignore File",
            "Secret files, build output and local configuration end up in the repository by accident.",
            "Add a .gitignore matching the stack; at minimum .env, key files and build directories.",
            Confidence::Confirmed,
            &["SEC-03, b.3.1/2"],
        ));
    } else if !gitignore.contains(".env") {
        out.push(finding(
            "DB-REPO-003",
            Category::Secrets,
            Severity::High,
            ".env Is Not Listed In .gitignore",
            "Nothing prevents an environment file from being committed by accident, which is the most common secret-leak path.",
            "Add `.env` and `.env.*` to .gitignore, with `!.env.example` as the exception.",
            Confidence::Confirmed,
            &["SEC-03, b.3.1/2"],
        ));
    }

    let has_npm = stack.package_managers.iter().any(|m| m == "npm");
    let lockfiles = [
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lockb",
        "poetry.lock",
        "Cargo.lock",
        "go.sum",
        "composer.lock",
        "Gemfile.lock",
        "pubspec.lock",
        "uv.lock",
    ];
    if !stack.package_managers.is_empty() && !has_file(inventory, &lockfiles) {
        out.push(finding(
            "DB-REPO-010",
            Category::SupplyChain,
            Severity::High,
            "No Dependency Lockfile",
            "Every install can resolve different versions: the build is not reproducible and a compromised new release enters the environment silently.",
            "Create a lockfile, commit it, and use `--frozen-lockfile` or `--locked` in CI.",
            Confidence::Confirmed,
            &["DEV-02, b.12.1"],
        ));
    }

    if let Some(requirements) = inventory
        .files
        .iter()
        .find(|f| f.rel_path.ends_with("requirements.txt"))
    {
        let unpinned = requirements
            .content
            .lines()
            .filter(|line| {
                let line = line.trim();
                !line.is_empty()
                    && !line.starts_with('#')
                    && !line.starts_with('-')
                    && !line.contains("==")
                    && !line.contains('@')
            })
            .count();
        if unpinned > 0 {
            out.push(
                Finding::builder("DB-REPO-011", Category::SupplyChain, Severity::Medium)
                    .title(format!("{unpinned} Dependencies Are Not Pinned To An Exact Version"))
                    .impact("A new release reaches the environment automatically, so a breaking change or a malicious version arrives unchecked.")
                    .remediation("Pin every dependency with `==` and manage updates through Renovate or Dependabot.")
                    .origin(Origin::Static)
                    .confidence(Confidence::Confirmed)
                    .evidence(Evidence::new(&requirements.rel_path, None, ""))
                    .policy("DEV-02, b.12.1")
                    .build(),
            );
        }
    }

    if stack.ci_systems.is_empty() {
        out.push(finding(
            "DB-REPO-020",
            Category::Compliance,
            Severity::Medium,
            "No CI Pipeline Detected",
            "Tests, linting and security checks never run automatically: the rule lives in human memory and is broken in practice.",
            "Set up a minimal pipeline: tests, lint, secret scan and dependency vulnerability check.",
            Confidence::Probable,
            &["DEV-03, b.4"],
        ));
    } else if !content_contains(
        inventory,
        &[
            "gitleaks",
            "trufflehog",
            "detect-secrets",
            "trivy",
            "semgrep",
            "snyk",
            "bandit",
            "safety",
            "npm audit",
            "pip-audit",
            "cargo audit",
            "grype",
            "osv-scanner",
        ],
    ) {
        out.push(finding(
            "DB-REPO-021",
            Category::SupplyChain,
            Severity::Medium,
            "CI Pipeline Has No Security Check",
            "Secret leaks and vulnerable dependencies are not caught at merge time, so the defect reaches production.",
            "Add a secret scanner (gitleaks) and a dependency scanner (trivy or osv-scanner) to the pipeline, and let critical findings block the merge.",
            Confidence::Probable,
            &["DEV-03, b.4.1"],
        ));
    }

    // A language that keeps unit tests in the same file has no test *files* at all.
    // Counting only paths reports "no tests" on a repository with hundreds of them.
    let test_files = inventory
        .files
        .iter()
        .filter(|f| f.is_test() || super::test_region_start(f).is_some())
        .count();
    let code_files = inventory
        .files
        .iter()
        .filter(|f| !f.is_test() && super::is_code_language(f.language))
        .count();
    if code_files > 20 && test_files == 0 {
        out.push(finding(
            "DB-REPO-022",
            Category::Compliance,
            Severity::High,
            "No Test Files Detected",
            "Nothing verifies whether a change breaks existing behaviour, so every release carries regression risk.",
            "Start with the critical flows: authentication, authorisation, payments and data writes.",
            Confidence::Confirmed,
            &["DEV-01, b.9"],
        ));
    } else if code_files > 50 && (test_files as f64) < (code_files as f64 * 0.1) {
        out.push(
            Finding::builder("DB-REPO-023", Category::Compliance, Severity::Medium)
                .title(format!(
                    "Test Coverage Looks Low ({test_files} Test Files / {code_files} Code Files)"
                ))
                .impact("Most regressions will not be caught automatically.")
                .remediation("Cover the critical modules first, and add a regression test for every defect you fix.")
                .origin(Origin::Static)
                .confidence(Confidence::Probable)
                .evidence(Evidence::new("<project>", None, ""))
                .policy("DEV-01, b.9")
                .build(),
        );
    }

    let is_web = stack.has_backend || stack.has_frontend;

    if is_web
        && !content_contains(
            inventory,
            &[
                "strict-transport-security",
                "helmet",
                "secure_headers",
                "x-content-type-options",
                "content-security-policy",
                "SecurityMiddleware",
            ],
        )
    {
        out.push(finding(
            "DB-REPO-030",
            Category::Configuration,
            Severity::Medium,
            "Security Headers Are Not Configured",
            "Without HSTS, CSP and X-Content-Type-Options the browser-side defence layers do not apply: MITM downgrade, XSS and MIME sniffing all become easier.",
            "Set the headers at the reverse proxy or in the application: HSTS (>=1 year), CSP, X-Content-Type-Options, Referrer-Policy, frame-ancestors.",
            Confidence::Probable,
            &["DEV-02, b.8.3"],
        ));
    }

    if is_web
        && !content_contains(
            inventory,
            &[
                "ratelimit",
                "rate_limit",
                "rate-limit",
                "throttle",
                "slowapi",
                "express-rate-limit",
                "limiter",
                "Throttling",
            ],
        )
    {
        out.push(finding(
            "DB-REPO-031",
            Category::Configuration,
            Severity::High,
            "No Rate Limiting Detected",
            "Credential stuffing, OTP guessing and bulk data extraction proceed unhindered, and denial of service becomes possible.",
            "Apply rate limiting to every public endpoint, with separate per-IP and per-account limits on authentication endpoints.",
            Confidence::Probable,
            &["DEV-02, b.10.1"],
        ));
    }

    let has_auth = content_contains(
        inventory,
        &[
            "login",
            "signin",
            "authenticate",
            "password",
            "jwt",
            "session",
        ],
    );
    if has_auth
        && !content_contains(
            inventory,
            &[
                "argon2",
                "bcrypt",
                "scrypt",
                "pbkdf2",
                "password_hash",
                "make_password",
                "BCryptPasswordEncoder",
                "Hash::make",
            ],
        )
    {
        out.push(finding(
            "DB-REPO-032",
            Category::Cryptography,
            Severity::High,
            "No Memory-Hard Password Function Detected",
            "Passwords are either stored in the clear or processed with a fast hash, so a database leak exposes them within hours.",
            "Use Argon2id (m>=64 MiB, t>=3) and migrate existing passwords on next login.",
            Confidence::Probable,
            &["CRYPTO-01, b.4.1"],
        ));
    }

    if has_auth
        && !content_contains(
            inventory,
            &[
                "totp",
                "mfa",
                "2fa",
                "two_factor",
                "twofactor",
                "webauthn",
                "passkey",
                "otp",
            ],
        )
    {
        out.push(finding(
            "DB-REPO-033",
            Category::Authentication,
            Severity::Low,
            "No Multi-Factor Authentication Detected",
            "A leaked password is enough to take over an account, and the risk is highest for administrative accounts.",
            "Add TOTP or passkey support, at minimum for administrative and privileged accounts.",
            Confidence::Possible,
            &["SEC-02, b.3.1"],
        ));
    }

    let pii_markers = [
        "national_id",
        "passport",
        "fin_code",
        "birth_date",
        "date_of_birth",
        "card_number",
        "iban",
        "ssn",
        "tax_id",
    ];
    if content_contains(inventory, &pii_markers)
        && !content_contains(
            inventory,
            &[
                "encrypt",
                "aesgcm",
                "aes_gcm",
                "fernet",
                "pgcrypto",
                "EncryptedField",
                "chacha20",
                "envelope",
                "kms",
            ],
        )
    {
        out.push(finding(
            "DB-REPO-040",
            Category::DataProtection,
            Severity::High,
            "Personal Data Stored Without Field-Level Encryption",
            "A leaked database dump exposes personal data in readable form. Disk encryption does not protect against this scenario: a dump taken from a running system is plaintext.",
            "Apply envelope encryption to sensitive columns (AES-256-GCM with a KMS or KEK), and add a blind index (HMAC) if exact-match search is required.",
            Confidence::Probable,
            &["CRYPTO-01, b.6.1.1", "SEC-05, b.3"],
        ));
    }

    if stack.has_mobile
        && !content_contains(
            inventory,
            &[
                "min_supported_version",
                "minSupportedVersion",
                "force_update",
                "forceUpdate",
                "remote_config",
                "feature_flag",
                "featureFlag",
                "kill_switch",
            ],
        )
    {
        out.push(finding(
            "DB-REPO-050",
            Category::Compliance,
            Severity::High,
            "Mobile App Has No Remote Kill Switch",
            "A release that reached the store cannot be rolled back. A server-controlled flag is the only way to disable a broken feature; without one the defect stays on user devices until a new release is approved.",
            "Add a server-side configuration endpoint: feature flags, `min_supported_version` and a service mode (normal, read-only, suspended).",
            Confidence::Probable,
            &["DEV-04, b.4.4"],
        ));
    }

    if !has_file(
        inventory,
        &["SECURITY.md", "security.md", ".well-known/security.txt"],
    ) {
        out.push(finding(
            "DB-REPO-051",
            Category::Compliance,
            Severity::Low,
            "No Security Policy Document (SECURITY.md)",
            "A researcher who finds a vulnerability has no way to reach you, so the finding may go to a public channel.",
            "Add SECURITY.md with a contact address, a response time and a disclosure process.",
            Confidence::Confirmed,
            &[],
        ));
    }

    if stack.has_iac && !content_contains(inventory, &["USER "]) {
        out.push(finding(
            "DB-REPO-052",
            Category::Infrastructure,
            Severity::Medium,
            "No Unprivileged User In The Container",
            "Without a USER instruction in the Dockerfile the process runs as root: an attacker with code execution in the application gets full privileges inside the container.",
            "Create an unprivileged user, set `USER appuser`, and adjust file ownership.",
            Confidence::Probable,
            &[],
        ));
    }

    {
        const EOL: &[(&str, &[&str])] = &[
            (
                "node",
                &[
                    "0", "4", "6", "8", "10", "12", "14", "16", "17", "18", "19", "21",
                ],
            ),
            (
                "python",
                &[
                    "2", "2.7", "3.0", "3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7", "3.8",
                ],
            ),
            (
                "ruby",
                &[
                    "2.0", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "3.0",
                ],
            ),
            (
                "php",
                &["5", "5.6", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0"],
            ),
            (
                "golang",
                &["1.15", "1.16", "1.17", "1.18", "1.19", "1.20", "1.21"],
            ),
            (
                "openjdk",
                &[
                    "7", "8", "9", "10", "12", "13", "14", "15", "16", "18", "19", "20",
                ],
            ),
            (
                "ubuntu",
                &[
                    "14.04", "16.04", "18.04", "20.10", "21.04", "21.10", "22.10", "23.04",
                ],
            ),
            ("debian", &["8", "9", "10", "jessie", "stretch", "buster"]),
            (
                "alpine",
                &[
                    "3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15", "3.16", "3.17",
                ],
            ),
            ("postgres", &["9", "9.6", "10", "11", "12"]),
            ("mysql", &["5.5", "5.6", "5.7"]),
            ("nginx", &["1.18", "1.20"]),
        ];

        let mut stale: Vec<(String, String, u32)> = Vec::new();
        for file in inventory
            .files
            .iter()
            .filter(|file| file.language == "Docker")
        {
            for (line_no, line) in file.lines_iter() {
                let trimmed = line.trim();
                let reference = match trimmed
                    .strip_prefix("FROM ")
                    .or_else(|| trimmed.strip_prefix("from "))
                {
                    Some(reference) => reference.split_whitespace().next().unwrap_or(""),
                    None => continue,
                };
                let (image, tag) = match reference.rsplit_once(':') {
                    Some((image, tag)) => (image, tag),
                    None => continue,
                };
                let short = image.rsplit('/').next().unwrap_or(image);
                let version = tag.split('-').next().unwrap_or(tag);

                if let Some((_, eol_versions)) =
                    EOL.iter().find(|(candidate, _)| *candidate == short)
                {
                    if eol_versions.contains(&version) {
                        stale.push((format!("{short}:{tag}"), file.rel_path.clone(), line_no));
                    }
                }
            }
        }

        if !stale.is_empty() {
            let mut builder = Finding::builder(
                "DB-REPO-062",
                Category::Infrastructure,
                Severity::High,
            )
            .title(format!(
                "{} Base Container Image Is End-Of-Life",
                stale.len()
            ))
            .description(
                stale
                    .iter()
                    .map(|(image, _, _)| image.clone())
                    .collect::<Vec<_>>()
                    .join(", "),
            )
            .impact(
                "An unsupported base image receives no security updates: your application code may be \
clean while the operating system and runtime underneath keep unpatched vulnerabilities.",
            )
            .remediation(
                "Move to a supported version and pin the image by digest \
(`FROM image:tag@sha256:...`), then re-check the dependencies.",
            )
            .origin(Origin::Static)
            .confidence(Confidence::Confirmed)
            .cwe(1104)
            .policy("DEV-02, b.12.4");
            for (_, file, line) in stale.iter().take(8) {
                builder = builder.evidence(Evidence::new(file, Some(*line), ""));
            }
            out.push(builder.build());
        }
    }

    if !gitignore.is_empty() {
        let patterns: Vec<String> = gitignore
            .lines()
            .map(|line| line.split('#').next().unwrap_or("").trim().to_string())
            .filter(|line| !line.is_empty() && !line.starts_with('!') && !line.ends_with('/'))
            .collect();

        let tracked_but_ignored: Vec<&SourceFile> = inventory
            .files
            .iter()
            .filter(|file| {
                patterns.iter().any(|pattern| {
                    let base = file.rel_path.rsplit('/').next().unwrap_or("");
                    let needle = pattern.trim_start_matches("**/").trim_start_matches('/');
                    if needle.is_empty() {
                        return false;
                    }
                    if let Some(suffix) = needle.strip_prefix('*') {
                        return base.ends_with(suffix);
                    }
                    base == needle || file.rel_path == needle
                })
            })
            .take(20)
            .collect();

        if !tracked_but_ignored.is_empty() {
            let mut builder = Finding::builder(
                "DB-REPO-060",
                Category::Configuration,
                Severity::Medium,
            )
            .title(format!(
                "{} Files Are Listed In .gitignore But Still Tracked",
                tracked_but_ignored.len()
            ))
            .description(
                ".gitignore only hides UNTRACKED files. A rule added later does not remove \
a file that has already been committed.",
            )
            .impact(
                "The team believes the file is hidden while git keeps shipping it to every \
clone. This pattern happens most often with `.env` and key files.",
            )
            .remediation(
                "Untrack it with `git rm --cached <file>` and commit. If the file holds \
secrets, you MUST rotate the values — they remain in history.",
            )
            .origin(Origin::Static)
            .confidence(Confidence::Confirmed)
            .policy("SEC-03, b.3.1/2");
            for file in tracked_but_ignored.iter().take(8) {
                builder = builder.evidence(Evidence::new(&file.rel_path, None, ""));
            }
            out.push(builder.build());
        }
    }

    if stack.has_migrations {
        let migration_columns: std::collections::HashSet<String> = inventory
            .files
            .iter()
            .filter(|file| file.is_migration() || file.language == "SQL")
            .flat_map(|file| {
                let mut names = Vec::new();
                for (_, line) in file.lines_iter() {
                    if let Some(rest) = line.split("sa.Column(").nth(1) {
                        if let Some(name) = rest.split(['\'', '"']).nth(1) {
                            names.push(name.to_string());
                        }
                    }
                    let lowered = line.to_lowercase();
                    if let Some(index) = lowered.find("add column") {
                        if let Some(name) = line[index + 10..].split_whitespace().next() {
                            names.push(name.trim_matches(['"', '`', ',']).to_string());
                        }
                    }
                }
                names
            })
            .collect();

        if !migration_columns.is_empty() {
            let column_definition = regex_lite(
                r"^\s*([a-z_][a-z0-9_]*)\s*(?::\s*Mapped\[[^\]]*\]\s*=\s*mapped_column|\s*=\s*(?:sa\.)?Column)\(",
            );
            let mut missing: Vec<(String, String, u32)> = Vec::new();

            for file in &inventory.files {
                if file.is_migration() || file.is_test() || file.language != "Python" {
                    continue;
                }
                if !file.content.contains("Column") {
                    continue;
                }
                for (line_no, line) in file.lines_iter() {
                    if let Some(name) = column_definition
                        .captures(line)
                        .and_then(|caps| caps.get(1))
                        .map(|m| m.as_str().to_string())
                    {
                        if !migration_columns.contains(&name) && name != "id" {
                            missing.push((name, file.rel_path.clone(), line_no));
                        }
                    }
                }
            }

            if !missing.is_empty() {
                let mut builder =
                    Finding::builder("DB-REPO-061", Category::Database, Severity::High)
                        .title(format!(
                            "{} Model Columns Are Never Created By A Migration",
                            missing.len()
                        ))
                        .description(
                            missing
                                .iter()
                                .take(10)
                                .map(|(name, file, line)| format!("`{name}` ({file}:{line})"))
                                .collect::<Vec<_>>()
                                .join(", "),
                        )
                        .impact(
                            "The code reads this column but the schema has no such column: after \
deployment that flow fails on every request. During a rolling deploy only the new pods hit \
the old schema, so the failure is partial and harder to diagnose.",
                        )
                        .remediation(
                            "Write a migration for the column and deploy it BEFORE the code \
(expand-contract).",
                        )
                        .origin(Origin::Static)
                        .confidence(Confidence::Probable)
                        .policy("DEV-04, b.6.2");
                for (_, file, line) in missing.iter().take(8) {
                    builder = builder.evidence(Evidence::new(file, Some(*line), ""));
                }
                out.push(builder.build());
            }
        }
    }

    if has_npm && !content_contains(inventory, &["\"engines\""]) {
        out.push(finding(
            "DB-REPO-053",
            Category::SupplyChain,
            Severity::Low,
            "Node Version Is Not Constrained",
            "Behaviour differs between Node versions, and the project may run on a version that no longer receives security updates.",
            "Add an `engines` section to package.json and use the same version in CI.",
            Confidence::Confirmed,
            &[],
        ));
    }

    // --- controls that used to be marked "manual assessment required" ----------
    //
    // A compliance control with no detector is reported as `unknown`, and an
    // unknown control is indistinguishable from an unchecked one at audit time.
    // Each of the following looks for the *mechanism* the control asks for. The
    // mechanism is checkable even when the policy behind it is not.

    if content_contains(inventory, &["password"]) {
        let breach_check = content_contains(
            inventory,
            &[
                "haveibeenpwned",
                "pwnedpasswords",
                "pwned_password",
                "breached_password",
                "password_blocklist",
                "common-passwords",
                "common_passwords",
                "zxcvbn",
                "password_strength",
                "PasswordStrength",
            ],
        );
        if !breach_check {
            out.push(finding(
                "DB-REPO-070",
                Category::Authentication,
                Severity::Medium,
                "Passwords Are Not Checked Against A Breached-Password List",
                "A password that satisfies every complexity rule can still be one of the most common credentials in circulation. Without a blocklist check, credential stuffing succeeds on accounts that appear to follow policy.",
                "Check new passwords against a breached list — the k-anonymity API of Pwned Passwords, or a local copy of the top ten thousand — and reject a match at registration and at password change.",
                Confidence::Probable,
                &["SEC-04, b.2"],
            ));
        }
    }

    let upload_markers = [
        "multipart",
        "UploadFile",
        "FileField",
        "createReadStream",
        "MultipartFile",
        "formidable",
        "multer",
        "ActiveStorage",
        "CarrierWave",
    ];
    if content_contains(inventory, &upload_markers) {
        let validated = content_contains(
            inventory,
            &[
                "content_type",
                "content-type",
                "mimetype",
                "mime_type",
                "magic",
                "filetype",
                "python-magic",
                "file-type",
                "imghdr",
                "allowed_extensions",
                "ALLOWED_EXTENSIONS",
                "max_upload",
                "MAX_UPLOAD",
                "max_content_length",
            ],
        );
        if !validated {
            out.push(finding(
                "DB-REPO-071",
                Category::ApiContract,
                Severity::High,
                "File Upload Has No Type Or Size Policy",
                "An upload endpoint that accepts any content type and any size lets an attacker store executable content on your storage and exhaust the disk. Checking the extension alone does not help: the extension is chosen by the caller.",
                "Validate the type by content rather than by extension, cap the size, rename the file yourself, store it outside the web root, and serve it without execute permission.",
                Confidence::Probable,
                &["SEC-05, b.6"],
            ));
        }
    }

    let stores_personal_data = content_contains(
        inventory,
        &[
            "national_id",
            "passport",
            "iban",
            "card_number",
            "birth_date",
            "date_of_birth",
            "phone_number",
            "personal_data",
        ],
    );
    if stores_personal_data {
        let retention = content_contains(
            inventory,
            &[
                "retention",
                "expires_at",
                "expire_at",
                "delete_after",
                "ttl",
                "purge",
                "anonymize",
                "anonymise",
                "data_retention",
                "cleanup_old",
            ],
        );
        if !retention {
            out.push(finding(
                "DB-REPO-072",
                Category::Privacy,
                Severity::Medium,
                "No Retention Period Is Implemented For Personal Data",
                "Personal data kept with no expiry accumulates indefinitely, which raises the impact of any future breach and conflicts with the storage-limitation principle. A policy document alone changes nothing if no code deletes anything.",
                "Give each category of personal data a retention window, implement the deletion as a scheduled job, and log what it removed.",
                Confidence::Probable,
                &["SEC-05, b.3"],
            ));
        }

        let subject_rights = content_contains(
            inventory,
            &[
                "delete_account",
                "delete-account",
                "account_deletion",
                "export_data",
                "data_export",
                "download_my_data",
                "gdpr",
                "subject_access",
                "erasure",
                "right_to_be_forgotten",
            ],
        );
        if !subject_rights {
            out.push(finding(
                "DB-REPO-073",
                Category::Privacy,
                Severity::Medium,
                "No Mechanism For Data Access Or Deletion Requests",
                "A user who asks for their data, or for its deletion, has to be served by hand. Manual handling misses the statutory deadline as volume grows, and a deletion done by hand usually misses the copies in backups, logs and analytics.",
                "Implement account deletion and data export as endpoints, and record which stores each one touches.",
                Confidence::Probable,
                &["SEC-05, b.7"],
            ));
        }
    }

    let backup_markers = [
        "pg_dump",
        "mysqldump",
        "mongodump",
        "restic",
        "borgbackup",
        "backup",
    ];
    if content_contains(inventory, &backup_markers) {
        let encrypted_backup = content_contains(
            inventory,
            &[
                "gpg",
                "age -r",
                "sops",
                "openssl enc",
                "restic",
                "borg",
                "kms",
                "sse-kms",
                "sse_kms",
                "ServerSideEncryption",
                "encryption_at_rest",
            ],
        );
        if !encrypted_backup {
            out.push(finding(
                "DB-REPO-074",
                Category::DataProtection,
                Severity::High,
                "Backups Are Not Encrypted",
                "A backup holds the same data as production with none of its access controls. An unencrypted dump on shared storage, or in a bucket that later becomes public, is a full database leak that nobody notices.",
                "Encrypt the dump before it leaves the host (age, gpg or restic), keep the key out of the backup pipeline, and test a restore.",
                Confidence::Probable,
                &["SEC-07, b.2"],
            ));
        }

        let immutable = content_contains(
            inventory,
            &[
                "object-lock",
                "object_lock",
                "ObjectLockConfiguration",
                "versioning",
                "immutable",
                "retention_policy",
                "governance",
                "compliance_mode",
            ],
        );
        if !immutable {
            out.push(finding(
                "DB-REPO-075",
                Category::Infrastructure,
                Severity::High,
                "Backups Can Be Deleted By Whoever Reaches Production",
                "If the identity that runs production can also delete the backups, then one compromised credential — or one mistaken command — destroys both the data and its only copy. Ransomware operators delete backups first for exactly this reason.",
                "Turn on object-lock or immutable versioning on the backup bucket, and give the production role write-only access to it.",
                Confidence::Probable,
                &["SEC-07, b.3"],
            ));
        }
    }

    // --- controls whose only detector was an AI lens ---------------------------
    //
    // An AI lens is the right tool for judgement, not for presence. Where the
    // control asks whether a mechanism exists at all, a deterministic check
    // answers it in every run, including the cheap ones.

    let state_changing = content_contains(
        inventory,
        &[
            "session",
            "cookie",
            "login",
            "signin",
            "sign_in",
            "authenticate",
        ],
    ) && content_contains(inventory, &["post", "put", "patch", "delete"]);
    if state_changing {
        let csrf = content_contains(
            inventory,
            &[
                "csrf",
                "xsrf",
                "CsrfProtect",
                "csrf_token",
                "SameSite",
                "samesite",
                "double_submit",
                "anti-forgery",
                "antiforgery",
                "verify_origin",
            ],
        );
        if !csrf {
            out.push(finding(
                "DB-REPO-076",
                Category::Authentication,
                Severity::High,
                "No CSRF Protection Detected On A Cookie Session",
                "With cookie-based sessions and no CSRF defence, any site the user visits can issue a state-changing request on their behalf: the browser attaches the session cookie automatically and the server cannot tell the difference.",
                "Use `SameSite=Lax` or `Strict` on the session cookie, and add a CSRF token or an origin check to every state-changing endpoint. Token-in-header authentication is not affected, but a cookie fallback re-opens the hole.",
                Confidence::Probable,
                &["SEC-04, b.5"],
            ));
        }
    }

    let card_fields = content_contains(
        inventory,
        &[
            "card_number",
            "cardnumber",
            "pan_number",
            "card_pan",
            "cvv",
            "cvc",
            "expiry_month",
            "exp_month",
            "cardholder",
        ],
    );
    if card_fields {
        let tokenised = content_contains(
            inventory,
            &[
                "payment_token",
                "card_token",
                "setup_intent",
                "payment_method_id",
                "stripe",
                "adyen",
                "braintree",
                "tokenize",
                "tokenise",
                "vault_id",
            ],
        );
        if !tokenised {
            out.push(finding(
                "DB-REPO-077",
                Category::Privacy,
                Severity::Critical,
                "Payment Card Fields Are Handled Without Tokenisation",
                "Holding a card number, and worse a CVV, puts the whole system inside PCI DSS scope and makes any database leak a card-data breach with mandatory notification. Tokenisation moves both the data and the scope to the payment provider.",
                "Never store the card number or CVV. Take payment details straight to the provider and keep only its token, then delete any card columns and rotate what was captured.",
                Confidence::Probable,
                &["SEC-05, b.5"],
            ));
        }
    }

    let real_data_in_tests = inventory.files.iter().any(|file| {
        let path = file.rel_path.to_lowercase();
        let is_test_data = file.is_test()
            || path.contains("fixture")
            || path.contains("seed")
            || path.contains("/testdata/");
        if !is_test_data {
            return false;
        }
        let body = &file.content;
        // A real address plus a real-looking phone number is the pattern that
        // distinguishes copied production data from a generated fixture.
        let has_real_mailbox = ["@gmail.", "@yahoo.", "@hotmail.", "@icloud.", "@mail.ru"]
            .iter()
            .any(|domain| body.contains(domain));
        let has_generator = [
            "faker",
            "Faker",
            "factory",
            "Factory",
            "mimesis",
            "@example.",
        ]
        .iter()
        .any(|marker| body.contains(marker));
        has_real_mailbox && !has_generator
    });
    if real_data_in_tests {
        out.push(finding(
            "DB-REPO-078",
            Category::Privacy,
            Severity::High,
            "Test Data Contains Real Mailboxes Rather Than Generated Values",
            "Test fixtures are shared far more widely than production data: every developer, every CI log and every fork holds a copy. Real contact details there are a disclosure of personal data with no legal basis, and test runs can send real mail to real people.",
            "Generate fixtures with Faker or a factory, or pseudonymise an extract before it becomes a fixture. Keep `@example.com` for addresses that must look real.",
            Confidence::Probable,
            &["SEC-05, b.4"],
        ));
    }

    let bulk_export = content_contains(
        inventory,
        &[
            "export_csv",
            "export_excel",
            "to_csv",
            "download_report",
            "bulk_export",
            "/export",
            "writexlsx",
            "csvwriter",
        ],
    );
    if bulk_export {
        let audited = content_contains(
            inventory,
            &[
                "audit_log",
                "auditlog",
                "audit_trail",
                "AuditEvent",
                "access_log",
                "record_access",
                "log_export",
            ],
        );
        if !audited {
            out.push(finding(
                "DB-REPO-079",
                Category::Privacy,
                Severity::Medium,
                "Bulk Export Is Not Written To An Audit Trail",
                "A bulk export is the cheapest way to remove a whole dataset, and it looks exactly like ordinary use. Without a record of who exported what and how much, insider misuse leaves no trace and an incident cannot be scoped afterwards.",
                "Log every export with the caller, the filter and the row count, and keep that log where the exporting user cannot edit it.",
                Confidence::Probable,
                &["SEC-05, b.8"],
            ));
        }
    }

    let migrations: Vec<&SourceFile> = inventory
        .files
        .iter()
        .filter(|file| {
            let path = file.rel_path.to_lowercase();
            path.contains("migration")
                || path.contains("/alembic/")
                || path.contains("/db/migrate/")
        })
        .collect();
    if !migrations.is_empty() {
        let without_rollback: Vec<&&SourceFile> = migrations
            .iter()
            .filter(|file| {
                let body = &file.content;
                let declares = body.contains("def downgrade")
                    || body.contains("def down")
                    || body.contains("async down")
                    || body.contains("public function down");
                if !declares {
                    return true;
                }
                // A declared rollback that only contains `pass` is not a rollback.
                let tail = body
                    .split("def downgrade")
                    .nth(1)
                    .or_else(|| body.split("def down").nth(1))
                    .unwrap_or("");
                let head: String = tail.chars().take(220).collect();
                head.contains("pass")
                    || head.contains("NotImplementedError")
                    || head.contains("raise")
                    || head.trim().is_empty()
            })
            .collect();

        if !without_rollback.is_empty() {
            let mut builder = Finding::builder(
                "DB-REPO-080",
                Category::Database,
                Severity::High,
            )
            .title(format!(
                "{} Migrations Have No Usable Rollback Step",
                without_rollback.len()
            ))
            .description(
                "The migration declares no reverse operation, or declares one that raises or does nothing.".to_string(),
            )
            .impact(
                "Once the migration is deployed there is no way back. If the release that needed it has to be reverted, the schema stays ahead of the code and every request on that path fails until somebody writes the reverse operation under pressure.".to_string(),
            )
            .remediation(
                "Write the reverse operation while the forward one is still fresh, and run it once against a copy of production so it is known to work.".to_string(),
            )
            .origin(Origin::Static)
            .confidence(Confidence::Confirmed)
            .policy("DEV-04, b.6.5");
            for file in without_rollback.iter().take(6) {
                builder = builder.evidence(Evidence::new(&file.rel_path, None, ""));
            }
            out.push(builder.build());
        }
    }

    out
}

#[cfg(test)]
mod repo_file_tests {
    use super::*;
    use crate::model::StackProfile;
    use std::path::PathBuf;

    fn empty_inventory(root: PathBuf) -> Inventory {
        Inventory {
            root,
            files: Vec::new(),
            stack: StackProfile::default(),
            manifests: Vec::new(),
            skipped_large: 0,
            skipped_large_names: Vec::new(),
        }
    }

    #[test]
    fn documentation_is_found_on_disk_even_though_it_is_never_inventoried() {
        let dir = std::env::temp_dir().join(format!("deadbolt-has-file-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("SECURITY.md"), "# Security Policy\n").unwrap();

        let inventory = empty_inventory(dir.clone());
        assert!(
            has_file(&inventory, &["SECURITY.md", "security.md"]),
            "a file present in the root must be found without being inventoried"
        );
        assert!(!has_file(&inventory, &["CODE_OF_CONDUCT.md"]));

        std::fs::remove_dir_all(&dir).ok();
    }
}
