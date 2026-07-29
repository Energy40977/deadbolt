use std::collections::BTreeSet;

use crate::model::{Category, Evidence, Finding, Origin, Severity};

/// A named attack path built from findings that are individually survivable.
///
/// Three medium findings in a report read as three tickets for three sprints.
/// The same three, when one enables the next, are a single critical path that
/// somebody can walk end to end today. Nothing else in the tool joins them up:
/// each lens sees its own slice, each rule sees its own line.
struct ChainRule {
    id: &'static str,
    title: &'static str,
    severity: Severity,
    impact: &'static str,
    remediation: &'static str,
    /// Every group must be present for the chain to exist. A group matches when
    /// any of its predicates matches a finding.
    links: &'static [&'static [Link]],
}

/// One condition against a finding.
#[derive(Clone, Copy)]
enum Link {
    Rule(&'static str),
    RulePrefix(&'static str),
    Cat(Category),
    /// Category plus a minimum severity, for "a serious one of these".
    CatAtLeast(Category, Severity),
}

impl Link {
    fn matches(self, finding: &Finding) -> bool {
        match self {
            Link::Rule(id) => finding.rule == id,
            Link::RulePrefix(prefix) => finding.rule.starts_with(prefix),
            Link::Cat(category) => finding.category == category,
            Link::CatAtLeast(category, severity) => {
                finding.category == category && finding.severity <= severity
            }
        }
    }
}

const CHAINS: &[ChainRule] = &[
    ChainRule {
        id: "DB-CHAIN-001",
        title:
            "Mass Data Extraction Path — Guessable Identifiers, No Ownership Check, No Rate Limit",
        severity: Severity::Critical,
        impact: "Each part is survivable on its own. Together they are a script: enumerate the \
identifiers, request every record, and nothing stops the volume. The result is the whole table \
in someone else's hands, and because reads are not audited there is no trace of it afterwards.",
        remediation:
            "Close the ownership check first — it is the one control that makes the other \
two irrelevant. Then add rate limiting per account rather than per IP, and log bulk reads with \
the caller and the row count.",
        links: &[
            &[
                Link::Rule("DB-AUZ-002"),
                Link::Rule("AI-authz"),
                Link::Cat(Category::Authorization),
            ],
            &[Link::Rule("DB-REPO-031"), Link::Rule("DB-CFG-003")],
        ],
    },
    ChainRule {
        id: "DB-CHAIN-002",
        title: "Unauthenticated State Change — Open Endpoint Reaching A Write Or Payment Path",
        severity: Severity::Critical,
        impact:
            "An endpoint with no authentication requirement sits in front of an operation that \
changes state. An anonymous caller can trigger it, and because failures are swallowed the \
resulting inconsistency surfaces later as a data problem rather than as a security incident.",
        remediation:
            "Apply deny-by-default at the router, then make the write path itself require \
an authenticated principal so a future route cannot re-open the same hole.",
        links: &[
            &[
                Link::Rule("DB-AUN-001"),
                Link::Cat(Category::Authentication),
            ],
            &[
                Link::Cat(Category::Database),
                Link::Cat(Category::ErrorHandling),
            ],
        ],
    },
    ChainRule {
        id: "DB-CHAIN-003",
        title: "Session Theft Path — XSS Reaching A Token In Readable Storage",
        severity: Severity::Critical,
        impact: "XSS on its own runs script in a browser. With the session token in storage that \
script can read, script running once means every session it can reach is taken over, and the \
theft is indistinguishable from normal use in the logs.",
        remediation: "Move the token into an httpOnly cookie so script cannot read it — that \
breaks the chain even while the XSS is still being fixed. Then fix the injection point and add \
a Content-Security-Policy.",
        links: &[
            &[Link::Rule("DB-INJ-005"), Link::Rule("AI-frontend")],
            &[Link::Rule("DB-PRV-002"), Link::Cat(Category::Frontend)],
        ],
    },
    ChainRule {
        id: "DB-CHAIN-004",
        title: "Credential Compromise Path — Weak Password Storage Plus An Exposed Database",
        severity: Severity::Critical,
        impact: "A database reachable from outside is one brute-forced password away from being \
read, and once read, password hashes that were built with a fast function fall within hours. \
Users are then exposed on every other service where they reused that password.",
        remediation: "Take the database off the public interface first, since that is a \
configuration change rather than a migration. Then move password storage to Argon2id and rehash \
on next login.",
        links: &[
            &[Link::Rule("DB-CRY-004"), Link::Rule("DB-REPO-032")],
            &[Link::Rule("DB-INF-002"), Link::Rule("DB-INF-003")],
        ],
    },
    ChainRule {
        id: "DB-CHAIN-005",
        title: "Silent Data Leak Path — Sensitive Data Reaching Logs That Ship Outside",
        severity: Severity::High,
        impact: "Personal data enters the log stream, and the log stream is shipped to a \
third-party service. That combination is a transfer of personal data to another processor, made \
without a legal basis, disclosure or consent — and it continues every day until the field is \
masked.",
        remediation: "Install a masking filter at the logging layer, not at the call sites: one \
central filter survives the next developer who logs an object. Then document what the telemetry \
component receives.",
        links: &[
            &[Link::Rule("DB-DAT-001"), Link::Rule("AI-data")],
            &[Link::Rule("DB-PRV-001"), Link::RulePrefix("DB-DEP-PRIVACY")],
        ],
    },
    ChainRule {
        id: "DB-CHAIN-006",
        title: "Irreversible Release Path — Breaking Schema Change With No Kill Switch",
        severity: Severity::Critical,
        impact: "A single-step schema change breaks the clients already on user devices, and \
without a server-controlled switch there is no way to stop the damage: a mobile release cannot \
be rolled back, so the breakage lasts until a new build is approved and installed.",
        remediation: "Split the migration into expand and contract across two releases, and add a \
server-side flag plus `min_supported_version` before the next schema change ships.",
        links: &[
            &[
                Link::Rule("DB-MIG-002"),
                Link::CatAtLeast(Category::ApiContract, Severity::High),
            ],
            &[Link::Rule("DB-REPO-042"), Link::Rule("DB-REPO-050")],
        ],
    },
];

/// Description of one chain, for `deadbolt explain DB-CHAIN-00x`.
///
/// The HTML report tells the reader to run that command, so every rule id it prints
/// has to be explainable — including the derived ones.
pub struct ChainInfo {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub impact: &'static str,
    pub remediation: &'static str,
    /// One line per link, listing what satisfies it.
    pub links: Vec<String>,
}

pub fn describe(id: &str) -> Option<ChainInfo> {
    CHAINS
        .iter()
        .find(|chain| chain.id == id)
        .map(|chain| ChainInfo {
            id: chain.id,
            title: chain.title,
            severity: chain.severity,
            impact: chain.impact,
            remediation: chain.remediation,
            links: chain
                .links
                .iter()
                .map(|group| {
                    group
                        .iter()
                        .map(|link| match link {
                            Link::Rule(id) => (*id).to_string(),
                            Link::RulePrefix(prefix) => format!("{prefix}*"),
                            Link::Cat(category) => format!("any {} finding", category.label()),
                            Link::CatAtLeast(category, severity) => {
                                format!(
                                    "{} finding at {} or worse",
                                    category.label(),
                                    severity.label()
                                )
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(" or ")
                })
                .collect(),
        })
}

pub fn all_ids() -> Vec<&'static str> {
    CHAINS.iter().map(|chain| chain.id).collect()
}

/// Builds chain findings from the report's own findings.
///
/// A chain is reported only when every link is present, and it carries the
/// locations of its members as evidence so the reader can walk the path.
pub fn correlate(findings: &[Finding]) -> Vec<Finding> {
    // Member selection must not depend on the order findings arrived in. It used to
    // take the first match, so a chain built from raw scan output cited a different
    // member than one built after the full pipeline — different evidence, different
    // fingerprint, and a chain the baseline could never accept. Severity first, then
    // location, gives one answer for a given set of findings.
    let mut candidates: Vec<&Finding> = findings
        .iter()
        .filter(|finding| finding.origin != Origin::Compliance)
        .collect();
    candidates.sort_by(|a, b| {
        let location = |finding: &Finding| {
            finding
                .evidence
                .first()
                .map(|evidence| (evidence.file.clone(), evidence.line.unwrap_or(0)))
                .unwrap_or_default()
        };
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.rule.cmp(&b.rule))
            .then_with(|| location(a).cmp(&location(b)))
    });

    CHAINS
        .iter()
        .filter_map(|chain| {
            let mut members: Vec<&Finding> = Vec::new();

            for group in chain.links {
                let hit = candidates
                    .iter()
                    .copied()
                    .find(|finding| group.iter().any(|link| link.matches(finding)))?;
                members.push(hit);
            }

            let rules: BTreeSet<&str> = members.iter().map(|f| f.rule.as_str()).collect();
            if rules.len() < chain.links.len() {
                // The same finding satisfied two groups; that is one defect, not a chain.
                return None;
            }

            let description = format!(
                "{} findings combine into one reachable path: {}",
                members.len(),
                members
                    .iter()
                    .map(|finding| format!("{} ({})", finding.title, finding.rule))
                    .collect::<Vec<_>>()
                    .join(" -> ")
            );

            let mut builder = Finding::builder(chain.id, Category::Authorization, chain.severity)
                .origin(Origin::Chain)
                .title(chain.title)
                .description(description)
                .impact(chain.impact)
                .remediation(chain.remediation);

            for member in &members {
                let location = member
                    .evidence
                    .first()
                    .map(|evidence| evidence.location())
                    .unwrap_or_else(|| "<project>".to_string());
                let (file, line) = split_location(&location);
                builder = builder.evidence(
                    Evidence::new(file, line, String::new())
                        .with_note(format!("{} — {}", member.rule, member.title)),
                );
            }

            Some(builder.build())
        })
        .collect()
}

fn split_location(location: &str) -> (String, Option<u32>) {
    match location.rsplit_once(':') {
        Some((file, line)) => match line.parse::<u32>() {
            Ok(number) => (file.to_string(), Some(number)),
            Err(_) => (location.to_string(), None),
        },
        None => (location.to_string(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule: &str, category: Category, severity: Severity, file: &str) -> Finding {
        Finding::builder(rule, category, severity)
            .title(format!("{rule} title"))
            .evidence(Evidence::new(file, Some(10), ""))
            .build()
    }

    #[test]
    fn a_complete_chain_is_reported_once() {
        let findings = vec![
            finding(
                "DB-AUZ-002",
                Category::Authorization,
                Severity::Medium,
                "a.py",
            ),
            finding(
                "DB-REPO-031",
                Category::Configuration,
                Severity::High,
                "b.py",
            ),
        ];
        let chains = correlate(&findings);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].rule, "DB-CHAIN-001");
        assert_eq!(chains[0].severity, Severity::Critical);
        assert_eq!(chains[0].evidence.len(), 2, "every member is cited");
    }

    #[test]
    fn the_same_findings_always_pick_the_same_members() {
        let a = finding(
            "DB-AUZ-002",
            Category::Authorization,
            Severity::Medium,
            "z.py",
        );
        let b = finding(
            "DB-AUZ-002",
            Category::Authorization,
            Severity::Medium,
            "a.py",
        );
        let c = finding(
            "DB-REPO-031",
            Category::Configuration,
            Severity::High,
            "b.py",
        );

        let one = correlate(&[a.clone(), b.clone(), c.clone()]);
        let two = correlate(&[c.clone(), b.clone(), a.clone()]);
        let three = correlate(&[b.clone(), c.clone(), a.clone()]);

        assert_eq!(one.len(), 1);
        let cited = |list: &[Finding]| {
            list[0]
                .evidence
                .iter()
                .map(|e| e.file.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(cited(&one), cited(&two));
        assert_eq!(cited(&one), cited(&three));
        assert_eq!(
            one[0].fingerprint(),
            two[0].fingerprint(),
            "a chain the baseline accepted must keep its fingerprint"
        );
    }

    #[test]
    fn an_incomplete_chain_is_not_reported() {
        let findings = vec![finding(
            "DB-AUZ-002",
            Category::Authorization,
            Severity::Medium,
            "a.py",
        )];
        assert!(correlate(&findings).is_empty());
    }

    #[test]
    fn one_finding_cannot_satisfy_two_links() {
        // DB-CFG-003 is in the second group only, so on its own it forms nothing.
        let findings = vec![finding(
            "DB-CFG-003",
            Category::Configuration,
            Severity::Medium,
            "a.py",
        )];
        assert!(correlate(&findings).is_empty());
    }

    #[test]
    fn chains_are_excluded_from_the_score() {
        let chain = correlate(&[
            finding(
                "DB-AUZ-002",
                Category::Authorization,
                Severity::Medium,
                "a.py",
            ),
            finding(
                "DB-REPO-031",
                Category::Configuration,
                Severity::High,
                "b.py",
            ),
        ]);
        assert_eq!(chain[0].origin, Origin::Chain);
    }

    #[test]
    fn locations_split_into_file_and_line() {
        assert_eq!(
            split_location("apps/web/a.ts:42"),
            ("apps/web/a.ts".to_string(), Some(42))
        );
        assert_eq!(split_location("<project>"), ("<project>".to_string(), None));
    }
}
