use std::collections::BTreeMap;

use crate::model::{AuditReport, Category, Confidence, ControlStatus, Finding, Origin, Severity};

pub fn render_with_trend(report: &AuditReport, trend_svg: &str) -> String {
    let mut main = String::new();

    main.push_str(&header(report));
    main.push_str(&scoreboard(report));
    main.push_str(&action_plan(report));
    if !trend_svg.is_empty() {
        main.push_str(&trend_section(trend_svg));
    }
    main.push_str(&stack(report));
    if !report.packs.is_empty() {
        main.push_str(&compliance(report));
    }
    main.push_str(&findings(report));
    if !report.packages.is_empty() {
        main.push_str(&dependencies(report));
    }
    main.push_str(&glossary(report));
    main.push_str(&footer(report));

    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<title>deadbolt · {title}</title>\n<link rel=\"icon\" href=\"data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%224%202%2056%2052%22%20width%3D%2232%22%20height%3D%2232%22%20fill%3D%22none%22%20stroke%3D%22%2300ff9c%22%20stroke-width%3D%222.6%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%3E%20%3Crect%20x%3D%224%22%20y%3D%222%22%20width%3D%2256%22%20height%3D%2252%22%20fill%3D%22%2304070a%22%2F%3E%20%3C%21--%20cranium%2C%20pinched%20at%20the%20temples%2C%20tapering%20to%20the%20jaw%20--%3E%20%3Cpath%20d%3D%22M32%206.5c-11%200-18.8%207.6-18.8%2018v6.2c0%202.3%201.1%204.4%203%205.6l2.3%201.4c.7.4%201.1%201.2%201.1%202v3.1%20c0%203%202.4%205.4%205.4%205.4h13.9c3%200%205.4-2.4%205.4-5.4v-3.1c0-.8.4-1.6%201.1-2l2.3-1.4%20c1.9-1.2%203-3.3%203-5.6V24.5c0-10.4-7.8-18-18.7-18z%22%2F%3E%20%3C%21--%20circuit%20on%20the%20skullcap%20--%3E%20%3Cg%20stroke-width%3D%221.15%22%20opacity%3D%220.9%22%3E%20%3Cpath%20d%3D%22M19.5%2014.5h8.5v-3.5%22%2F%3E%20%3Cpath%20d%3D%22M44.5%2014.5H36v-3.5%22%2F%3E%20%3Ccircle%20cx%3D%2228%22%20cy%3D%2210.6%22%20r%3D%221.2%22%20fill%3D%22%2300ff9c%22%20stroke%3D%22none%22%2F%3E%20%3Ccircle%20cx%3D%2236%22%20cy%3D%2210.6%22%20r%3D%221.2%22%20fill%3D%22%2300ff9c%22%20stroke%3D%22none%22%2F%3E%20%3C%2Fg%3E%20%3C%21--%20deadbolt%20keyhole%20in%20the%20frontal%20bone%20--%3E%20%3Ccircle%20cx%3D%2232%22%20cy%3D%2217.6%22%20r%3D%222.5%22%2F%3E%20%3Cpath%20d%3D%22M30.6%2021.4h2.8l-.7%203.1h-1.4z%22%20fill%3D%22%2300ff9c%22%20stroke%3D%22none%22%2F%3E%20%3C%21--%20eye%20sockets%3A%20hex%20bays%20angled%20inward%20--%3E%20%3Cpath%20d%3D%22M17.6%2025.6l3.4-2.6%207.6%201.4%201.1%205.3-3.4%203.4-7.6-1.6z%22%20fill%3D%22%2300ff9c%22%20stroke%3D%22none%22%2F%3E%20%3Cpath%20d%3D%22M46.4%2025.6L43%2023l-7.6%201.4-1.1%205.3%203.4%203.4%207.6-1.6z%22%20fill%3D%22%2300ff9c%22%20stroke%3D%22none%22%2F%3E%20%3Cg%20stroke%3D%22%2304070a%22%20stroke-width%3D%221%22%20opacity%3D%220.65%22%3E%20%3Cpath%20d%3D%22M19.4%2028.6l8.2%201.4M44.6%2028.6l-8.2%201.4%22%2F%3E%20%3C%2Fg%3E%20%3C%21--%20nasal%20aperture%20--%3E%20%3Cpath%20d%3D%22M32%2034.8l-2.4%204.8h4.8z%22%20fill%3D%22%2300ff9c%22%20stroke%3D%22none%22%2F%3E%20%3C%21--%20upper%20jaw%20line%20%2B%20teeth%20as%20pins%20--%3E%20%3Cpath%20d%3D%22M23.5%2043.5h17%22%2F%3E%20%3Cg%20stroke-width%3D%221.5%22%3E%20%3Cpath%20d%3D%22M26.7%2043.5v4.6M30.2%2043.5v4.6M33.8%2043.5v4.6M37.3%2043.5v4.6%22%2F%3E%20%3C%2Fg%3E%20%3C%2Fsvg%3E\">\n<style>{CSS}</style>\n</head>\n<body>\n\
<div class=\"grid-bg\" aria-hidden=\"true\"></div>\n<div class=\"app\">\n{side}\n\
<main>{main}</main>\n</div>\n<script>{SCRIPT}</script>\n</body>\n</html>\n",
        title = escape(&report.meta.project),
        side = sidebar(report),
    )
}

/// Fixed navigation rail. A report this long is unusable without one, and it
/// keeps the score visible while the reader is deep in the findings list.
fn sidebar(report: &AuditReport) -> String {
    let count = |severity: Severity| {
        report
            .findings
            .iter()
            .filter(|finding| finding.severity == severity)
            .count()
    };

    let mut links = vec![
        ("#overview", "Overview".to_string()),
        ("#plan", "Where To Start".to_string()),
        ("#stack", "Project Stack".to_string()),
    ];
    if !report.packs.is_empty() {
        links.push(("#compliance", "Standards Compliance".to_string()));
    }
    links.push(("#findings", format!("Findings ({})", report.findings.len())));
    if !report.packages.is_empty() {
        links.push((
            "#dependencies",
            format!("Dependencies ({})", report.packages.len()),
        ));
    }
    links.push(("#glossary", "Glossary".to_string()));

    let nav: String = links
        .iter()
        .map(|(href, label)| format!(r#"<a href="{href}">{label}</a>"#))
        .collect();

    let pills: String = Severity::all()
        .into_iter()
        .filter(|severity| count(*severity) > 0)
        .map(|severity| {
            format!(
                r#"<span class="mini {class}"><b>{count}</b> {label}</span>"#,
                class = severity_class(severity),
                count = count(severity),
                label = severity_word(severity),
            )
        })
        .collect();

    format!(
        r#"<aside class="side">
  <div class="side-brand">{shield} DEADBOLT</div>
  <div class="side-score {class}">
    <span class="side-num" data-count="{score:.1}">0.0</span>
    <span class="side-grade">{grade}</span>
  </div>
  <div class="side-pills">{pills}</div>
  <nav>{nav}</nav>
  <p class="side-foot">{project}<br>{started}</p>
</aside>"#,
        shield = mark("brand-ico"),
        class = match report.score.overall {
            s if s >= 75.0 => "good",
            s if s >= 50.0 => "fair",
            _ => "bad",
        },
        score = report.score.overall,
        grade = escape(&report.score.grade),
        project = escape(&report.meta.project),
        started = escape(report.meta.started_at.get(..10).unwrap_or("")),
    )
}

fn escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn severity_class(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "crit",
        Severity::High => "high",
        Severity::Medium => "med",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

/// Plain-language severity. "CRITICAL" says nothing about what to do next;
/// "must be fixed now" does.
fn severity_action(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "Fix Now",
        Severity::High => "Fix This Week",
        Severity::Medium => "Schedule It",
        Severity::Low => "When There Is Time",
        Severity::Info => "Information Only",
    }
}

fn icon(category: Category) -> &'static str {
    match category {
        Category::Secrets => {
            r#"<path d="M12 2a5 5 0 0 1 5 5v3h1a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2h1V7a5 5 0 0 1 5-5zm0 2a3 3 0 0 0-3 3v3h6V7a3 3 0 0 0-3-3zm0 9a2 2 0 0 0-1 3.7V19h2v-2.3A2 2 0 0 0 12 13z"/>"#
        }
        Category::Cryptography => {
            r#"<path d="M12 1 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5l-8-4zm0 2.2 6 3V11c0 4-2.5 7.9-6 9-3.5-1.1-6-5-6-9V6.2l6-3zM11 8h2v4h-2V8zm0 5h2v2h-2v-2z"/>"#
        }
        Category::Authentication => {
            r#"<path d="M12 2a5 5 0 1 1 0 10 5 5 0 0 1 0-10zm0 2a3 3 0 1 0 0 6 3 3 0 0 0 0-6zm-8 18v-1c0-3.3 3.6-6 8-6s8 2.7 8 6v1H4z"/>"#
        }
        Category::Authorization => {
            r#"<path d="M12 1 3 5v6c0 5.5 3.8 10.4 9 12 5.2-1.6 9-6.5 9-12V5l-9-4zm-1 6h2v5h-2V7zm-3.5 8.5 3.5-2 3.5 2-3.5 2-3.5-2z"/>"#
        }
        Category::Injection => {
            r#"<path d="M3 4h18v2H3V4zm2 4h14l-1.5 12h-11L5 8zm4 2 .8 8h1.4L10.4 10H9zm4 0-.8 8h1.4l.8-8H13z"/>"#
        }
        Category::DataProtection => {
            r#"<path d="M12 2c4.4 0 8 1.3 8 3v14c0 1.7-3.6 3-8 3s-8-1.3-8-3V5c0-1.7 3.6-3 8-3zm0 2c-3.6 0-6 .9-6 1s2.4 1 6 1 6-.9 6-1-2.4-1-6-1zm6 4.6C16.5 9.5 14.4 10 12 10s-4.5-.5-6-1.4V12c0 .1 2.4 1 6 1s6-.9 6-1V8.6z"/>"#
        }
        Category::Privacy => {
            r#"<path d="M12 4.5C7 4.5 2.7 7.6 1 12c1.7 4.4 6 7.5 11 7.5s9.3-3.1 11-7.5c-1.7-4.4-6-7.5-11-7.5zm0 12.5a5 5 0 1 1 0-10 5 5 0 0 1 0 10zm0-8a3 3 0 1 0 0 6 3 3 0 0 0 0-6z"/>"#
        }
        Category::ErrorHandling => {
            r#"<path d="M12 2 1 21h22L12 2zm0 4.5 7.5 12.5h-15L12 6.5zM11 10h2v5h-2v-5zm0 6h2v2h-2v-2z"/>"#
        }
        Category::SupplyChain => {
            r#"<path d="M10 3h4v3h4a2 2 0 0 1 2 2v4h-3v-2h-3v3h-4v-3H7v2H4V8a2 2 0 0 1 2-2h4V3zm-6 12h4v6H4v-6zm6 0h4v6h-4v-6zm6 0h4v6h-4v-6z"/>"#
        }
        Category::Infrastructure => {
            r#"<path d="M4 4h16v5H4V4zm0 7h16v5H4v-5zm0 7h16v3H4v-3zM6 6v1h2V6H6zm0 7v1h2v-1H6z"/>"#
        }
        Category::Frontend => {
            r#"<path d="M3 4h18a1 1 0 0 1 1 1v11a1 1 0 0 1-1 1h-7v2h3v2H7v-2h3v-2H3a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1zm1 2v9h16V6H4z"/>"#
        }
        Category::Mobile => {
            r#"<path d="M7 2h10a2 2 0 0 1 2 2v16a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2zm0 2v14h10V4H7zm4 15h2v1h-2v-1z"/>"#
        }
        Category::Database => {
            r#"<path d="M12 2c4.4 0 8 1.3 8 3s-3.6 3-8 3-8-1.3-8-3 3.6-3 8-3zm8 6.5V12c0 1.7-3.6 3-8 3s-8-1.3-8-3V8.5c1.8 1.4 5 2 8 2s6.2-.6 8-2zm0 6V18c0 1.7-3.6 3-8 3s-8-1.3-8-3v-3.5c1.8 1.4 5 2 8 2s6.2-.6 8-2z"/>"#
        }
        Category::ApiContract => {
            r#"<path d="M8.7 3.3 10 4.7 5.4 9.3a4 4 0 0 0 5.7 5.7l4.6-4.6 1.4 1.4-4.6 4.6a6 6 0 0 1-8.5-8.5l4.7-4.6zM15.3 20.7 14 19.3l4.6-4.6a4 4 0 0 0-5.7-5.7L8.3 13.6 6.9 12.2l4.6-4.6a6 6 0 0 1 8.5 8.5l-4.7 4.6z"/>"#
        }
        Category::Configuration => {
            r#"<path d="M12 8a4 4 0 1 1 0 8 4 4 0 0 1 0-8zm0 2a2 2 0 1 0 0 4 2 2 0 0 0 0-4zm-1-9h2l.4 2.6 2.3 1 2.2-1.5 1.4 1.4-1.5 2.2 1 2.3L21 11v2l-2.6.4-1 2.3 1.5 2.2-1.4 1.4-2.2-1.5-2.3 1L13 23h-2l-.4-2.6-2.3-1L6.1 21l-1.4-1.4 1.5-2.2-1-2.3L3 13v-2l2.6-.4 1-2.3L5.1 6.1 6.5 4.7l2.2 1.5 2.3-1L11 1z"/>"#
        }
        Category::Compliance => {
            r#"<path d="M9 2h6a2 2 0 0 1 2 2v1h1a2 2 0 0 1 2 2v13a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h1V4a2 2 0 0 1 2-2zm0 2v1h6V4H9zm-1.6 9.4 1.2-1.2 1.9 1.9 4-4 1.2 1.2-5.2 5.2-3.1-3.1z"/>"#
        }
    }
}

/// The product mark: a skull whose cranium is a circuit board and whose frontal
/// bone carries a keyhole. Simplified from `assets/deadbolt-mark.svg` — the board
/// traces and target brackets of the full mark turn to mud below 20 px.
const MARK: &str = r##"<!-- cranium, pinched at the temples, tapering to the jaw --> <path d="M32 6.5c-11 0-18.8 7.6-18.8 18v6.2c0 2.3 1.1 4.4 3 5.6l2.3 1.4c.7.4 1.1 1.2 1.1 2v3.1 c0 3 2.4 5.4 5.4 5.4h13.9c3 0 5.4-2.4 5.4-5.4v-3.1c0-.8.4-1.6 1.1-2l2.3-1.4 c1.9-1.2 3-3.3 3-5.6V24.5c0-10.4-7.8-18-18.7-18z"/> <!-- circuit on the skullcap --> <g stroke-width="1.15" opacity="0.9"> <path d="M19.5 14.5h8.5v-3.5"/> <path d="M44.5 14.5H36v-3.5"/> <circle cx="28" cy="10.6" r="1.2" fill="currentColor" stroke="none"/> <circle cx="36" cy="10.6" r="1.2" fill="currentColor" stroke="none"/> </g> <!-- deadbolt keyhole in the frontal bone --> <circle cx="32" cy="17.6" r="2.5"/> <path d="M30.6 21.4h2.8l-.7 3.1h-1.4z" fill="currentColor" stroke="none"/> <!-- eye sockets: hex bays angled inward --> <path d="M17.6 25.6l3.4-2.6 7.6 1.4 1.1 5.3-3.4 3.4-7.6-1.6z" fill="currentColor" stroke="none"/> <path d="M46.4 25.6L43 23l-7.6 1.4-1.1 5.3 3.4 3.4 7.6-1.6z" fill="currentColor" stroke="none"/> <g stroke="#04070a" stroke-width="1" opacity="0.65"> <path d="M19.4 28.6l8.2 1.4M44.6 28.6l-8.2 1.4"/> </g> <!-- nasal aperture --> <path d="M32 34.8l-2.4 4.8h4.8z" fill="currentColor" stroke="none"/> <!-- upper jaw line + teeth as pins --> <path d="M23.5 43.5h17"/> <g stroke-width="1.5"> <path d="M26.7 43.5v4.6M30.2 43.5v4.6M33.8 43.5v4.6M37.3 43.5v4.6"/> </g>"##;
const ICON_ARROW: &str = r#"<path d="M4 11h11.2l-4.6-4.6L12 5l7 7-7 7-1.4-1.4 4.6-4.6H4z"/>"#;
const ICON_TARGET: &str = r#"<path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm0 2a8 8 0 1 1 0 16 8 8 0 0 1 0-16zm0 3a5 5 0 1 0 0 10 5 5 0 0 0 0-10zm0 3a2 2 0 1 1 0 4 2 2 0 0 1 0-4z"/>"#;

/// The full mark, with the board traces and target brackets that the simplified
/// version drops. Only used at logo size in the header, where the detail reads.
const MARK_FULL: &str = r##"  <!-- board traces feeding the skull -->
  <g stroke-width="1.3" opacity="0.8">
    <path d="M2 22h5M2 22v-7h7"/>
    <path d="M62 22h-5M62 22v-7h-7"/>
    <path d="M4 45h6M60 45h-6"/>
    <circle cx="9" cy="15" r="1.5" fill="currentColor" stroke="none"/>
    <circle cx="55" cy="15" r="1.5" fill="currentColor" stroke="none"/>
    <circle cx="4" cy="45" r="1.5" fill="currentColor" stroke="none"/>
    <circle cx="60" cy="45" r="1.5" fill="currentColor" stroke="none"/>
  </g>
  <!-- cranium, pinched at the temples, tapering to the jaw -->
  <path d="M32 6.5c-11 0-18.8 7.6-18.8 18v6.2c0 2.3 1.1 4.4 3 5.6l2.3 1.4c.7.4 1.1 1.2 1.1 2v3.1
           c0 3 2.4 5.4 5.4 5.4h13.9c3 0 5.4-2.4 5.4-5.4v-3.1c0-.8.4-1.6 1.1-2l2.3-1.4
           c1.9-1.2 3-3.3 3-5.6V24.5c0-10.4-7.8-18-18.7-18z"/>
  <!-- circuit on the skullcap -->
  <g stroke-width="1.15" opacity="0.9">
    <path d="M19.5 14.5h8.5v-3.5"/>
    <path d="M44.5 14.5H36v-3.5"/>
    <circle cx="28" cy="10.6" r="1.2" fill="currentColor" stroke="none"/>
    <circle cx="36" cy="10.6" r="1.2" fill="currentColor" stroke="none"/>
  </g>
  <!-- deadbolt keyhole in the frontal bone -->
  <circle cx="32" cy="17.6" r="2.5"/>
  <path d="M30.6 21.4h2.8l-.7 3.1h-1.4z" fill="currentColor" stroke="none"/>
  <!-- eye sockets: hex bays angled inward -->
  <path d="M17.6 25.6l3.4-2.6 7.6 1.4 1.1 5.3-3.4 3.4-7.6-1.6z" fill="currentColor" stroke="none"/>
  <path d="M46.4 25.6L43 23l-7.6 1.4-1.1 5.3 3.4 3.4 7.6-1.6z" fill="currentColor" stroke="none"/>
  <g stroke="#04070a" stroke-width="1" opacity="0.65">
    <path d="M19.4 28.6l8.2 1.4M44.6 28.6l-8.2 1.4"/>
  </g>
  <!-- nasal aperture -->
  <path d="M32 34.8l-2.4 4.8h4.8z" fill="currentColor" stroke="none"/>
  <!-- upper jaw line + teeth as pins -->
  <path d="M23.5 43.5h17"/>
  <g stroke-width="1.5">
    <path d="M26.7 43.5v4.6M30.2 43.5v4.6M33.8 43.5v4.6M37.3 43.5v4.6"/>
  </g>
  <!-- traces leaving the mandible -->
  <g stroke-width="1.3" opacity="0.8">
    <path d="M23.6 48.6l-4 4.4h-5.2"/>
    <path d="M40.4 48.6l4 4.4h5.2"/>
    <circle cx="14.4" cy="53" r="1.5" fill="currentColor" stroke="none"/>
    <circle cx="49.6" cy="53" r="1.5" fill="currentColor" stroke="none"/>
  </g>
  <!-- temple vias -->
  <g stroke-width="1.15" opacity="0.85">
    <path d="M13.2 33h-2.6M50.8 33h2.6"/>
    <circle cx="10.6" cy="33" r="1.2" fill="currentColor" stroke="none"/>
    <circle cx="53.4" cy="33" r="1.2" fill="currentColor" stroke="none"/>
  </g>
  <!-- target brackets -->
  <g stroke-width="1.6" opacity="0.65">
    <path d="M2 9V2h7M55 2h7v7M62 55v7h-7M9 62H2v-7"/>
  </g>"##;

/// The mark has its own viewBox, so it cannot go through `svg()`.
fn logo() -> String {
    format!(
        r#"<svg class="logo-mark" viewBox="0 0 64 64" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" role="img" aria-label="deadbolt"><title>deadbolt</title>{MARK_FULL}</svg>"#
    )
}

fn mark(class: &str) -> String {
    format!(
        r#"<svg class="ico {class}" viewBox="4 2 56 52" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{MARK}</svg>"#
    )
}

fn svg(path: &str, class: &str) -> String {
    format!(r#"<svg class="ico {class}" viewBox="0 0 24 24" aria-hidden="true">{path}</svg>"#)
}

fn header(report: &AuditReport) -> String {
    let command = match report.meta.mode.as_str() {
        "diff" => "deadbolt diff",
        "scan" => "deadbolt scan .",
        "deps" => "deadbolt deps .",
        "watch" => "deadbolt watch .",
        _ => "deadbolt audit .",
    };

    format!(
        r#"<header>
  <div class="term" role="presentation">
    <span class="dots"><i></i><i></i><i></i></span>
    <code>$ {command}</code><span class="caret"></span>
  </div>
  <div class="lockup">
    {logo}
    <div class="lockup-text">
      <div class="wordmark">DEADBOLT<span class="ver">v{version}</span></div>
      <div class="tagline">Security Audit For Any Codebase</div>
    </div>
  </div>
  <h1>{project}</h1>
  <p class="sub">{target}</p>
  <p class="sub when">{started} · {duration} ms{cost}</p>
</header>
"#,
        logo = logo(),
        version = escape(&report.meta.version),
        project = escape(&report.meta.project),
        target = escape(&report.meta.target),
        started = escape(report.meta.started_at.get(..19).unwrap_or("")),
        duration = report.meta.duration_ms,
        cost = if report.meta.ai_cost_usd > 0.0 {
            format!(" · AI Cost ${:.2}", report.meta.ai_cost_usd)
        } else {
            String::new()
        },
    )
}

/// Circumference for r = 54.
const RING_C: f64 = 339.29;
/// Circumference for r = 40 (donut).
const DONUT_C: f64 = 251.33;

fn score_ring(report: &AuditReport) -> String {
    let offset = RING_C * (1.0 - report.score.overall / 100.0);
    let class = match report.score.overall {
        s if s >= 75.0 => "good",
        s if s >= 50.0 => "fair",
        _ => "bad",
    };

    // Ticks every five points, longer every twenty-five: the reader can see where
    // the value sits on the scale without reading the number twice.
    let ticks: String = (0..20)
        .map(|step| {
            let long = step % 5 == 0;
            let angle = -90.0 + (step as f64) * 18.0;
            let (inner, outer) = if long { (44.0, 51.0) } else { (47.0, 51.0) };
            let radians = angle.to_radians();
            format!(
                r#"<line x1="{x1:.2}" y1="{y1:.2}" x2="{x2:.2}" y2="{y2:.2}" class="tick{}"/>"#,
                if long { " long" } else { "" },
                x1 = 64.0 + inner * radians.cos(),
                y1 = 64.0 + inner * radians.sin(),
                x2 = 64.0 + outer * radians.cos(),
                y2 = 64.0 + outer * radians.sin(),
            )
        })
        .collect();

    // The two thresholds that change the verdict, marked on the dial itself.
    let markers: String = [50.0_f64, 75.0]
        .iter()
        .map(|value| {
            let radians = (-90.0 + value * 3.6).to_radians();
            format!(
                r#"<line x1="{x1:.2}" y1="{y1:.2}" x2="{x2:.2}" y2="{y2:.2}" class="threshold"/>"#,
                x1 = 64.0 + 41.0 * radians.cos(),
                y1 = 64.0 + 41.0 * radians.sin(),
                x2 = 64.0 + 58.0 * radians.cos(),
                y2 = 64.0 + 58.0 * radians.sin(),
            )
        })
        .collect();

    format!(
        r#"<div class="ring-wrap {class}">
  <svg viewBox="0 0 128 128" class="ring">
    <g class="ticks">{ticks}{markers}</g>
    <circle cx="64" cy="64" r="54" class="ring-track"/>
    <circle cx="64" cy="64" r="54" class="ring-fill"
            style="stroke-dasharray:{RING_C:.2};stroke-dashoffset:{offset:.2}"/>
  </svg>
  <div class="ring-text">
    <div class="ring-num" data-count="{score:.1}">0.0</div>
    <div class="ring-of">OF 100</div>
    <div class="ring-grade">{grade}</div>
  </div>
</div>"#,
        score = report.score.overall,
        grade = escape(&report.score.grade),
    )
}

/// A strip of single-number tiles.
///
/// The ring answers "how bad", the donut "how bad in what mix". Neither answers
/// the questions asked next: how dense are the defects, how many actually block a
/// release, how much of the run was AI. Each tile is one number with the unit it
/// is measured in, because a number without a denominator invites the wrong
/// comparison between two repositories of different size.
fn kpi_tiles(report: &AuditReport) -> String {
    let blocking = report
        .findings
        .iter()
        .filter(|finding| finding.severity <= Severity::High)
        .count();
    let kloc = (report.stack.total_lines as f64 / 1000.0).max(0.001);
    let density = report
        .findings
        .iter()
        .filter(|finding| finding.origin != Origin::Compliance)
        .count() as f64
        / kloc;

    let mut tiles: Vec<(String, String, &str)> = vec![
        (
            format!("{blocking}"),
            "Blocking".to_string(),
            if blocking == 0 { "ok" } else { "bad" },
        ),
        (
            format!("{density:.1}"),
            "Per 1000 Lines".to_string(),
            if density < 1.0 { "ok" } else { "warn" },
        ),
        (
            format!("{:.0}k", report.stack.total_lines as f64 / 1000.0),
            "Lines Scanned".to_string(),
            "",
        ),
    ];

    if !report.packages.is_empty() {
        let vulnerable = report
            .packages
            .iter()
            .filter(|audit| !audit.vulnerabilities.is_empty())
            .count();
        tiles.push((
            format!("{vulnerable}/{}", report.packages.len()),
            "Packages With CVEs".to_string(),
            if vulnerable == 0 { "ok" } else { "bad" },
        ));
    }
    if !report.packs.is_empty() {
        let satisfied: usize = report.packs.iter().map(|pack| pack.satisfied).sum();
        let total: usize = report
            .packs
            .iter()
            .map(|pack| pack.satisfied + pack.violated + pack.unknown)
            .sum();
        tiles.push((
            format!("{:.0}%", (satisfied as f64 / total.max(1) as f64) * 100.0),
            "Controls Satisfied".to_string(),
            "",
        ));
    }
    if !report.meta.lenses_run.is_empty() {
        tiles.push((
            format!("{}", report.meta.lenses_run.len()),
            "AI Lenses Run".to_string(),
            "",
        ));
    }
    if report.meta.ai_cost_usd > 0.0 {
        tiles.push((
            format!("${:.2}", report.meta.ai_cost_usd),
            "AI Cost".to_string(),
            "",
        ));
    }
    tiles.push((
        crate::ui::human_duration(report.meta.duration_ms),
        "Duration".to_string(),
        "",
    ));

    let cells: String = tiles
        .iter()
        .map(|(value, label, class)| {
            format!(r#"<div class="kpi {class}"><b>{value}</b><span>{label}</span></div>"#)
        })
        .collect();
    format!(r#"<div class="kpis">{cells}</div>"#)
}

fn severity_donut(report: &AuditReport) -> String {
    let counts: Vec<(Severity, usize)> = Severity::all()
        .into_iter()
        .map(|severity| {
            (
                severity,
                report
                    .findings
                    .iter()
                    .filter(|finding| finding.severity == severity)
                    .count(),
            )
        })
        .filter(|(_, count)| *count > 0)
        .collect();

    let total: usize = counts.iter().map(|(_, count)| count).sum();
    if total == 0 {
        return String::new();
    }

    let mut offset = 0.0_f64;
    let mut segments = String::new();
    let mut legend = String::new();

    for (index, (severity, count)) in counts.iter().enumerate() {
        let length = DONUT_C * (*count as f64 / total as f64);
        segments.push_str(&format!(
            r#"<circle cx="50" cy="50" r="40" class="seg {class}" style="stroke-dasharray:{length:.2} {rest:.2};stroke-dashoffset:{off:.2};animation-delay:{delay}ms"><title>{count} {label} — {share:.0}%</title></circle>"#,
            class = severity_class(*severity),
            rest = DONUT_C - length,
            off = -offset,
            delay = index * 110,
            label = severity_word(*severity),
            share = (*count as f64 / total as f64) * 100.0,
        ));
        legend.push_str(&format!(
            r#"<li class="{class}"><span class="swatch"></span><b>{count}</b>{label}<i>{share:.0}%</i><em>{action}</em></li>"#,
            class = severity_class(*severity),
            label = severity_word(*severity),
            share = (*count as f64 / total as f64) * 100.0,
            action = severity_action(*severity),
        ));
        offset += length;
    }

    format!(
        r#"<div class="donut-wrap">
  <svg viewBox="0 0 100 100" class="donut">{segments}
    <text x="50" y="46" class="donut-num">{total}</text>
    <text x="50" y="57" class="donut-lbl">FINDINGS</text>
    <text x="50" y="65" class="donut-sub">{blocking} BLOCKING</text>
  </svg>
  <ul class="legend">{legend}</ul>
</div>"#,
        blocking = counts
            .iter()
            .filter(|(severity, _)| *severity <= Severity::High)
            .map(|(_, count)| count)
            .sum::<usize>(),
    )
}

/// Display word for the severity, used where a label reads better than a
/// shouted English constant.
fn severity_word(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

fn category_bars(report: &AuditReport) -> String {
    let mut grouped: BTreeMap<Category, (usize, Severity)> = BTreeMap::new();
    for finding in &report.findings {
        let entry = grouped
            .entry(finding.category)
            .or_insert((0, Severity::Info));
        entry.0 += 1;
        if finding.severity < entry.1 {
            entry.1 = finding.severity;
        }
    }

    let mut rows: Vec<(Category, usize, Severity)> = grouped
        .into_iter()
        .map(|(category, (count, worst))| (category, count, worst))
        .collect();
    rows.sort_by_key(|(_, count, _)| std::cmp::Reverse(*count));
    let max = rows.first().map(|(_, count, _)| *count).unwrap_or(1).max(1);
    let total_findings: usize = rows.iter().map(|(_, count, _)| *count).sum();

    let items: String = rows
        .iter()
        .enumerate()
        .map(|(index, (category, count, worst))| {
            format!(
                r#"<li><span class="cat-name">{ico}{label}</span>
<span class="cat-track"><span class="cat-fill {class}" style="--w:{percent:.1}%;animation-delay:{delay}ms"></span></span>
<b>{count}</b><i>{share:.0}%</i></li>"#,
                ico = svg(icon(*category), "cat-ico"),
                label = escape(category.label()),
                class = severity_class(*worst),
                percent = (*count as f64 / max as f64) * 100.0,
                share = (*count as f64 / total_findings.max(1) as f64) * 100.0,
                delay = 60 * index,
            )
        })
        .collect();

    format!(r#"<ul class="cat-list">{items}</ul>"#)
}

fn scoreboard(report: &AuditReport) -> String {
    let verdict = if report.findings.is_empty() {
        "No Problems Were Found In This Run."
    } else {
        match report.score.overall {
            s if s >= 75.0 => "The State Is Good. Scheduling The Remaining Notes Is Enough.",
            s if s >= 50.0 => "The State Is Mixed. Critical And High Findings Need To Be Queued.",
            _ => "The State Is Serious. The Critical Findings Below Should Close Before The Next Release.",
        }
    };

    format!(
        r#"<section class="board" id="overview">
  <h2>{target} Overview</h2>
  <p class="verdict">{verdict}</p>
  {tiles}
  <div class="board-grid">
    {ring}
    {donut}
    <div class="cats">
      <h3>Where The Problems Are</h3>
      {bars}
    </div>
  </div>
</section>
"#,
        target = svg(ICON_TARGET, "h-ico"),
        tiles = kpi_tiles(report),
        ring = score_ring(report),
        donut = severity_donut(report),
        bars = category_bars(report),
    )
}

/// The reader's first question is never "how many findings" but "what do I do
/// on Monday morning". This answers it: the heaviest files, in order.
fn action_plan(report: &AuditReport) -> String {
    let blocking: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.severity <= Severity::High)
        .collect();

    if blocking.is_empty() {
        return "<section id=\"plan\"><h2>Where To Start</h2><p class=\"clean\">Nothing \
Needs Urgent Fixing.</p></section>\n"
            .to_string();
    }

    let mut per_file: BTreeMap<&str, (usize, Severity, &str)> = BTreeMap::new();
    for finding in &blocking {
        let file = finding
            .evidence
            .first()
            .map(|evidence| evidence.file.as_str())
            .unwrap_or("(no file recorded)");
        let entry = per_file
            .entry(file)
            .or_insert((0, Severity::Info, finding.title.as_str()));
        entry.0 += 1;
        if finding.severity < entry.1 {
            entry.1 = finding.severity;
            entry.2 = finding.title.as_str();
        }
    }

    let mut ranked: Vec<(&str, usize, Severity, &str)> = per_file
        .into_iter()
        .map(|(file, (count, worst, title))| (file, count, worst, title))
        .collect();
    ranked.sort_by_key(|(_, count, worst, _)| (*worst as i32, std::cmp::Reverse(*count)));

    let steps: String = ranked
        .iter()
        .take(8)
        .enumerate()
        .map(|(index, (file, count, worst, title))| {
            format!(
                r#"<li style="animation-delay:{delay}ms"><span class="step-no">{no}</span>
<div><code>{file}</code>
<div class="muted">{count} findings · worst: <span class="tag {class}">{severity}</span> {title}</div></div></li>"#,
                delay = index * 90,
                no = index + 1,
                file = escape(file),
                class = severity_class(*worst),
                severity = severity_word(*worst),
                title = escape(title),
            )
        })
        .collect();

    let extra = ranked.len().saturating_sub(8);
    let tail = if extra > 0 {
        format!("<p class=\"muted\">{extra} More Files Follow This List.</p>")
    } else {
        String::new()
    };

    format!(
        r#"<section id="plan">
  <h2>Where To Start</h2>
  <p class="note">Critical and high findings, grouped by file and ordered by severity.
  Fixing one file usually closes several findings at once, which is why this list walks
  file by file rather than finding by finding.</p>
  <ol class="plan">{steps}</ol>
  {tail}
</section>
"#
    )
}

/// A short dictionary. The report is read by people who do not spend their day
/// in security terminology; every term used above gets one plain sentence here.
fn glossary(report: &AuditReport) -> String {
    let terms: &[(&str, &str)] = &[
        ("Secret", "A password, API key or token — a value that lets whoever holds it into the system. It belongs in an environment variable, never in the code."),
        ("SQL Injection", "If text typed by a user is pasted into a query, that person can write a command instead of text and read or delete the database."),
        ("XSS", "If text typed by a user is rendered as HTML, that person can run their own code in another user's browser and steal their session."),
        ("IDOR", "Changing an id in the URL to see somebody else's data. The cause: the server never asks whether the record belongs to this user."),
        ("SSRF", "The server itself fetches a URL supplied by the user. Internal services — the database, an admin panel, cloud metadata — become reachable from outside."),
        ("JWT", "A signed token that identifies the user. If the signature is not verified, anyone can mint a token claiming to be an admin."),
        ("Hash", "Turning data into a form that cannot be reversed. MD5 and SHA-1 are broken; passwords need bcrypt or argon2."),
        ("CORS", "The browser rule for which sites may call this API. If it says `*`, every site may."),
        ("Migration", "A script that changes the database structure. A wrong migration can stop a live system and delete data."),
        ("Gate", "If a finding at or above a chosen severity exists, deadbolt exits non-zero and CI stops the release."),
        ("Baseline", "A recorded list of findings that are already known and accepted. They stop warning, while new ones still show up."),
    ];

    let ai_note = if report.meta.ai_enabled {
        "<li><b>AI Review</b> — a step that reads the code separately and looks for logic \
defects the rules cannot catch (authorisation gaps, data-leak chains). Its results are marked \
as probable: they need human confirmation.</li>"
    } else {
        "<li><b>AI Review</b> — not enabled for this report; only rule-based checking ran. \
Run it with <code>--ai</code> to surface logic defects.</li>"
    };

    let items: String = terms
        .iter()
        .map(|(term, explanation)| format!("<li><b>{term}</b> — {explanation}</li>"))
        .collect();

    format!(
        r#"<section id="glossary">
  <h2>Glossary</h2>
  <ul class="gloss">{items}{ai_note}</ul>
</section>
"#
    )
}

fn trend_section(trend_svg: &str) -> String {
    format!(
        r#"<section>
  <h2>How The Score Changes Over Time</h2>
  <div class="trend">{trend_svg}</div>
  <p class="note">Every run is appended to <code>.deadbolt-history.jsonl</code>.
  If the ratchet is enabled, a drop in the score stops the release.</p>
</section>
"#
    )
}

fn stack(report: &AuditReport) -> String {
    let total = report.stack.total_lines.max(1);
    let languages: String = report
        .stack
        .languages
        .iter()
        .take(7)
        .map(|language| {
            format!(
                r#"<li><span class="lang-name">{name}</span>
<span class="lang-track"><span class="lang-fill" style="--w:{percent:.1}%"></span></span>
<span class="muted">{lines} lines</span></li>"#,
                name = escape(&language.name),
                percent = (language.lines as f64 / total as f64) * 100.0,
                lines = language.lines,
            )
        })
        .collect();

    let chips = |items: &[String]| -> String {
        if items.is_empty() {
            "<span class=\"muted\">None Detected</span>".to_string()
        } else {
            items
                .iter()
                .map(|item| format!("<span class=\"pill\">{}</span>", escape(item)))
                .collect()
        }
    };

    format!(
        r#"<section id="stack">
  <h2>What This Project Is Built From</h2>
  <div class="two">
    <ul class="langs">{languages}</ul>
    <table class="meta">
      <tr><th>Frameworks</th><td>{frameworks}</td></tr>
      <tr><th>Databases</th><td>{databases}</td></tr>
      <tr><th>Package Managers</th><td>{managers}</td></tr>
      <tr><th>Automation (CI)</th><td>{ci}</td></tr>
      <tr><th>Infrastructure</th><td>{infra}</td></tr>
      <tr><th>Size</th><td>{files} files · {lines} lines of code</td></tr>
    </table>
  </div>
</section>
"#,
        frameworks = chips(&report.stack.frameworks),
        databases = chips(&report.stack.databases),
        managers = chips(&report.stack.package_managers),
        ci = chips(&report.stack.ci_systems),
        infra = chips(&report.stack.infrastructure),
        files = report.stack.total_files,
        lines = report.stack.total_lines,
    )
}

fn compliance(report: &AuditReport) -> String {
    let cards: String = report
        .packs
        .iter()
        .map(|pack| {
            let coverage = pack.coverage();
            let circumference = 163.36_f64; // r = 26
            let offset = circumference * (1.0 - coverage / 100.0);
            format!(
                r#"<article class="pack">
  <svg viewBox="0 0 64 64" class="mini-ring">
    <circle cx="32" cy="32" r="26" class="ring-track"/>
    <circle cx="32" cy="32" r="26" class="ring-fill"
            style="stroke-dasharray:{circumference:.2};stroke-dashoffset:{offset:.2}"/>
    <text x="32" y="37" class="mini-num">{coverage:.0}%</text>
  </svg>
  <div>
    <h4>{title}</h4>
    <p class="muted">{name} {version}</p>
    <ul class="pack-stats">
      <li class="ok"><b>{satisfied}</b> Satisfied</li>
      <li class="bad"><b>{violated}</b> Violated</li>
      <li class="muted"><b>{unknown}</b> Could Not Be Checked</li>
    </ul>
  </div>
</article>"#,
                title = escape(&pack.title),
                name = escape(&pack.name),
                version = escape(&pack.version),
                satisfied = pack.satisfied,
                violated = pack.violated,
                unknown = pack.unknown,
            )
        })
        .collect();

    let violated_rows: String = report
        .controls
        .iter()
        .filter(|control| control.status == ControlStatus::Violated)
        .map(|control| {
            format!(
                r#"<tr><td><code>{pack} {id}</code></td><td>{title}</td>
<td><span class="tag {class}">{severity}</span></td></tr>"#,
                pack = escape(&control.pack),
                id = escape(&control.id),
                title = escape(&control.title),
                class = severity_class(control.severity),
                severity = severity_word(control.severity),
            )
        })
        .collect();

    let violated_count = report
        .controls
        .iter()
        .filter(|control| control.status == ControlStatus::Violated)
        .count();

    let violated_block = if violated_count == 0 {
        String::new()
    } else {
        format!(
            r#"<h3>Violated Controls ({violated_count})</h3>
<table><thead><tr><th>Control</th><th>What It Requires</th><th>Severity</th></tr></thead>
<tbody>{violated_rows}</tbody></table>"#
        )
    };

    format!(
        r#"<section id="compliance">
  <h2>Standards Compliance</h2>
  <p class="note">Each pack is evaluated independently. <b>Could Not Be Checked</b> means
  this tool cannot assess that control (the AI review was not enabled, or only a human can
  judge it). It does not mean the control is satisfied.</p>
  <div class="packs">{cards}</div>
  {violated_block}
</section>
"#
    )
}

fn origin_label(finding: &Finding) -> String {
    match finding.origin {
        Origin::Ai => format!("AI Review · {}", finding.lens),
        Origin::Dependency => "Dependency Research".to_string(),
        Origin::Compliance => "Standards Control".to_string(),
        Origin::Chain => "Correlated Attack Path".to_string(),
        Origin::Static => format!("rule {}", finding.rule),
    }
}

/// Multi-step evidence is an attack path; drawing it as one makes the route
/// obvious in a way a list of line numbers never does.
fn chain(finding: &Finding) -> String {
    if finding.evidence.len() < 2 {
        return String::new();
    }
    let last = finding.evidence.len() - 1;
    let steps: String = finding
        .evidence
        .iter()
        .rev()
        .enumerate()
        .map(|(index, evidence)| {
            let role = if index == 0 {
                "Starts Here"
            } else if index == last {
                "Reaches Here"
            } else {
                "Passes Through"
            };
            format!(
                r#"<li style="animation-delay:{delay}ms">
  <span class="step-role">{role}</span>
  <code>{location}</code>{snippet}
</li>"#,
                delay = index * 120,
                location = escape(&evidence.location()),
                snippet = if evidence.snippet.is_empty() {
                    String::new()
                } else {
                    format!("<pre>{}</pre>", escape(&evidence.snippet))
                },
            )
        })
        .collect();

    format!(
        r#"<div class="chain"><div class="chain-head">{arrow} Problemin yolu</div><ol>{steps}</ol></div>"#,
        arrow = svg(ICON_ARROW, "chain-ico")
    )
}

fn finding_block(finding: &Finding, index: usize) -> String {
    let class = severity_class(finding.severity);

    let single_evidence = if finding.evidence.len() == 1 {
        finding
            .evidence
            .first()
            .filter(|evidence| !evidence.snippet.is_empty())
            .map(|evidence| format!("<pre>{}</pre>", escape(&evidence.snippet)))
            .unwrap_or_default()
    } else {
        String::new()
    };

    let field = |label: &str, value: &str| -> String {
        if value.is_empty() {
            String::new()
        } else {
            format!(
                "<div class=\"field\"><span>{label}</span><p>{}</p></div>",
                escape(value)
            )
        }
    };

    let steps = |value: &str| -> String {
        if value.is_empty() {
            return String::new();
        }
        let parts: Vec<&str> = value
            .split_inclusive(['.', '!'])
            .map(str::trim)
            .filter(|part| part.len() > 3)
            .collect();
        if parts.len() < 2 {
            return field("How To Fix It", value);
        }
        let items: String = parts
            .iter()
            .map(|part| format!("<li>{}</li>", escape(part)))
            .collect();
        format!("<div class=\"field\"><span>How To Fix It — Step By Step</span><ol class=\"fix\">{items}</ol></div>")
    };

    let mut references = Vec::new();
    if let Some(cwe) = finding.cwe {
        references.push(format!(
            "<a href=\"https://cwe.mitre.org/data/definitions/{cwe}.html\">CWE-{cwe}</a>"
        ));
    }
    if !finding.asvs.is_empty() {
        references.push(format!("OWASP ASVS {}", escape(&finding.asvs.join(", "))));
    }
    if !finding.policy_refs.is_empty() {
        references.push(escape(&finding.policy_refs.join(", ")));
    }

    let hint = if finding.origin == Origin::Static && !finding.rule.is_empty() {
        format!(
            "<span class=\"hint\">More About This Rule: <code>deadbolt explain {}</code></span>",
            escape(&finding.rule)
        )
    } else {
        String::new()
    };

    let confidence_note = match finding.confidence {
        Confidence::Confirmed => String::new(),
        Confidence::Probable => {
            "<span class=\"conf probable\">Probable — Needs Manual Confirmation</span>".to_string()
        }
        Confidence::Possible => {
            "<span class=\"conf possible\">Unconfirmed — Does Not Block The Release</span>"
                .to_string()
        }
    };

    format!(
        r#"<details class="f {class}" style="animation-delay:{delay}ms">
  <summary>
    <span class="tag {class}">{severity}</span>
    <span class="title">{title}</span>
    <code class="loc">{location}</code>
    <span class="muted origin">{origin}</span>
  </summary>
  <div class="fbody">
    {description}
    {single_evidence}
    {chain}
    {impact}
    {scenario}
    {remediation}
    <div class="refs">{references}{confidence_note}{hint}</div>
  </div>
</details>
"#,
        delay = index.min(20) * 40,
        severity = severity_word(finding.severity),
        title = escape(&finding.title),
        location = escape(&finding.primary_location()),
        origin = escape(&origin_label(finding)),
        description = if finding.description.is_empty() {
            String::new()
        } else {
            format!("<p class=\"desc\">{}</p>", escape(&finding.description))
        },
        chain = chain(finding),
        impact = field("What Can Happen", &finding.impact),
        scenario = field("Concrete Scenario", &finding.scenario),
        remediation = steps(&finding.remediation),
        references = references.join(" · "),
        hint = hint,
    )
}

fn findings(report: &AuditReport) -> String {
    if report.findings.is_empty() {
        return "<section id=\"findings\"><h2>Findings</h2><p class=\"clean\">No Problems Found.</p></section>\n"
            .to_string();
    }

    let mut grouped: BTreeMap<Severity, Vec<&Finding>> = BTreeMap::new();
    for finding in &report.findings {
        grouped.entry(finding.severity).or_default().push(finding);
    }

    let mut sections = String::new();
    let mut counter = 0usize;
    for (severity, items) in grouped {
        sections.push_str(&format!(
            r#"<h3 class="sev-head {class}"><span class="tag {class}">{label}</span>
{count} findings <em>— {action}</em></h3>"#,
            class = severity_class(severity),
            label = severity_word(severity),
            count = items.len(),
            action = severity_action(severity),
        ));
        for finding in items {
            sections.push_str(&finding_block(finding, counter));
            counter += 1;
        }
    }

    format!(
        r#"<section id="findings">
  <h2>Findings ({total})</h2>
  <p class="note">Click a finding to open what can happen, a concrete scenario
  and how to fix it.</p>
  <div class="toolbar">
    <button type="button" data-toggle="open">Expand All</button>
    <button type="button" data-toggle="close">Collapse All</button>
  </div>
  {sections}
</section>
"#,
        total = report.findings.len()
    )
}

fn dependencies(report: &AuditReport) -> String {
    let mut risky: Vec<_> = report
        .packages
        .iter()
        .filter(|audit| !audit.vulnerabilities.is_empty() || !audit.signals.is_empty())
        .collect();
    risky.sort_by(|a, b| {
        b.risk_score
            .partial_cmp(&a.risk_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if risky.is_empty() {
        return format!(
            "<section id=\"dependencies\"><h2>Dependencies</h2><p class=\"clean\">{} packages checked, no risk signal found.</p></section>\n",
            report.packages.len()
        );
    }

    let max_risk = risky
        .iter()
        .map(|audit| audit.risk_score)
        .fold(1.0_f64, f64::max);

    let rows: String = risky
        .iter()
        .take(60)
        .filter_map(|audit| {
            let package = audit.package.as_ref()?;

            let vulnerabilities = if audit.vulnerabilities.is_empty() {
                "<span class=\"muted\">none</span>".to_string()
            } else {
                let shown: String = audit
                    .vulnerabilities
                    .iter()
                    .take(3)
                    .map(|vulnerability| {
                        format!(
                            "<a href=\"https://osv.dev/vulnerability/{id}\">{id}</a>",
                            id = escape(&vulnerability.id)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                let extra = audit.vulnerabilities.len().saturating_sub(3);
                if extra > 0 {
                    format!("{shown} <span class=\"muted\">and {extra} more</span>")
                } else {
                    shown
                }
            };

            let signals: String = audit
                .signals
                .iter()
                .map(|signal| format!("<span class=\"sig\">{}</span>", escape(signal.label())))
                .collect();

            let research = audit
                .research
                .as_ref()
                .map(|research| {
                    format!(
                        "<div class=\"muted research\">Collects Personal Data: <b>{}</b>{}</div>",
                        escape(research.collects_personal_data.label()),
                        if research.verdict.is_empty() {
                            String::new()
                        } else {
                            format!(" — {}", escape(&research.verdict))
                        }
                    )
                })
                .unwrap_or_default();

            Some(format!(
                r#"<tr><td><code>{name}</code>
<div class="muted">{ecosystem} · {usage}</div>{research}</td>
<td><code>{version}</code></td><td>{vulnerabilities}</td><td>{signals}</td>
<td class="risk"><span class="risk-track"><span class="risk-fill" style="--w:{percent:.0}%"></span></span>{score:.0}</td></tr>"#,
                name = escape(&package.name),
                ecosystem = escape(&package.ecosystem),
                usage = if package.direct {
                    "added by us"
                } else {
                    "pulled in by another package"
                },
                version = escape(&package.version),
                percent = (audit.risk_score / max_risk) * 100.0,
                score = audit.risk_score,
            ))
        })
        .collect();

    format!(
        r#"<section id="dependencies">
  <h2>Dependencies</h2>
  <p class="note">{total} packages checked · {risky} carry a risk signal.
  Vulnerability ids link to the OSV.dev database.</p>
  <table><thead><tr><th>Package</th><th>Version</th><th>Known Vulnerabilities</th>
  <th>Risk Signals</th><th>Risk Score</th></tr></thead><tbody>{rows}</tbody></table>
</section>
"#,
        total = report.packages.len(),
        risky = risky.len(),
    )
}

fn footer(report: &AuditReport) -> String {
    let warnings: String = report
        .meta
        .warnings
        .iter()
        .map(|warning| format!("<li>{}</li>", escape(warning)))
        .collect();

    let warning_block = if warnings.is_empty() {
        String::new()
    } else {
        format!("<h3>Notes Worth Attention</h3><ul class=\"warn\">{warnings}</ul>")
    };

    let checks = if report.meta.lenses_run.is_empty() {
        "rule-based checking only".to_string()
    } else {
        format!("AI Lenses: {}", escape(&report.meta.lenses_run.join(", ")))
    };

    format!(
        r#"<footer>
  {warning_block}
  <p class="muted">{tool} {version} · rejim: {mode} · {checks} · {duration} ms · {started}</p>
  <p class="muted small">This report is fully self-contained: it loads no external image,
  font or script. It opens without internet access and can be sent by email.</p>
</footer>
"#,
        tool = escape(&report.meta.tool),
        version = escape(&report.meta.version),
        mode = escape(&report.meta.mode),
        duration = report.meta.duration_ms,
        started = escape(report.meta.started_at.get(..19).unwrap_or("")),
    )
}

const SCRIPT: &str = r#"
(function () {
  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  document.querySelectorAll('[data-count]').forEach(function (node) {
    var target = parseFloat(node.getAttribute('data-count'));
    if (reduce || !isFinite(target)) { node.textContent = target.toFixed(1); return; }
    var start = performance.now(), duration = 1100;
    function tick(now) {
      var progress = Math.min((now - start) / duration, 1);
      var eased = 1 - Math.pow(1 - progress, 3);   // settle, do not stop abruptly
      node.textContent = (target * eased).toFixed(1);
      if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  });

  document.querySelectorAll('[data-toggle]').forEach(function (button) {
    button.addEventListener('click', function () {
      var open = button.getAttribute('data-toggle') === 'open';
      document.querySelectorAll('details.f').forEach(function (item) { item.open = open; });
    });
  });
})();
"#;

const CSS: &str = r##"
:root{
  --bg:#04070a;--bg2:#070c12;--panel:#080e14;--line:#123020;--line2:#0d1f16;
  --fg:#c8f5d8;--dim:#4e7f63;--acid:#00ff9c;--acid2:#00c97c;
  --crit:#ff2d55;--high:#ff8a1f;--med:#ffe14d;--low:#5d8f77;--info:#22b8ff;--ok:#00ff9c;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--fg);font:13px/1.6 var(--mono);
  position:relative;overflow-x:hidden;letter-spacing:.01em;
  text-shadow:0 0 12px rgba(0,255,156,.09)}
::selection{background:var(--acid);color:#04070a}

/* backdrop: grid + vignette + scanlines */
.grid-bg{position:fixed;inset:0;pointer-events:none;z-index:0;opacity:.5;
  background-image:linear-gradient(var(--line2) 1px,transparent 1px),
                   linear-gradient(90deg,var(--line2) 1px,transparent 1px);
  background-size:28px 28px;
  mask-image:radial-gradient(ellipse 100% 70% at 50% 0%,#000 5%,transparent 75%);
  -webkit-mask-image:radial-gradient(ellipse 100% 70% at 50% 0%,#000 5%,transparent 75%)}
.grid-bg::after{content:"";position:absolute;inset:0;
  background:repeating-linear-gradient(180deg,rgba(0,255,156,.05) 0 1px,transparent 1px 3px);
  animation:drift 8s linear infinite}
@keyframes drift{to{transform:translateY(3px)}}
.app{display:flex;align-items:flex-start;min-height:100vh;position:relative;z-index:1}
main{flex:1;min-width:0}

/* rail */
.side{position:sticky;top:0;height:100vh;width:16.5rem;flex:none;z-index:2;
  border-right:1px solid var(--line);background:
    linear-gradient(180deg,rgba(0,255,156,.05),transparent 40%),var(--bg2);
  padding:1.2rem 1rem;display:flex;flex-direction:column;gap:.9rem;overflow-y:auto}
.side-brand{display:flex;align-items:center;gap:.4rem;font-weight:700;letter-spacing:.28em;
  font-size:.64rem;color:var(--acid);text-transform:uppercase}
.side-brand::after{content:"_";animation:blink 1s step-end infinite}
.brand-ico{width:13px;height:13px;fill:var(--acid)}
.side-score{display:flex;align-items:baseline;gap:.45rem;padding:.5rem .6rem;
  border:1px solid var(--line);background:#050a0e;position:relative}
.side-score::before{content:"SCORE";position:absolute;top:-.45rem;left:.45rem;
  font-size:.52rem;letter-spacing:.18em;color:var(--dim);background:var(--bg2);padding:0 .25rem}
.side-num{font-size:1.9rem;font-weight:700;font-variant-numeric:tabular-nums;line-height:1}
.side-score.good .side-num{color:var(--ok);text-shadow:0 0 18px var(--ok)}
.side-score.fair .side-num{color:var(--med);text-shadow:0 0 18px var(--med)}
.side-score.bad .side-num{color:var(--crit);text-shadow:0 0 18px var(--crit)}
.side-grade{font-size:.72rem;font-weight:700;letter-spacing:.16em;color:var(--dim)}
.side-pills{display:flex;flex-wrap:wrap;gap:.25rem}
.mini{font-size:.6rem;padding:.1rem .35rem;border:1px solid currentColor;
  text-transform:uppercase;letter-spacing:.1em}
.mini.crit{color:var(--crit)}.mini.high{color:var(--high)}.mini.med{color:var(--med)}
.mini.low{color:var(--low)}.mini.info{color:var(--info)}
.side nav{display:flex;flex-direction:column;margin-top:.3rem}
.side nav a{color:var(--fg);text-decoration:none;font-size:.74rem;padding:.28rem .4rem;
  border-left:2px solid transparent;transition:.12s;text-transform:uppercase;letter-spacing:.06em}
.side nav a::before{content:"[ ] ";color:var(--dim)}
.side nav a:hover{color:var(--acid);border-left-color:var(--acid);background:rgba(0,255,156,.06)}
.side nav a:hover::before{content:"[x] ";color:var(--acid)}
.side-foot{margin-top:auto;font-size:.64rem;color:var(--dim);word-break:break-word;
  border-top:1px solid var(--line2);padding-top:.5rem}

/* header */
header{padding:1.4rem 1.8rem 1.6rem;border-bottom:1px solid var(--line);
  background:linear-gradient(180deg,rgba(0,255,156,.04),transparent)}
.term{display:flex;align-items:center;gap:.6rem;background:#050a0e;
  border:1px solid var(--line);padding:.4rem .7rem;max-width:34rem;font-size:.76rem}
.term code{color:var(--acid)}
.dots{display:flex;gap:.28rem}
.dots i{width:7px;height:7px;display:block;background:var(--line)}
.dots i:first-child{background:var(--crit)}
.dots i:nth-child(2){background:var(--med)}
.dots i:nth-child(3){background:var(--ok)}
.caret{width:7px;height:13px;background:var(--acid);animation:blink 1s step-end infinite;
  box-shadow:0 0 10px var(--acid)}
@keyframes blink{50%{opacity:0}}
.brand{display:flex;align-items:center;gap:.4rem;margin-top:1.1rem;font-weight:700;
  letter-spacing:.3em;font-size:.62rem;color:var(--acid);text-transform:uppercase}
.ver{color:var(--dim);letter-spacing:.05em}
h1{margin:.35rem 0 .15rem;font-size:1.5rem;letter-spacing:.02em;text-transform:uppercase;
  color:#eafff2;text-shadow:0 0 22px rgba(0,255,156,.28)}
h1::before{content:"# ";color:var(--acid)}
.sub{margin:0;color:var(--dim);font-size:.72rem;word-break:break-all}
.sub.when{margin-top:.2rem}

/* sections */
section,footer{padding:1.7rem 1.8rem;border-bottom:1px solid var(--line2);max-width:1500px}
h2{font-size:.82rem;margin:0 0 .7rem;display:flex;align-items:center;gap:.45rem;
  text-transform:uppercase;letter-spacing:.2em;color:var(--acid)}
h2::before{content:"//";color:var(--dim);letter-spacing:0}
h3{font-size:.72rem;margin:1.5rem 0 .6rem;text-transform:uppercase;letter-spacing:.16em;
  color:var(--fg)}
h4{margin:0 0 .1rem;font-size:.78rem;text-transform:uppercase;letter-spacing:.1em}
.h-ico{width:14px;height:14px;fill:var(--acid)}
.verdict{margin:.1rem 0 1.4rem;color:var(--fg);max-width:78ch;opacity:.85}
.note{font-size:.72rem;color:var(--dim);margin:.4rem 0 1rem;max-width:90ch}
.clean{color:var(--ok)}
.clean::before{content:"[OK] "}
.muted{color:var(--dim);font-size:.7rem}
.small{font-size:.66rem}
code{font-family:var(--mono)}

/* score board */
.board-grid{display:flex;gap:2.8rem;flex-wrap:wrap;align-items:center}
.ring-wrap{position:relative;width:236px;height:236px;flex:none}
.ring{width:236px;height:236px;transform:rotate(-90deg)}
.ring-track{fill:none;stroke:var(--line);stroke-width:5.5}
.ring-fill{fill:none;stroke-width:5.5;stroke-linecap:butt;
  animation:ringIn 1.4s cubic-bezier(.2,.8,.2,1) both}
.good .ring-fill{stroke:var(--ok);filter:drop-shadow(0 0 8px var(--ok))}
.fair .ring-fill{stroke:var(--med);filter:drop-shadow(0 0 8px var(--med))}
.bad .ring-fill{stroke:var(--crit);filter:drop-shadow(0 0 8px var(--crit))}
.good .ring-num{color:var(--ok)}.fair .ring-num{color:var(--med)}.bad .ring-num{color:var(--crit)}
@keyframes ringIn{from{stroke-dashoffset:339.29}}
.ring-text{position:absolute;inset:0;display:flex;flex-direction:column;
  align-items:center;justify-content:center;line-height:1.05}
.ring-num{font-size:3.6rem;font-weight:700;font-variant-numeric:tabular-nums;line-height:1}
.ring-of{font-size:.66rem;color:var(--dim);letter-spacing:.2em;text-transform:uppercase}
.ring-grade{margin-top:.5rem;font-weight:700;font-size:1.15rem;letter-spacing:.3em}

.donut-wrap{display:flex;gap:1.4rem;align-items:center;flex:none}
.donut{width:212px;height:212px;transform:rotate(-90deg)}
.seg{fill:none;stroke-width:11;animation:segIn .9s cubic-bezier(.2,.8,.2,1) both}
@keyframes segIn{from{stroke-dasharray:0 251.33}}
.seg.crit{stroke:var(--crit)}.seg.high{stroke:var(--high)}.seg.med{stroke:var(--med)}
.seg.low{stroke:var(--low)}.seg.info{stroke:var(--info)}
.donut-num,.donut-lbl{transform:rotate(90deg);transform-origin:50px 50px;
  text-anchor:middle;fill:var(--fg);font-family:var(--mono)}
.donut-num{font-size:16px;font-weight:700}
.donut-lbl{font-size:5.4px;fill:var(--dim);letter-spacing:.2em}
.donut-sub{transform:rotate(90deg);transform-origin:50px 50px;text-anchor:middle;
  font-size:4.8px;fill:var(--crit);letter-spacing:.16em;font-family:var(--mono)}
.seg{cursor:help}
.legend{list-style:none;margin:0;padding:0;font-size:.78rem}
.legend li{display:flex;align-items:baseline;gap:.5rem;padding:.22rem 0}
.legend b{font-variant-numeric:tabular-nums;min-width:1.6rem;text-align:right}
.legend em{color:var(--dim);font-style:normal;font-size:.66rem;text-transform:uppercase;
  letter-spacing:.08em}
.swatch{width:9px;height:9px;display:inline-block}
.legend .crit .swatch{background:var(--crit)}.legend .high .swatch{background:var(--high)}
.legend .med .swatch{background:var(--med)}.legend .low .swatch{background:var(--low)}
.legend .info .swatch{background:var(--info)}

.cats{flex:1;min-width:20rem}
.cat-list,.langs{list-style:none;margin:0;padding:0}
.cat-list li{display:grid;grid-template-columns:12rem 1fr 2.2rem;gap:.6rem;
  align-items:center;padding:.14rem 0;font-size:.72rem;text-transform:uppercase;
  letter-spacing:.06em}
.cat-name{display:flex;align-items:center;gap:.4rem}
.cat-ico{width:12px;height:12px;fill:var(--dim);flex:none}
.cat-track,.lang-track,.risk-track{background:#071016;border:1px solid var(--line2);
  height:12px;overflow:hidden;display:block}
.cat-fill,.lang-fill,.risk-fill{display:block;height:100%;width:var(--w);
  animation:grow 1s cubic-bezier(.2,.8,.2,1) both;
  background-image:repeating-linear-gradient(90deg,rgba(0,0,0,.35) 0 1px,transparent 1px 4px)}
@keyframes grow{from{width:0}}
.cat-fill.crit{background-color:var(--crit)}.cat-fill.high{background-color:var(--high)}
.cat-fill.med{background-color:var(--med)}.cat-fill.low{background-color:var(--low)}
.cat-fill.info{background-color:var(--info)}
.cat-list b{font-variant-numeric:tabular-nums;text-align:right}

.trend{background:#050a0e;border:1px solid var(--line);padding:.8rem;overflow:hidden}
.trend svg polyline{animation:draw 1.8s ease-out both;filter:drop-shadow(0 0 6px var(--acid))}
@keyframes draw{from{stroke-dasharray:1400;stroke-dashoffset:1400}
                to{stroke-dasharray:1400;stroke-dashoffset:0}}

/* stack */
.two{display:flex;gap:2.2rem;flex-wrap:wrap}
.langs{min-width:20rem;flex:1}
.langs li{display:grid;grid-template-columns:7rem 1fr 6rem;gap:.6rem;align-items:center;
  padding:.14rem 0;font-size:.72rem}
.lang-fill{background-color:var(--acid2)}
table.meta{border-collapse:collapse;font-size:.72rem;min-width:22rem;display:table}
table.meta th{text-align:left;color:var(--dim);font-weight:400;padding:.28rem .8rem .28rem 0;
  vertical-align:top;white-space:nowrap;border:0;text-transform:uppercase;letter-spacing:.1em;
  font-size:.66rem}
table.meta td{padding:.28rem 0;border:0}
.pill{display:inline-block;background:#071016;border:1px solid var(--line);
  padding:.05rem .4rem;margin:0 .2rem .2rem 0;font-size:.66rem;color:var(--fg)}

/* compliance */
.packs{display:flex;gap:.8rem;flex-wrap:wrap;margin-bottom:.8rem}
.pack{display:flex;gap:.8rem;align-items:center;background:#050a0e;
  border:1px solid var(--line);padding:.7rem .9rem;min-width:18rem;flex:1;position:relative}
.pack::before,.pack::after{content:"";position:absolute;width:6px;height:6px;
  border:1px solid var(--acid)}
.pack::before{top:-1px;left:-1px;border-right:0;border-bottom:0}
.pack::after{bottom:-1px;right:-1px;border-left:0;border-top:0}
.mini-ring{width:84px;height:84px;flex:none;transform:rotate(-90deg)}
.mini-ring .ring-track{stroke-width:4}
.mini-ring .ring-fill{stroke-width:4;stroke:var(--ok)}
.mini-num{transform:rotate(90deg);transform-origin:32px 32px;text-anchor:middle;
  font-size:13px;font-weight:700;fill:var(--fg);font-family:var(--mono)}
.pack-stats{list-style:none;margin:.3rem 0 0;padding:0;font-size:.68rem;
  display:flex;gap:.8rem;flex-wrap:wrap;text-transform:uppercase;letter-spacing:.06em}
.ok{color:var(--ok)}.bad{color:var(--crit)}

/* tables */
table{width:100%;border-collapse:collapse;font-size:.72rem;display:block;overflow-x:auto}
th{text-align:left;font-weight:700;color:var(--acid);font-size:.62rem;text-transform:uppercase;
  letter-spacing:.14em;padding:.4rem .6rem;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:.45rem .6rem;border-bottom:1px solid var(--line2);vertical-align:top}
tr:hover td{background:rgba(0,255,156,.04)}
.risk{white-space:nowrap;display:flex;align-items:center;gap:.4rem;
  font-variant-numeric:tabular-nums}
.risk-track{width:58px}
.risk-fill{background-color:var(--crit);
  background-image:repeating-linear-gradient(90deg,rgba(0,0,0,.4) 0 1px,transparent 1px 4px)}
.sig{display:inline-block;font-size:.62rem;padding:.02rem .3rem;margin:0 .18rem .18rem 0;
  background:#071016;border:1px solid var(--line);text-transform:uppercase;letter-spacing:.06em}
.research{margin-top:.25rem}
a{color:var(--info)}
a:hover{color:var(--acid)}

/* action plan */
ol.plan{list-style:none;margin:0;padding:0}
ol.plan li{display:flex;gap:.7rem;align-items:flex-start;background:#050a0e;
  border:1px solid var(--line2);border-left:2px solid var(--acid);padding:.55rem .8rem;
  margin:.3rem 0;animation:fadeUp .5s ease-out both}
.step-no{flex:none;width:1.5rem;height:1.5rem;display:grid;place-items:center;
  background:#04070a;border:1px solid var(--acid);color:var(--acid);font-weight:700;
  font-size:.68rem}
ol.plan code{font-size:.74rem;word-break:break-all;color:#eafff2}

/* findings */
.toolbar{display:flex;gap:.4rem;margin:.2rem 0 .9rem}
.toolbar button{background:#050a0e;color:var(--fg);border:1px solid var(--line);
  padding:.28rem .7rem;font-size:.66rem;cursor:pointer;font-family:var(--mono);
  text-transform:uppercase;letter-spacing:.12em;transition:.12s}
.toolbar button:hover{border-color:var(--acid);color:var(--acid);
  box-shadow:0 0 12px rgba(0,255,156,.25)}
.sev-head{display:flex;align-items:center;gap:.5rem;font-size:.68rem;padding-top:.6rem;
  border-top:1px solid var(--line2);color:var(--dim);letter-spacing:.12em}
.sev-head em{font-style:normal;font-size:.64rem}
details.f{background:#050a0e;border:1px solid var(--line2);border-left:2px solid var(--line);
  margin:.28rem 0;animation:fadeUp .45s ease-out both}
@keyframes fadeUp{from{opacity:0;transform:translateY(6px)}}
details.f.crit{border-left-color:var(--crit)}
details.f.high{border-left-color:var(--high)}
details.f.med{border-left-color:var(--med)}
details.f.low{border-left-color:var(--low)}
details.f.info{border-left-color:var(--info)}
details.f:hover{border-color:var(--line)}
details.f.crit[open]{box-shadow:inset 2px 0 0 var(--crit),0 0 24px -12px var(--crit)}
details.f[open]{border-color:var(--line)}
summary{cursor:pointer;padding:.5rem .7rem;display:flex;gap:.5rem;align-items:baseline;
  flex-wrap:wrap;list-style:none}
summary::-webkit-details-marker{display:none}
summary::after{content:"[+]";margin-left:auto;color:var(--dim);font-size:.66rem}
details[open] summary::after{content:"[-]";color:var(--acid)}
.tag{font-size:.6rem;font-weight:700;padding:.06rem .3rem;letter-spacing:.14em;
  white-space:nowrap;border:1px solid currentColor;text-transform:uppercase}
.tag::before{content:"[ "}
.tag::after{content:" ]"}
.tag.crit{color:var(--crit)}.tag.high{color:var(--high)}.tag.med{color:var(--med)}
.tag.low{color:var(--low)}.tag.info{color:var(--info)}
.title{flex:1;min-width:15rem;font-weight:600;color:#eafff2}
.loc{font-size:.68rem;color:var(--acid2)}
.origin{font-size:.62rem;text-transform:uppercase;letter-spacing:.1em}
.fbody{padding:0 .7rem .8rem;border-top:1px solid var(--line2)}
.desc{margin:.6rem 0;opacity:.9}
.field{margin:.6rem 0}
.field span{font-size:.6rem;text-transform:uppercase;letter-spacing:.16em;
  color:var(--acid);font-weight:700}
.field span::before{content:"> "}
.field p{margin:.15rem 0 0;opacity:.9}
pre{background:#02050a;border:1px solid var(--line2);border-left:2px solid var(--acid2);
  padding:.45rem .6rem;overflow-x:auto;font-size:.72rem;margin:.4rem 0;
  font-family:var(--mono);color:#d8ffe8}
ol.fix{margin:.2rem 0 0;padding-left:1.2rem}
ol.fix li{margin:.1rem 0}
.refs{margin-top:.7rem;font-size:.66rem;color:var(--dim);display:flex;gap:.5rem;
  flex-wrap:wrap;align-items:center}
.conf{padding:.04rem .35rem;border:1px dashed currentColor;font-size:.62rem;
  text-transform:uppercase;letter-spacing:.08em}
.conf.probable{color:var(--med)}.conf.possible{color:var(--dim)}
.hint code{color:var(--acid)}

/* attack chain */
.chain{margin:.7rem 0;background:#02050a;border:1px solid var(--line);padding:.65rem .8rem}
.chain-head{display:flex;align-items:center;gap:.35rem;font-size:.6rem;text-transform:uppercase;
  letter-spacing:.18em;color:var(--acid);font-weight:700}
.chain-ico{width:12px;height:12px;fill:var(--acid)}
.chain ol{list-style:none;margin:.6rem 0 0;padding:0;position:relative}
.chain ol::before{content:"";position:absolute;left:5px;top:5px;bottom:12px;width:1px;
  background:linear-gradient(180deg,var(--acid),transparent)}
.chain li{position:relative;padding:0 0 .7rem 1.3rem;animation:fadeUp .5s ease-out both}
.chain li::before{content:"";position:absolute;left:0;top:5px;width:11px;height:11px;
  border:1px solid var(--acid);background:#02050a;box-shadow:0 0 8px rgba(0,255,156,.5)}
.step-role{display:block;font-size:.58rem;text-transform:uppercase;letter-spacing:.16em;
  color:var(--dim);font-weight:700}
.chain code{font-size:.72rem;color:var(--acid2)}
.chain pre{margin:.3rem 0 0}

/* glossary */
ul.gloss{list-style:none;margin:0;padding:0;display:grid;
  grid-template-columns:repeat(auto-fit,minmax(23rem,1fr));gap:.5rem}
ul.gloss li{background:#050a0e;border:1px solid var(--line2);padding:.6rem .8rem;
  font-size:.72rem;opacity:.92}
ul.gloss b{color:var(--acid);text-transform:uppercase;letter-spacing:.08em}

.warn{font-size:.7rem;color:var(--med);padding-left:1rem;list-style:none}
.warn li::before{content:"! ";color:var(--med);font-weight:700}
footer{border-bottom:0}

/* gauge ticks and thresholds */
.ticks line{stroke:var(--line);stroke-width:1}
.ticks line.long{stroke:var(--dim);stroke-width:1.4}
.ticks line.threshold{stroke:var(--dim);stroke-width:1;stroke-dasharray:2 2;opacity:.9}

/* kpi strip */
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(8.5rem,1fr));gap:.5rem;
  margin:0 0 1.6rem}
.kpi{position:relative;background:#050a0e;border:1px solid var(--line2);padding:.6rem .7rem}
.kpi::before{content:"";position:absolute;top:-1px;left:-1px;width:5px;height:5px;
  border-top:1px solid var(--acid);border-left:1px solid var(--acid)}
.kpi b{display:block;font-size:1.35rem;font-weight:700;font-variant-numeric:tabular-nums;
  line-height:1.1;color:#eafff2}
.kpi span{display:block;margin-top:.15rem;font-size:.58rem;text-transform:uppercase;
  letter-spacing:.14em;color:var(--dim)}
.kpi.ok b{color:var(--ok);text-shadow:0 0 14px rgba(0,255,156,.35)}
.kpi.warn b{color:var(--med)}
.kpi.bad b{color:var(--crit);text-shadow:0 0 14px rgba(255,45,85,.3)}

/* share labels */
.legend i{font-style:normal;color:var(--dim);font-size:.64rem;min-width:2.2rem;text-align:right}
.cat-list i{font-style:normal;color:var(--dim);font-size:.62rem;text-align:right}
.cat-list li{grid-template-columns:12rem 1fr 2.2rem 2.4rem}

/* header lockup */
.lockup{display:flex;align-items:center;gap:1.1rem;margin:1.4rem 0 .2rem}
.logo-mark{width:76px;height:76px;flex:none;color:var(--acid);
  filter:drop-shadow(0 0 14px rgba(0,255,156,.35))}
.lockup-text{display:flex;flex-direction:column;gap:.2rem}
.wordmark{display:flex;align-items:baseline;gap:.55rem;font-size:1.5rem;font-weight:700;
  letter-spacing:.34em;color:var(--acid);text-shadow:0 0 20px rgba(0,255,156,.4)}
.wordmark .ver{font-size:.62rem;letter-spacing:.1em;color:var(--dim);font-weight:400}
.tagline{font-size:.6rem;letter-spacing:.28em;text-transform:uppercase;color:var(--dim)}
.side-brand .ico{width:20px;height:20px}
@media(max-width:720px){
  .logo-mark{width:56px;height:56px}
  .wordmark{font-size:1.1rem;letter-spacing:.24em}
}

@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{animation:none!important;transition:none!important}
  .cat-fill,.lang-fill,.risk-fill{width:var(--w)}
}
@media(max-width:1000px){
  .app{flex-direction:column}
  .side{position:static;height:auto;width:100%;border-right:0;
    border-bottom:1px solid var(--line);flex-direction:row;flex-wrap:wrap;align-items:center}
  .side nav{flex-direction:row;flex-wrap:wrap}
  .side-foot{margin-top:0;border-top:0}
}
@media(max-width:720px){
  header,section,footer{padding:1rem}
  .cat-list li{grid-template-columns:8.5rem 1fr 1.8rem}
  .langs li{grid-template-columns:5.5rem 1fr 4.5rem}
}
"##;
