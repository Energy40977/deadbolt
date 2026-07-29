use std::io::{self, IsTerminal};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::Result;
use dialoguer::console::{colors_enabled, style, Term};
use dialoguer::theme::ColorfulTheme;
use dialoguer::Select;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

use crate::discover::Inventory;

pub const BANNER: &str = r"
   ▄▄████▄▄   ██████╗ ███████╗ █████╗ ██████╗ ██████╗  ██████╗ ██╗  ████████╗
  ▄████████▄  ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔═══██╗██║  ╚══██╔══╝
  ██  ██  ██  ██║  ██║█████╗  ███████║██║  ██║██████╔╝██║   ██║██║     ██║
  ██  ██  ██  ██║  ██║██╔══╝  ██╔══██║██║  ██║██╔══██╗██║   ██║██║     ██║
  ▀██▄▟▙▄██▀  ██████╔╝███████╗██║  ██║██████╔╝██████╔╝╚██████╔╝███████╗██║
   ██║║║║██   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝╚═╝
";

pub fn interactive() -> bool {
    io::stderr().is_terminal() && io::stdin().is_terminal()
}

fn rule() -> String {
    format!("  {}", style("─".repeat(68)).dim())
}

/// Vertical gradient over the banner.
///
/// One flat colour makes block art read as a solid slab. Interpolating per row
/// puts a highlight on the cranium and lets the jaw and the wordmark shadow fall
/// away, which is what gives the glyphs depth in a terminal that has no shading.
/// Truecolor escapes are written directly: `console` exposes the 256-colour cube
/// only, and the 24-bit ramp is what makes the steps invisible.
fn gradient(text: &str, top: (u8, u8, u8), bottom: (u8, u8, u8)) -> String {
    let lines: Vec<&str> = text.lines().collect();
    if !colors_enabled() {
        return text.to_string();
    }
    let last = lines.len().saturating_sub(1).max(1) as f64;
    lines
        .iter()
        .enumerate()
        .map(|(index, line)| {
            let t = index as f64 / last;
            let mix = |from: u8, to: u8| {
                (from as f64 + (to as f64 - from as f64) * t)
                    .round()
                    .clamp(0.0, 255.0) as u8
            };
            format!(
                "\x1b[1m\x1b[38;2;{};{};{}m{line}\x1b[0m",
                mix(top.0, bottom.0),
                mix(top.1, bottom.1),
                mix(top.2, bottom.2),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn welcome(version: &str) {
    // Light from above: near-white at the cranium, acid green through the middle,
    // deep teal where the wordmark's shadow sits.
    eprintln!("{}", gradient(BANNER, (214, 255, 233), (0, 138, 92)));
    eprintln!(
        "  {}  {}  {}",
        style(format!("v{version}")).green(),
        style("·").dim(),
        style("Security And Compliance Audit For Any Codebase").white()
    );
    eprintln!("{}", rule());
}

pub fn project_summary(target: &Path, inventory: &Inventory, claude: Option<&Path>) {
    let field = |name: &str, value: String| {
        eprintln!(
            "  {} {:<18}{}",
            style("▸").green(),
            style(name).dim(),
            style(value).white()
        );
    };

    let languages: Vec<String> = inventory
        .stack
        .languages
        .iter()
        .take(4)
        .map(|language| format!("{} ({})", language.name, language.lines))
        .collect();

    field("Target", target.display().to_string());
    field(
        "Size",
        format!(
            "{} Files · {} Lines",
            inventory.stack.total_files, inventory.stack.total_lines
        ),
    );
    if !languages.is_empty() {
        field("Languages", languages.join(", "));
    }
    if !inventory.stack.frameworks.is_empty() {
        let shown: Vec<&str> = inventory
            .stack
            .frameworks
            .iter()
            .take(5)
            .map(String::as_str)
            .collect();
        field("Frameworks", shown.join(", "));
    }
    field(
        "Manifests",
        if inventory.manifests.is_empty() {
            "None".to_string()
        } else {
            inventory.manifests.join(", ")
        },
    );
    field(
        "AI Review",
        match claude {
            Some(_) => "Available".to_string(),
            None => "Unavailable — claude CLI Not Found".to_string(),
        },
    );
    eprintln!("{}", rule());
}

fn theme() -> ColorfulTheme {
    ColorfulTheme {
        active_item_prefix: style("  ▶".to_string()).green().bold(),
        inactive_item_prefix: style("   ".to_string()),
        active_item_style: dialoguer::console::Style::new().green().bold(),
        inactive_item_style: dialoguer::console::Style::new().white(),
        prompt_prefix: style("  ::".to_string()).green().bold(),
        prompt_suffix: style(String::new()),
        success_prefix: style("  ::".to_string()).green(),
        success_suffix: style(String::new()),
        ..ColorfulTheme::default()
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct Answers {
    pub mode: usize,
    pub ai_possible: bool,
    pub budget: Option<String>,
    pub lenses: Vec<String>,
    pub out_dir: Option<String>,
}

pub fn build_argv(target: &str, answers: &Answers) -> Vec<String> {
    let mut argv = vec!["deadbolt".to_string()];
    let ai = answers.mode == 2 && answers.ai_possible;

    argv.push(
        match answers.mode {
            0 => "scan",
            3 => "diff",
            _ => "audit",
        }
        .to_string(),
    );
    argv.push(target.to_string());

    if answers.mode == 1 || (answers.mode == 2 && !answers.ai_possible) {
        argv.push("--no-ai".to_string());
    }
    if ai {
        if let Some(budget) = &answers.budget {
            argv.push("--budget".to_string());
            argv.push(budget.clone());
        }
        if !answers.lenses.is_empty() {
            argv.push("--lens".to_string());
            argv.push(answers.lenses.join(","));
        }
    }

    if let Some(directory) = &answers.out_dir {
        argv.push("--format".to_string());
        argv.push("terminal,html".to_string());
        argv.push("--out".to_string());
        argv.push(directory.clone());
    }
    argv
}

/// Cost tier of a mode. The colour carries the information, so the reader sees
/// which choice spends money before reading the text.
enum Tier {
    /// Free and fast.
    Free,
    /// Free but goes to the network.
    Network,
    /// Spends money.
    Paid,
}

impl Tier {
    fn paint(&self, text: &str) -> String {
        match self {
            Tier::Free => style(text).green().to_string(),
            Tier::Network => style(text).cyan().to_string(),
            Tier::Paid => style(text).yellow().to_string(),
        }
    }
}

const MODES: &[(&str, &str, Tier)] = &[
    ("Quick Scan", "Rules Only · No Network · ~10s", Tier::Free),
    (
        "Scan + Dependencies",
        "Adds CVE Lookup · ~2min",
        Tier::Network,
    ),
    (
        "Full Audit",
        "Adds AI Review · ~10min · Costs Money",
        Tier::Paid,
    ),
    (
        "Changed Lines Only",
        "Git Diff · Pre-Commit · ~5s",
        Tier::Free,
    ),
];

pub fn wizard(
    target: &Path,
    _inventory: &Inventory,
    claude: Option<&Path>,
) -> Result<Option<Vec<String>>> {
    let ai_possible = claude.is_some();
    let items: Vec<String> = MODES
        .iter()
        .map(|(label, detail, tier)| format!("{:<22}{}", label, tier.paint(detail)))
        .collect();

    let selection = Select::with_theme(&theme())
        .with_prompt(format!(
            "Select Mode {}",
            style("(↑↓ Move · Enter Run · Esc Quit)").dim()
        ))
        .items(&items)
        .default(if ai_possible { 1 } else { 0 })
        .interact_on_opt(&Term::stderr())?;

    let mode = match selection {
        Some(mode) => mode,
        None => {
            eprintln!("  {}", style("Cancelled").dim());
            return Ok(None);
        }
    };

    if mode == 2 && !ai_possible {
        eprintln!(
            "  {} claude CLI Not Found — Running Without AI Review",
            style("!").yellow().bold()
        );
    }

    let answers = Answers {
        mode,
        ai_possible,
        budget: None,
        lenses: Vec::new(),
        out_dir: Some("./deadbolt-report".to_string()),
    };
    let argv = build_argv(&target.display().to_string(), &answers);

    eprintln!("{}", rule());
    eprintln!(
        "  {} {}",
        style("$").green().bold(),
        style(argv.join(" ")).white().bold()
    );
    eprintln!("{}", rule());
    Ok(Some(argv))
}

pub struct Progress {
    multi: MultiProgress,
    bar: ProgressBar,
    phase_started: Mutex<Instant>,
    total_started: Instant,
    enabled: bool,
    total_phases: usize,
    index: AtomicUsize,
}

impl Progress {
    pub fn new(enabled: bool, total_phases: usize) -> Self {
        let multi = MultiProgress::new();
        let bar = if enabled {
            let bar = multi.add(ProgressBar::new_spinner());
            bar.set_style(
                ProgressStyle::with_template("  {spinner:.green} {msg}")
                    .unwrap_or_else(|_| ProgressStyle::default_spinner())
                    .tick_strings(&["▰▱▱", "▰▰▱", "▰▰▰", "▱▰▰", "▱▱▰", "▱▱▱"]),
            );
            bar.enable_steady_tick(std::time::Duration::from_millis(110));
            bar
        } else {
            ProgressBar::hidden()
        };
        Self {
            multi,
            bar,
            phase_started: Mutex::new(Instant::now()),
            total_started: Instant::now(),
            enabled,
            total_phases,
            index: AtomicUsize::new(0),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn phase(&self, title: &str) {
        if let Ok(mut started) = self.phase_started.lock() {
            *started = Instant::now();
        }
        let index = self.index.fetch_add(1, Ordering::Relaxed) + 1;
        self.bar.set_message(format!(
            "{} {}",
            style(format!("[{index}/{}]", self.total_phases)).dim(),
            title
        ));
    }

    pub fn done(&self, title: &str, summary: &str) {
        let elapsed = self
            .phase_started
            .lock()
            .map(|started| started.elapsed())
            .unwrap_or_default();
        self.log(&format!(
            "{} {:<22}{:<46}{}",
            style("✔").green().bold(),
            title,
            style(summary).white(),
            style(human_duration(elapsed.as_millis() as u64)).dim()
        ));
    }

    pub fn log(&self, line: &str) {
        if self.enabled {
            self.multi.println(format!("  {line}")).ok();
        }
    }

    pub fn warn(&self, line: &str) {
        self.log(&format!("{} {line}", style("!").yellow().bold()));
    }

    pub fn counter(&self, total: u64, label: &str) -> ProgressBar {
        if !self.enabled {
            return ProgressBar::hidden();
        }
        let bar = self.multi.insert_before(&self.bar, ProgressBar::new(total));
        bar.set_style(
            ProgressStyle::with_template("  {prefix:<12} {bar:26.green/black} {pos}/{len}  {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("▰▰▱"),
        );
        bar.set_prefix(label.to_string());
        bar
    }

    pub fn finish(&self) {
        if self.enabled {
            self.bar.finish_and_clear();
            self.multi
                .println(format!(
                    "  {} Complete In {}",
                    style("✔").green().bold(),
                    style(human_duration(
                        self.total_started.elapsed().as_millis() as u64
                    ))
                    .bold()
                ))
                .ok();
        }
    }
}

pub fn human_duration(millis: u64) -> String {
    if millis < 1000 {
        return format!("{millis}ms");
    }
    let seconds = millis / 1000;
    if seconds < 60 {
        return format!("{}.{}s", seconds, (millis % 1000) / 100);
    }
    format!("{}m {}s", seconds / 60, seconds % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_audit_without_a_cap_passes_no_budget_flag() {
        let answers = Answers {
            mode: 2,
            ai_possible: true,
            out_dir: Some("./audit".to_string()),
            ..Answers::default()
        };
        let argv = build_argv(".", &answers);
        assert!(!argv.contains(&"--budget".to_string()));
        assert!(!argv.contains(&"--no-ai".to_string()));
        assert_eq!(argv[1], "audit");
        assert!(argv.windows(2).any(|pair| pair == ["--out", "./audit"]));
    }

    #[test]
    fn a_cap_and_selected_lenses_reach_the_command_line() {
        let answers = Answers {
            mode: 2,
            ai_possible: true,
            budget: Some("12".to_string()),
            lenses: vec!["authz".to_string(), "crypto".to_string()],
            out_dir: None,
        };
        let argv = build_argv(".", &answers);
        assert!(argv.windows(2).any(|pair| pair == ["--budget", "12"]));
        assert!(argv
            .windows(2)
            .any(|pair| pair == ["--lens", "authz,crypto"]));
        assert!(!argv.contains(&"--format".to_string()));
    }

    #[test]
    fn modes_map_to_the_right_subcommand() {
        let argv = |mode, ai| {
            build_argv(
                ".",
                &Answers {
                    mode,
                    ai_possible: ai,
                    ..Answers::default()
                },
            )
        };
        assert_eq!(argv(0, true)[1], "scan");
        assert_eq!(argv(3, true)[1], "diff");
        assert!(argv(1, true).contains(&"--no-ai".to_string()));
        assert!(argv(2, false).contains(&"--no-ai".to_string()));
        assert!(!argv(2, true).contains(&"--no-ai".to_string()));
    }

    #[test]
    fn the_gradient_keeps_every_row_and_its_text() {
        let plain = "aa\nbb\ncc";
        let painted = gradient(plain, (255, 255, 255), (0, 0, 0));
        assert_eq!(painted.lines().count(), 3);
        for (row, source) in painted.lines().zip(plain.lines()) {
            assert!(row.contains(source), "the row text survives: {row:?}");
        }
    }

    #[test]
    fn durations_read_naturally_at_each_scale() {
        assert_eq!(human_duration(420), "420ms");
        assert_eq!(human_duration(4200), "4.2s");
        assert_eq!(human_duration(125_000), "2m 5s");
    }

    #[test]
    fn a_hidden_progress_never_panics() {
        let progress = Progress::new(false, 4);
        progress.phase("Reading Project");
        progress.done("Reading Project", "36 Files");
        progress.warn("Something");
        let bar = progress.counter(3, "AI");
        bar.inc(1);
        progress.finish();
        assert!(!progress.enabled());
    }

    #[test]
    fn the_wordmark_rows_line_up() {
        let wordmark: Vec<&str> = BANNER
            .lines()
            .filter(|line| line.contains('╗') || line.contains('╚'))
            .collect();
        assert_eq!(wordmark.len(), 6, "the wordmark is six rows");
        let widths: Vec<usize> = wordmark.iter().map(|line| line.chars().count()).collect();
        assert!(
            widths.iter().all(|width| *width >= 60),
            "no wordmark row may be truncated: {widths:?}"
        );
    }

    #[test]
    fn the_banner_fits_a_standard_terminal() {
        let widest = BANNER
            .lines()
            .map(|line| line.chars().count())
            .max()
            .unwrap_or(0);
        assert!(widest <= 80, "the banner must fit 80 columns, got {widest}");
    }

    #[test]
    fn every_banner_row_carries_both_the_skull_and_the_wordmark() {
        let rows: Vec<&str> = BANNER
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        assert_eq!(rows.len(), 6, "the lockup is six rows");
        for row in &rows {
            let chars: Vec<char> = row.chars().collect();
            let left: String = chars.iter().take(13).collect();
            let right: String = chars.iter().skip(13).collect();
            assert!(
                left.contains('█') || left.contains('▀') || left.contains('▄'),
                "the skull column must be drawn on every row: {row:?}"
            );
            // The last wordmark row is its drop shadow, drawn in box glyphs only.
            assert!(
                right.contains('█') || right.contains('╚'),
                "the wordmark must sit on the same row: {row:?}"
            );
        }
    }
}
