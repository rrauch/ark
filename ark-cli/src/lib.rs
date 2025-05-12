use anyhow::bail;
use ark_core::{ArkSeed, HelmKey, ProgressReport, ProgressStatus};
use colored::Colorize;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Formatter};
use std::str::FromStr;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncBufReadExt, BufReader};
use zeroize::{Zeroize, ZeroizeOnDrop};

static WAITING_STYLE: Lazy<ProgressStyle> = Lazy::new(|| {
    ProgressStyle::default_bar()
        .template("{prefix} {spinner:.dim.green} {msg:.dim}")
        .expect("Failed to create progress style template")
});

static ACTIVE_STYLE: Lazy<ProgressStyle> = Lazy::new(|| {
    ProgressStyle::default_bar()
        .template("{prefix} {spinner:.green} {msg} ({pos}/{len}) [{elapsed_precise}] {wide_bar:.cyan/blue}")
        .expect("Failed to create progress style template")
        .progress_chars("=> ")
});

static SUCCESS_STYLE: Lazy<ProgressStyle> = Lazy::new(|| {
    ProgressStyle::default_bar()
        .template("{prefix} ✅ {msg} ({pos}/{len}) [{elapsed_precise}]")
        .expect("Failed to create progress style template")
});

static FAILURE_STYLE: Lazy<ProgressStyle> = Lazy::new(|| {
    ProgressStyle::default_bar()
        .template("{prefix} ❌ {msg} ({pos}/{len}) [{elapsed_precise}]")
        .expect("Failed to create progress style template")
});

pub struct ProgressView {
    multi_progress: MultiProgress,
    bars: HashMap<usize, (ProgressBar, Option<ProgressStatus>)>,
    last_tick: SystemTime,
    refresh_frequency: Duration,
}

impl ProgressView {
    pub fn new(initial_report: &ProgressReport, refresh_frequency: Duration) -> Self {
        let mut view = ProgressView {
            multi_progress: MultiProgress::new(),
            bars: HashMap::new(),
            last_tick: SystemTime::now(),
            refresh_frequency,
        };

        view.process(initial_report, &mut 0, 0, &mut HashSet::new());
        view
    }

    /// Updates the progress display based on the provided `current_report`.
    /// Call this method repeatedly with the latest Report state.
    pub fn update(&mut self, current_report: &ProgressReport) {
        let mut visited = HashSet::new();

        // Recursively process the report tree to update or create bars
        self.process(current_report, &mut 0, 0, &mut visited);

        // Clean up bars for reports that no longer exist in the current_report
        let mut stale_ids = Vec::new();
        for id in self.bars.keys() {
            if !visited.contains(id) {
                stale_ids.push(*id);
            }
        }

        for id in stale_ids {
            if let Some((pb, _)) = self.bars.remove(&id) {
                // Finishes the bar and it will be removed from MultiProgress display.
                pb.finish_and_clear();
            }
        }
    }

    /// Recursive helper to process each node in the Report tree.
    /// This is called by both `new` (via initial processing) and `update`.
    fn process(
        &mut self,
        report: &ProgressReport,
        idx: &mut usize,
        depth: usize,
        visited: &mut HashSet<usize>,
    ) {
        *idx += 1;
        let report_id = report.id();
        visited.insert(report_id);

        let indent = "  ".repeat(depth);
        let label_text = report.label().unwrap_or("");
        let message = format!("{}", label_text);

        let total = report.total() as u64;
        let completed = report.completed() as u64;

        // Check if an existing bar needs full recreation.
        // This happens if a task was finished (SUCCESS/FAILURE) but is now WAITING/ACTIVE again.
        let needs_recreation = if let Some((pb, _)) = self.bars.get(&report_id) {
            pb.is_finished()
                && (report.status() == ProgressStatus::ACTIVE
                    || report.status() == ProgressStatus::WAITING)
        } else {
            false
        };

        if needs_recreation {
            if let Some((old_pb, _)) = self.bars.remove(&report_id) {
                old_pb.finish_and_clear();
            }
        }

        if !self.bars.contains_key(&report_id) {
            let pb = self
                .multi_progress
                .insert(*idx - 1, ProgressBar::new(total).with_prefix(indent));
            self.bars.insert(report_id, (pb, None));
        }

        let (pb, status) = self.bars.get_mut(&report_id).expect("bar to be there");

        let status_changed = status.map(|s| s != report.status()).unwrap_or(true);
        *status = Some(report.status());

        match report.status() {
            ProgressStatus::WAITING => {
                if status_changed {
                    pb.reset_elapsed();
                    pb.set_style(WAITING_STYLE.clone());
                }
            }
            ProgressStatus::ACTIVE => {
                if status_changed {
                    pb.reset_elapsed();
                    pb.set_style(ACTIVE_STYLE.clone());
                }
            }
            ProgressStatus::SUCCESS => {
                if !pb.is_finished() {
                    pb.set_style(SUCCESS_STYLE.clone());
                    pb.finish_with_message(format!("{}", message));
                }
            }
            ProgressStatus::FAILURE => {
                if !pb.is_finished() {
                    pb.set_style(FAILURE_STYLE.clone());
                    pb.abandon_with_message(format!("{}", message));
                }
            }
        }

        if !pb.is_finished() {
            if pb.length().is_none() || pb.length().unwrap() != total {
                pb.set_length(total);
            }

            if pb.position() != completed {
                pb.set_position(completed);
            }

            if pb.message() != message {
                pb.set_message(message);
            }
        }

        // Recurse for subreports
        for sub_report in report.subreports() {
            self.process(sub_report, idx, depth + 1, visited);
        }

        self.tick();
    }

    /// Finishes all active progress bars and clears them from the MultiProgress display.
    /// Call this when the entire task represented by this view is complete and display should be removed.
    pub fn clear(&mut self) {
        for (_id, (pb, status)) in self.bars.drain() {
            // .drain() consumes the items
            if !pb.is_finished() {
                let current_msg = pb.message().to_string();
                if let Some(ProgressStatus::FAILURE) = status {
                    pb.abandon_with_message(current_msg);
                } else {
                    pb.finish_with_message(format!("{} ✓", current_msg,));
                }
            } else {
                // If already finished, ensure it's cleared from display.
                // finish_and_clear() is idempotent for the bar's state but good for MP.
                pb.finish_and_clear();
            }
        }
        // self.active_bars is now empty.

        // Clears all bars from the MultiProgress display.
        if let Err(e) = self.multi_progress.clear() {
            eprintln!("Error clearing MultiProgress: {}", e); // Log appropriately
        }
    }

    pub fn tick(&mut self) {
        for (pb, _) in self.bars.values() {
            if !pb.is_finished() {
                pb.tick();
            }
        }
        self.last_tick = SystemTime::now();
    }

    pub fn next_tick_in(&self) -> Duration {
        self.last_tick
            .checked_add(self.refresh_frequency)
            .expect("adding duration should work")
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::from_millis(0))
    }
}

pub async fn ask_confirmation(question: &str) -> bool {
    let mut reader = BufReader::new(tokio::io::stdin());
    let mut line = String::new();
    loop {
        println!("{}", question);
        match reader.read_line(&mut line).await {
            Ok(_) => {
                let resp = line.trim();
                if resp.eq_ignore_ascii_case("y") || resp.eq_ignore_ascii_case("yes") {
                    return true;
                }
                if resp.eq_ignore_ascii_case("n") || resp.eq_ignore_ascii_case("no") {
                    return false;
                }
                println!("{}", "Only y/n accepted, please try again".red());
            }
            Err(_) => return false,
        }
        line.clear();
    }
}

pub async fn press_enter_key() {
    println!();
    println!("  {}", "Press Enter to continue".dimmed());
    println!();
    let mut reader = BufReader::new(tokio::io::stdin());
    let mut line = String::new();
    let _ = reader.read_line(&mut line).await;
}

#[derive(Zeroize, ZeroizeOnDrop, Clone)]
struct ConfidentialStrings(Vec<String>);

impl From<Vec<String>> for ConfidentialStrings {
    fn from(value: Vec<String>) -> Self {
        Self(value)
    }
}

impl Debug for ConfidentialStrings {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "<redacted>[{}]", self.0.len())
    }
}

impl AsRef<Vec<String>> for ConfidentialStrings {
    fn as_ref(&self) -> &Vec<String> {
        &self.0
    }
}

impl AsMut<Vec<String>> for ConfidentialStrings {
    fn as_mut(&mut self) -> &mut Vec<String> {
        &mut self.0
    }
}

pub async fn read_seed() -> anyhow::Result<ArkSeed> {
    let mut seed_words = ConfidentialStrings::from(Vec::with_capacity(24));
    loop {
        // Use spawn_blocking to run the synchronous rpassword
        let input = tokio::task::spawn_blocking(|| rpassword::read_password()).await??;

        seed_words.as_mut().extend(
            input
                .trim()
                .split_whitespace()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
        );

        if seed_words.as_ref().len() == 24 {
            break;
        } else if seed_words.as_ref().len() > 24 {
            bail!("invalid seed, exactly 24 words are expected");
        }
    }
    Ok(ArkSeed::try_from_mnemonic(seed_words.as_ref().join(" "))?)
}

pub async fn read_helm_key() -> anyhow::Result<HelmKey> {
    let input = tokio::task::spawn_blocking(|| rpassword::read_password()).await??;
    Ok(HelmKey::from_str(input.trim())?)
}
