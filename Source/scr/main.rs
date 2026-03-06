use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::{
    fs,
    signal,
    sync::watch,
    time::sleep,
};
use tracing::{debug, error, info, warn};


const FLAGS_RAW: &str = include_str!("../flags.txt");
#[derive(Debug, Clone)]
struct Config {
    webhook_valid:   String,
    webhook_flagged: String,
    servers:         Vec<String>,
    start_id:        u64,
    state_file:      PathBuf,
    poll_interval:   Duration,
    webhook_delay:   Duration,
    api_timeout:     Duration,
    log_file:        PathBuf,
}

impl Config {
    fn from_env() -> Result<Self> {
        let webhook_valid   = require("WEBHOOK_VALID")?;
        let webhook_flagged = require("WEBHOOK_FLAGGED")?;
        let servers_raw     = require("SERVERS")?;
        let servers: Vec<String> = servers_raw
            .split(',')
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if servers.is_empty() {
            anyhow::bail!("SERVERS must contain at least one URL");
        }

        Ok(Self {
            webhook_valid,
            webhook_flagged,
            servers,
            start_id:      std::env::var("START_ID").ok().and_then(|v| v.parse().ok()).unwrap_or(0),
            state_file:    env_or("STATE_FILE", "user_state.json").into(),
            poll_interval: secs(env_f64("POLL_INTERVAL", 15.0)),
            webhook_delay: secs(env_f64("WEBHOOK_DELAY", 1.8)),
            api_timeout:   secs(env_f64("API_TIMEOUT",   10.0)),
            log_file:      env_or("LOG_FILE", "flagged.log").into(),
        })
    }
}

fn require(k: &str) -> Result<String> {
    std::env::var(k).with_context(|| format!("Missing required env var: {k}"))
}
fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}
fn env_f64(k: &str, d: f64) -> f64 {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}
fn secs(s: f64) -> Duration {
    Duration::from_millis((s * 1000.0) as u64)
}

struct FlagList {
    terms: Vec<String>,
}

impl FlagList {
    fn build() -> Self {
        let terms = FLAGS_RAW
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| normalise(l))
            .collect();
        Self { terms }
    }
    fn check(&self, username: &str) -> Vec<String> {
        let norm = normalise(username);
        let stripped = norm.chars().filter(|c| c.is_alphanumeric()).collect::<String>();

        self.terms
            .iter()
            .filter(|term| {
                let term_stripped: String = term.chars().filter(|c| c.is_alphanumeric()).collect();
                norm.contains(term.as_str()) || stripped.contains(term_stripped.as_str())
            })
            .cloned()
            .collect()
    }
}

const LEET: &[(char, char)] = &[
    ('4', 'a'), ('@', 'a'),
    ('8', 'b'),
    ('(', 'c'),
    ('3', 'e'),
    ('9', 'g'),
    ('1', 'i'), ('!', 'i'), ('|', 'i'),
    ('0', 'o'),
    ('5', 's'), ('$', 's'),
    ('7', 't'),
    ('2', 'z'),
    ('+', 't'),
    ('<', 'c'),
    ('6', 'g'),
];

fn normalise(s: &str) -> String {
    let folded: String = s
        .chars()
        .flat_map(|c| {
            let mut buf = [0u8; 4];
            c.encode_utf8(&mut buf);
            unicode_fold(c)
        })
        .collect();
    let lower = folded.to_lowercase();
    lower
        .chars()
        .map(|c| {
            LEET.iter()
                .find(|(leet, _)| *leet == c)
                .map(|(_, normal)| *normal)
                .unwrap_or(c)
        })
        .collect()
}

fn unicode_fold(c: char) -> Vec<char> {
    let mapped = match c {
        'а' => 'a', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'с' => 'c',
        'х' => 'x', 'у' => 'y', 'і' => 'i', 'ї' => 'i', 'ѕ' => 's',
        'А' => 'A', 'В' => 'B', 'Е' => 'E', 'К' => 'K', 'М' => 'M',
        'Н' => 'H', 'О' => 'O', 'Р' => 'P', 'С' => 'C', 'Т' => 'T',
        'Х' => 'X',
        'α' => 'a', 'β' => 'b', 'ε' => 'e', 'ο' => 'o', 'ρ' => 'p',
        'à'|'á'|'â'|'ã'|'ä'|'å'|'æ' => 'a',
        'ç' => 'c',
        'è'|'é'|'ê'|'ë' => 'e',
        'ì'|'í'|'î'|'ï' => 'i',
        'ñ' => 'n',
        'ò'|'ó'|'ô'|'õ'|'ö'|'ø' => 'o',
        'ù'|'ú'|'û'|'ü' => 'u',
        'ý'|'ÿ' => 'y',
        'ß' => return vec!['s', 's'],
        'đ' => 'd',
        'ł' => 'l',
        'š' => 's',
        'ž' => 'z',
        'č' => 'c',
        'ć' => 'c',
        'ń' => 'n',
        'ź'|'ż' => 'z',
        other => other,
    };
    vec![mapped]
}

struct BotDetector {
    history: VecDeque<String>,
}

impl BotDetector {
    fn new() -> Self {
        Self { history: VecDeque::with_capacity(31) }
    }
    fn check(&mut self, username: &str) -> Option<String> {
        let norm = normalise(username);
        let reason = self.analyse(&norm);
        if self.history.len() == 30 {
            self.history.pop_front();
        }
        self.history.push_back(norm);
        reason
    }

    fn analyse(&self, norm: &str) -> Option<String> {
        if let Some((base, num)) = split_trailing_number(norm) {
            for prev in &self.history {
                if let Some((prev_base, prev_num)) = split_trailing_number(prev) {
                    if prev_base == base && num.abs_diff(prev_num) <= 2 {
                        return Some(format!("Sequential pattern: `{base}###`"));
                    }
                }
            }
        }
        for prev in &self.history {
            let sim = similarity(norm, prev);
            if sim >= 0.85 && norm != prev {
                return Some(format!("High similarity to recent username `{prev}` ({:.0}%)", sim * 100.0));
            }
        }

        if let Some((base, _)) = split_trailing_number(norm) {
            let base_count = self.history.iter()
                .filter(|p| split_trailing_number(p).map(|(b, _)| b == base).unwrap_or(false))
                .count();
            if base_count >= 2 {
                return Some(format!("Repeated base `{base}` in recent window ({} matches)", base_count));
            }
        }

        None
    }
}

fn split_trailing_number(s: &str) -> Option<(String, u64)> {
    let chars: Vec<char> = s.chars().collect();
    let num_start = chars.iter().rposition(|c| !c.is_ascii_digit())?;
    let base: String = chars[..=num_start].iter().collect();
    let num_str: String = chars[num_start + 1..].iter().collect();
    if num_str.is_empty() || num_str.len() > 8 { return None; }
    let num = num_str.parse::<u64>().ok()?;
    Some((base, num))
}

fn similarity(a: &str, b: &str) -> f64 {
    let la = a.chars().count();
    let lb = b.chars().count();
    if la == 0 && lb == 0 { return 1.0; }
    let max = la.max(lb);
    let dist = levenshtein(a, b);
    1.0 - (dist as f64 / max as f64)
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (la, lb) = (a.len(), b.len());
    let mut dp = vec![0usize; lb + 1];
    for j in 0..=lb { dp[j] = j; }
    for i in 1..=la {
        let mut prev = i - 1;
        dp[0] = i;
        for j in 1..=lb {
            let old = dp[j];
            dp[j] = if a[i-1] == b[j-1] {
                prev
            } else {
                1 + dp[j].min(dp[j-1]).min(prev)
            };
            prev = old;
        }
    }
    dp[lb]
}

#[derive(Debug, Deserialize)]
struct UserListResponse {
    data: Option<Vec<UserEntry>>,
}

#[derive(Debug, Deserialize, Clone)]
struct UserEntry {
    id:       u64,
    username: String,
}

#[derive(Serialize, Deserialize, Default)]
struct State(HashMap<String, u64>);

impl State {
    async fn load(path: &PathBuf) -> Self {
        fs::read_to_string(path).await
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    async fn save(&self, path: &PathBuf) -> Result<()> {
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, serde_json::to_string_pretty(self)?).await?;
        fs::rename(&tmp, path).await?;
        Ok(())
    }

    fn latest(&self, server: &str, fallback: u64) -> u64 {
        // State file always wins; START_ID is only used when no state exists yet
        self.0.get(server).copied().unwrap_or(fallback)
    }

    fn set(&mut self, server: &str, id: u64) {
        self.0.insert(server.to_string(), id);
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Verdict {
    Clean,
    Flagged,
    Bot,
    FlaggedBot,
}

impl Verdict {
    fn color(self) -> u32 {
        match self {
            Verdict::Clean      => 0x3F5F4A, // muted green
            Verdict::Flagged    => 0x7A3E3E, // muted red
            Verdict::Bot        => 0x4B4F7A, // muted indigo
            Verdict::FlaggedBot => 0x7A4F1A, // amber-brown
        }
    }

    fn label(self) -> &'static str {
        match self {
            Verdict::Clean      => "Clean",
            Verdict::Flagged    => "Flagged",
            Verdict::Bot        => "Bot",
            Verdict::FlaggedBot => "Flagged + Bot",
        }
    }

    fn is_bad(self) -> bool {
        self != Verdict::Clean
    }
}

fn build_embed(user: &UserEntry, server: &str, verdict: Verdict, hits: &[String], bot_reason: Option<&str>) -> Value {
    let profile_url = format!("{server}/profile/{}/", user.id);

    let reason_parts: Vec<String> = {
        let mut v = vec![];
        if !hits.is_empty() {
            v.push(format!("Terms: {}", hits.join(", ")));
        }
        if let Some(r) = bot_reason {
            v.push(format!("Bot: {r}"));
        }
        v
    };
    let reason = if reason_parts.is_empty() { "None".to_string() } else { reason_parts.join(" | ") };

    json!({
        "author": {
            "name": user.username,
            "url":  profile_url
        },
        "color": verdict.color(),
        "fields": [
            { "name": "Verdict",   "value": verdict.label(),           "inline": true  },
            { "name": "User ID",   "value": user.id.to_string(),        "inline": true  },
            { "name": "Server",    "value": server,                     "inline": true  },
            { "name": "Reason",    "value": reason,                     "inline": false },
            { "name": "Timestamp", "value": Utc::now().format("%d %b %Y · %H:%M UTC").to_string(), "inline": false }
        ]
    })
}

async fn send_webhook(client: &Client, url: &str, embed: Value, delay: Duration) -> Result<()> {
    sleep(delay).await;
    let payload = json!({ "embeds": [embed], "allowed_mentions": { "parse": [] } });

    for attempt in 0u32..4 {
        let res = client.post(url).json(&payload).send().await?;
        match res.status().as_u16() {
            200..=299 => return Ok(()),
            429 => {
                let wait = res.json::<Value>().await
                    .ok()
                    .and_then(|v| v["retry_after"].as_f64())
                    .unwrap_or(1.0);
                warn!("Rate limited, waiting {wait:.1}s");
                sleep(secs(wait)).await;
            }
            code => {
                let backoff = Duration::from_secs(2u64.pow(attempt));
                warn!("Webhook returned {code}, retrying in {backoff:?}");
                sleep(backoff).await;
            }
        }
    }
    anyhow::bail!("Webhook failed after 4 attempts");
}

async fn append_log(path: &PathBuf, user: &UserEntry, server: &str, verdict: Verdict, hits: &[String], bot_reason: Option<&str>) {
    let line = format!(
        "{} | {} | {} | id:{} | verdict:{} | flags:[{}] | bot:{}\n",
        Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
        server,
        user.username,
        user.id,
        verdict.label(),
        hits.join(", "),
        bot_reason.unwrap_or("no"),
    );
    use std::io::Write;
    match std::fs::OpenOptions::new().create(true).append(true).open(path) {
        Ok(mut f) => { let _ = f.write_all(line.as_bytes()); }
        Err(e)    => error!("Failed to write log: {e}"),
    }
}

async fn process_user(
    user:     &UserEntry,
    server:   &str,
    flags:    &FlagList,
    detector: &mut BotDetector,
    cfg:      &Config,
    client:   &Client,
) {
    let hits       = flags.check(&user.username);
    let bot_reason = detector.check(&user.username);

    let verdict = match (hits.is_empty(), bot_reason.is_none()) {
        (true,  true)  => Verdict::Clean,
        (false, true)  => Verdict::Flagged,
        (true,  false) => Verdict::Bot,
        (false, false) => Verdict::FlaggedBot,
    };

    let embed = build_embed(user, server, verdict, &hits, bot_reason.as_deref());
    let webhook_url = if verdict.is_bad() { &cfg.webhook_flagged } else { &cfg.webhook_valid };

    if let Err(e) = send_webhook(client, webhook_url, embed, cfg.webhook_delay).await {
        error!("[{server}] Webhook failed for {}: {e}", user.id);
    }

    if verdict.is_bad() {
        append_log(&cfg.log_file, user, server, verdict, &hits, bot_reason.as_deref()).await;
        info!("[{server}] {} -- {} ({})", user.username, verdict.label(),
            hits.first().map(|s| s.as_str()).or(bot_reason.as_deref()).unwrap_or("?"));
    } else {
        info!("[{server}] {} (id:{}) -- Clean", user.username, user.id);
    }
}

async fn poll_server(
    client:   &Client,
    server:   &str,
    state:    &mut State,
    flags:    &FlagList,
    detector: &mut BotDetector,
    cfg:      &Config,
) -> Result<()> {
    let latest = state.latest(server, cfg.start_id);
    let mut all_new: Vec<UserEntry> = Vec::new();
    let mut page = 1u32;
    loop {
        let url = format!("{server}/user/?page={page}&count=400");
        let resp: UserListResponse = client.get(&url).send().await?.json().await?;
        let entries = resp.data.unwrap_or_default();

        if entries.is_empty() {
            break;
        }

        let min_id = entries.iter().map(|u| u.id).min().unwrap_or(0);
        let new_entries: Vec<UserEntry> = entries.into_iter().filter(|u| u.id > latest).collect();

        debug!("[{server}] Page {page}: {} entries, min_id={min_id}", new_entries.len());

        let done = new_entries.is_empty() || min_id <= latest;
        all_new.extend(new_entries);

        if done {
            break;
        }

        page += 1;
    }

    if all_new.is_empty() {
        debug!("[{server}] No new users since ID {latest}");
        return Ok(());
    }
    all_new.sort_by_key(|u| u.id);
    info!("[{server}] {} new user(s), IDs {}..{}", all_new.len(),
        all_new.first().unwrap().id, all_new.last().unwrap().id);

    for user in all_new {
        process_user(&user, server, flags, detector, cfg, client).await;
        state.set(server, user.id);
        state.save(&cfg.state_file).await
            .unwrap_or_else(|e| error!("State save failed: {e}"));
    }

    Ok(())
}

async fn run(cfg: Arc<Config>, flags: Arc<FlagList>, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    let client = Client::builder()
        .timeout(cfg.api_timeout)
        .user_agent("kogama-user-monitor/1.0")
        .build()?;

    let mut state = State::load(&cfg.state_file).await;
    // One bot detector per server to avoid cross-server false positives
    let mut detectors: HashMap<String, BotDetector> = cfg.servers.iter()
        .map(|s| (s.clone(), BotDetector::new()))
        .collect();

    info!("User monitor running across {} server(s). Ctrl-C to stop.", cfg.servers.len());
    info!("Flag list: {} terms loaded.", flags.terms.len());
    for server in &cfg.servers {
        let id = state.latest(server, cfg.start_id);
        info!("[{server}] Resuming from ID {id}");
    }

    loop {
        if *shutdown.borrow() {
            info!("Shutdown received, saving state...");
            state.save(&cfg.state_file).await?;
            break;
        }

        for server in &cfg.servers {
            let detector = detectors.get_mut(server).unwrap();
            if let Err(e) = poll_server(&client, server, &mut state, &flags, detector, &cfg).await {
                warn!("[{server}] Poll error: {e}");
            }
        }

        state.save(&cfg.state_file).await
            .unwrap_or_else(|e| error!("State save failed: {e}"));

        tokio::select! {
            _ = sleep(cfg.poll_interval) => {}
            _ = shutdown.changed() => {}
        }
    }

    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "user_monitor=info".parse().unwrap()),
        )
        .with_target(false)
        .init();

    let cfg   = Arc::new(Config::from_env().context("Failed to load configuration")?);
    let flags = Arc::new(FlagList::build());

    let (tx, rx) = watch::channel(false);
    let handle = tokio::spawn(run(cfg, flags, rx));

    signal::ctrl_c().await?;
    let _ = tx.send(true);
    handle.await??;
    Ok(())
}
