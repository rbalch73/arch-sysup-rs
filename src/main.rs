//! Arch-Sysup — Arch Linux GUI system manager (Rust/egui port)
//! Tabs: Updates | Search & Install | Package Info | System Stats | Orphans | Repositories | Mirrors

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui::{self, Color32, FontId, RichText, Vec2};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

// ── Colours ───────────────────────────────────────────────────────────────────

struct Theme {
    bg:         Color32,
    bg_panel:   Color32,
    bg_row_alt: Color32,
    bg_hdr:     Color32,
    bg_log:     Color32,
    fg:         Color32,
    fg_dim:     Color32,
    accent:     Color32,
    border:     Color32,
    btn_bg:     Color32,
    ver_old:    Color32,
    ver_new:    Color32,
    kernel_fg:  Color32,
    kernel_bg:  Color32,
    btn_green:  Color32,
    btn_red:    Color32,
    btn_orange: Color32,
    btn_accent: Color32,
    repo_core:  Color32,
    repo_extra: Color32,
    repo_multi: Color32,
    repo_chaot: Color32,
    repo_aur:   Color32,
    repo_def:   Color32,
    chart1:     Color32,
    chart2:     Color32,
    chart3:     Color32,
}

fn hex(s: &str) -> Color32 {
    let s = s.trim_start_matches('#');
    let r = u8::from_str_radix(&s[0..2], 16).unwrap_or(0);
    let g = u8::from_str_radix(&s[2..4], 16).unwrap_or(0);
    let b = u8::from_str_radix(&s[4..6], 16).unwrap_or(0);
    Color32::from_rgb(r, g, b)
}

impl Theme {
    fn dark() -> Self {
        Self {
            bg:         hex("0e1117"), bg_panel:   hex("161b24"),
            bg_row_alt: hex("12171f"), bg_hdr:     hex("1c2230"),
            bg_log:     hex("0a0e14"), fg:          hex("c9d1d9"),
            fg_dim:     hex("6e7681"), accent:      hex("58a6ff"),
            border:     hex("30363d"), btn_bg:      hex("21262d"),
            ver_old:    hex("f85149"), ver_new:     hex("3fb950"),
            kernel_fg:  hex("ff4444"), kernel_bg:   hex("2d0f0f"),
            btn_green:  hex("238636"), btn_red:     hex("b62324"),
            btn_orange: hex("9a5a00"), btn_accent:  hex("1f4788"),
            repo_core:  hex("e3b341"), repo_extra:  hex("3fb950"),
            repo_multi: hex("39c5cf"), repo_chaot:  hex("58a6ff"),
            repo_aur:   hex("bc8cff"), repo_def:    hex("8b949e"),
            chart1:     hex("58a6ff"), chart2:      hex("3fb950"),
            chart3:     hex("f85149"),
        }
    }
    fn light() -> Self {
        Self {
            bg:         hex("f6f8fa"), bg_panel:   hex("ffffff"),
            bg_row_alt: hex("f0f2f4"), bg_hdr:     hex("e8ecf0"),
            bg_log:     hex("1c1c1c"), fg:          hex("1f2328"),
            fg_dim:     hex("656d76"), accent:      hex("0969da"),
            border:     hex("d0d7de"), btn_bg:      hex("e6edf3"),
            ver_old:    hex("cf222e"), ver_new:     hex("1a7f37"),
            kernel_fg:  hex("cf222e"), kernel_bg:   hex("ffebe9"),
            btn_green:  hex("1a7f37"), btn_red:     hex("cf222e"),
            btn_orange: hex("bc4c00"), btn_accent:  hex("0969da"),
            repo_core:  hex("9a6700"), repo_extra:  hex("1a7f37"),
            repo_multi: hex("0969da"), repo_chaot:  hex("6639ba"),
            repo_aur:   hex("8250df"), repo_def:    hex("57606a"),
            chart1:     hex("0969da"), chart2:      hex("1a7f37"),
            chart3:     hex("cf222e"),
        }
    }
    fn repo_color(&self, repo: &str) -> Color32 {
        match repo.to_lowercase().as_str() {
            "core"        => self.repo_core,
            "extra"       => self.repo_extra,
            "multilib"    => self.repo_multi,
            "chaotic-aur" => self.repo_chaot,
            "aur"         => self.repo_aur,
            _             => self.repo_def,
        }
    }
}

// ── Data types ────────────────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct UpdateEntry {
    pkg:    String,
    repo:   String,
    old:    String,
    new:    String,
    kernel: bool,
}

#[derive(Clone, Default)]
struct SearchResult {
    repo:      String,
    pkg:       String,
    ver:       String,
    desc:      String,
    installed: bool,
    source:    String,
    selected:  bool,
}

#[derive(Clone, Default)]
struct PkgInfo {
    fields:    Vec<(String, String)>,
    files:     String,
    installed: bool,
}

#[derive(Clone, Default)]
struct StatsData {
    pkg_count: String,
    explicit:  String,
    aur_count: String,
    orphans:   String,
    disk_pkg:  String,
    disk_root: String,
    disk_home: String,
    last_upd:  String,
    kernel_ver:String,
    uptime:    String,
    root_used: f32,
    root_total:f32,
    home_used: f32,
    home_total:f32,
}

#[derive(Clone)]
struct RepoSection {
    name:    String,
    enabled: bool,
    lines:   Vec<String>,
    is_opts: bool,
}

#[derive(Clone)]
struct MirrorConf {
    countries:       String,
    proto_https:     bool,
    proto_http:      bool,
    sort:            String,
    latest:          String,
    age:             String,
    timeout:         String,
    ipv4:            bool,
    ipv6:            bool,
}

impl Default for MirrorConf {
    fn default() -> Self {
        Self {
            countries:   String::new(),
            proto_https: true,
            proto_http:  false,
            sort:        "rate".into(),
            latest:      "5".into(),
            age:         "12".into(),
            timeout:     "5".into(),
            ipv4:        false,
            ipv6:        false,
        }
    }
}

// Shared state passed between background threads and the UI
#[derive(Default)]
struct Shared {
    log_lines:    Vec<(String, LogColor)>,
    updates:      Option<Vec<UpdateEntry>>,
    search_res:   Option<Vec<SearchResult>>,
    pkg_info:     Option<(String, Option<PkgInfo>)>, // (pkg_name, result)
    stats:        Option<StatsData>,
    orphans:      Option<Vec<(String, String, String)>>, // (name, ver, desc)
    repo_sections:Option<Vec<RepoSection>>,
    repo_preamble:Vec<String>,
    mirror_status:Option<String>,
    status:       String,
    busy:         bool,
}

#[derive(Clone, Copy, PartialEq)]
enum LogColor { Normal, Dim, Green, Red, Accent, Orange }

// ── Helpers ───────────────────────────────────────────────────────────────────

fn detect_aur_helper() -> Option<String> {
    for h in &["yay", "paru"] {
        if which(h) { return Some(h.to_string()); }
    }
    None
}

fn which(cmd: &str) -> bool {
    Command::new("which").arg(cmd).output()
        .map(|o| o.status.success()).unwrap_or(false)
}

fn run_cmd(args: &[&str]) -> String {
    Command::new(args[0]).args(&args[1..])
        .output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn is_kernel(pkg: &str) -> bool {
    let re_base = regex_simple_kernel(pkg);
    re_base || pkg.starts_with("linux-") && pkg.chars().nth(6).map(|c| c.is_ascii_digit()).unwrap_or(false)
}

fn regex_simple_kernel(pkg: &str) -> bool {
    matches!(pkg, "linux" | "linux-lts" | "linux-zen" | "linux-hardened"
                | "linux-rt" | "linux-cachyos" | "linux-xanmod"
                | "linux-tkg" | "linux-mainline")
}

fn repo_order(repo: &str) -> usize {
    match repo.to_lowercase().as_str() {
        "core" => 0, "extra" => 1, "multilib" => 2,
        "chaotic-aur" => 3, "aur" => 4, _ => 5,
    }
}

fn split_ver_diff(ver: &str, other: &str) -> (String, String) {
    let common = ver.chars().zip(other.chars())
        .take_while(|(a, b)| a == b).count();
    (ver[..common].to_string(), ver[common..].to_string())
}

fn fmt_bytes(mut n: f64) -> String {
    for unit in &["B","KB","MB","GB","TB"] {
        if n < 1024.0 { return format!("{:.1} {}", n, unit); }
        n /= 1024.0;
    }
    format!("{:.1} PB", n)
}

fn verify_sudo(pw: &str) -> bool {
    let mut child = Command::new("sudo")
        .args(["-S", "-v"])
        .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().unwrap();
    if let Some(mut stdin) = child.stdin.take() {
        let _ = writeln!(stdin, "{}", pw);
    }
    child.wait().map(|s| s.success()).unwrap_or(false)
}

fn sudo_cmd_streaming(pw: &str, cmd: &[&str], log: &Arc<Mutex<Shared>>) {
    let mut full = vec!["sudo", "-S", "-p", ""];
    full.extend_from_slice(cmd);
    let mut child = match Command::new(full[0])
        .args(&full[1..])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn() {
            Ok(c) => c,
            Err(e) => {
                push_log(log, &format!("Error: {e}"), LogColor::Red);
                return;
            }
        };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = writeln!(stdin, "{}", pw);
    }
    // Stream stdout
    if let Some(stdout) = child.stdout.take() {
        for line in BufReader::new(stdout).lines().flatten() {
            push_log(log, &line, LogColor::Normal);
        }
    }
    // Also capture stderr
    if let Some(stderr) = child.stderr.take() {
        for line in BufReader::new(stderr).lines().flatten() {
            push_log(log, &line, LogColor::Dim);
        }
    }
    let status = child.wait().unwrap_or_else(|_| {
        // If wait fails, treat as non-zero exit
        Command::new("false").status().unwrap()
    });
    if !status.success() {
        push_log(log, &format!("Exit code: {}", status.code().unwrap_or(-1)), LogColor::Red);
    }
}

fn cmd_streaming(cmd: &[&str], log: &Arc<Mutex<Shared>>) {
    let mut child = match Command::new(cmd[0]).args(&cmd[1..])
        .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
            Ok(c) => c, Err(e) => { push_log(log, &format!("Error: {e}"), LogColor::Red); return; }
        };
    if let Some(stdout) = child.stdout.take() {
        for line in BufReader::new(stdout).lines().flatten() {
            push_log(log, &line, LogColor::Normal);
        }
    }
    if let Some(stderr) = child.stderr.take() {
        for line in BufReader::new(stderr).lines().flatten() {
            push_log(log, &line, LogColor::Dim);
        }
    }
    let _ = child.wait();
}

fn push_log(shared: &Arc<Mutex<Shared>>, line: &str, color: LogColor) {
    if let Ok(mut s) = shared.lock() {
        s.log_lines.push((line.to_string(), color));
    }
}

fn set_status(shared: &Arc<Mutex<Shared>>, msg: &str) {
    if let Ok(mut s) = shared.lock() { s.status = msg.to_string(); }
}

// ── pacman.conf parsing ───────────────────────────────────────────────────────

fn parse_pacman_conf(path: &str) -> (Vec<String>, Vec<RepoSection>) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c, Err(_) => return (vec![], vec![]),
    };
    let mut preamble = vec![];
    let mut sections: Vec<RepoSection> = vec![];
    let mut current: Option<RepoSection> = None;

    for line in content.lines() {
        let s = line.trim();
        if let Some(name) = s.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if let Some(sec) = current.take() { sections.push(sec); }
            let is_opts = name.to_lowercase() == "options";
            current = Some(RepoSection { name: name.to_string(), enabled: true,
                lines: vec![line.to_string() + "\n"], is_opts });
        } else if s.starts_with("#[") && s.ends_with(']') {
            if let Some(sec) = current.take() { sections.push(sec); }
            let name = s[2..s.len()-1].to_string();
            let is_opts = name.to_lowercase() == "options";
            current = Some(RepoSection { name, enabled: false,
                lines: vec![line.to_string() + "\n"], is_opts });
        } else if let Some(ref mut sec) = current {
            sec.lines.push(line.to_string() + "\n");
        } else {
            preamble.push(line.to_string() + "\n");
        }
    }
    if let Some(sec) = current { sections.push(sec); }
    (preamble, sections)
}

fn write_pacman_conf(preamble: &[String], sections: &[RepoSection]) -> String {
    let mut out = String::new();
    for l in preamble { out.push_str(l); }
    for sec in sections {
        if sec.is_opts {
            for l in &sec.lines { out.push_str(l); }
            continue;
        }
        if sec.lines.is_empty() { continue; }
        if sec.enabled {
            out.push_str(&format!("[{}]\n", sec.name));
        } else {
            out.push_str(&format!("#[{}]\n", sec.name));
        }
        for ln in sec.lines.iter().skip(1) {
            let s = ln.trim();
            if sec.enabled {
                // uncomment Include/Server lines
                if s.starts_with('#') {
                    let stripped = s.trim_start_matches('#').trim();
                    if stripped.starts_with("Include =") || stripped.starts_with("Server =") {
                        out.push_str(stripped); out.push('\n'); continue;
                    }
                }
                out.push_str(ln);
            } else {
                if s.starts_with("Include =") || s.starts_with("Server =") {
                    out.push('#'); out.push_str(ln);
                } else {
                    out.push_str(ln);
                }
            }
        }
    }
    out
}

// ── reflector.conf ────────────────────────────────────────────────────────────

const REFLECTOR_CONF: &str = "/etc/xdg/reflector/reflector.conf";
const MANAGED_OPTS: &[&str] = &[
    "--country","--protocol","--sort","--latest",
    "--age","--connection-timeout","--ipv4","--ipv6",
];

fn load_mirror_conf() -> MirrorConf {
    let mut mc = MirrorConf::default();
    let content = match std::fs::read_to_string(REFLECTOR_CONF) {
        Ok(c) => c, Err(_) => return mc,
    };
    let mut proto_https = false;
    let mut proto_http  = false;
    for line in content.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') { continue; }
        if s.starts_with("--country ") { mc.countries = s[10..].trim().to_string(); }
        else if s.starts_with("--protocol ") {
            let v = s[11..].trim();
            proto_https = v.contains("https");
            proto_http  = v.contains("http") && !v.contains("https");
        } else if s.starts_with("--sort ") { mc.sort = s[7..].trim().to_string(); }
        else if s.starts_with("--latest ") { mc.latest = s[9..].trim().to_string(); }
        else if s.starts_with("--age ") { mc.age = s[6..].trim().to_string(); }
        else if s.starts_with("--connection-timeout ") { mc.timeout = s[21..].trim().to_string(); }
        else if s == "--ipv4" { mc.ipv4 = true; }
        else if s == "--ipv6" { mc.ipv6 = true; }
    }
    mc.proto_https = proto_https || !proto_http;
    mc.proto_http  = proto_http;
    mc
}

fn build_mirror_conf(mc: &MirrorConf) -> String {
    // Read existing file, preserve unmanaged lines, replace managed ones
    let existing = std::fs::read_to_string(REFLECTOR_CONF).unwrap_or_default();
    let mut kept = String::new();
    for line in existing.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') { kept.push_str(line); kept.push('\n'); continue; }
        let managed = MANAGED_OPTS.iter().any(|opt| s == *opt || s.starts_with(&format!("{} ", opt)));
        if !managed { kept.push_str(line); kept.push('\n'); }
    }
    let mut managed = String::new();
    if !mc.countries.is_empty() { managed.push_str(&format!("--country {}\n", mc.countries)); }
    let mut protos = vec![];
    if mc.proto_https { protos.push("https"); }
    if mc.proto_http  { protos.push("http"); }
    if !protos.is_empty() { managed.push_str(&format!("--protocol {}\n", protos.join(","))); }
    if !mc.sort.is_empty() { managed.push_str(&format!("--sort {}\n", mc.sort)); }
    if !mc.latest.is_empty() && mc.latest.parse::<u32>().is_ok() {
        managed.push_str(&format!("--latest {}\n", mc.latest));
    }
    if !mc.age.is_empty() { managed.push_str(&format!("--age {}\n", mc.age)); }
    if !mc.timeout.is_empty() { managed.push_str(&format!("--connection-timeout {}\n", mc.timeout)); }
    if mc.ipv4 { managed.push_str("--ipv4\n"); }
    if mc.ipv6 { managed.push_str("--ipv6\n"); }
    kept + &managed
}

fn sudo_write_file(pw: &str, path: &str, content: &str) -> Result<(), String> {
    use std::io::Write;
    let mut tmp = tempfile()?;
    tmp.1.write_all(content.as_bytes()).map_err(|e| e.to_string())?;
    drop(tmp.1);
    let mut child = Command::new("sudo").args(["-S", "-p", "", "cp", &tmp.0, path])
        .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped())
        .spawn().map_err(|e| e.to_string())?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = writeln!(stdin, "{}", pw);
    }
    let status = child.wait().map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&tmp.0);
    if status.success() { Ok(()) } else { Err("sudo cp failed".into()) }
}

fn tempfile() -> Result<(String, std::fs::File), String> {
    let path = format!("/tmp/arch-sysup-{}.tmp", std::process::id());
    let f = std::fs::File::create(&path).map_err(|e| e.to_string())?;
    Ok((path, f))
}

// ── Tab enum ──────────────────────────────────────────────────────────────────

#[derive(PartialEq, Clone, Copy)]
enum Tab { Updates, Search, PkgInfo, Stats, Orphans, Repos, Mirrors }

// ── App state ─────────────────────────────────────────────────────────────────

struct App {
    theme:        Theme,
    dark_mode:    bool,
    tab:          Tab,
    shared:       Arc<Mutex<Shared>>,
    aur_helper:   Option<String>,

    // Updates
    updates:      Vec<UpdateEntry>,
    kernel_found: bool,
    show_reboot:  bool,

    // Search
    search_query: String,
    search_res:   Vec<SearchResult>,

    // Package Info
    info_query:   String,
    pkg_info:     Option<(String, Option<PkgInfo>)>,

    // Stats
    stats:        Option<StatsData>,

    // Orphans
    orphans:      Vec<(String, String, String, bool)>, // (name,ver,desc,selected)

    // Repos
    repo_preamble:Vec<String>,
    repo_sections:Vec<RepoSection>,
    repo_dirty:   bool,
    show_add_repo:bool,
    new_repo_name:String,
    new_repo_inc: String,
    new_repo_err: String,

    // Mirrors
    mirror_conf:      MirrorConf,
    mirror_dirty:     bool,
    mirror_status:    String,

    // Sudo
    sudo_pw:        String,
    sudo_verified:  bool,
    show_sudo:      bool,
    sudo_prompt:    String,
    sudo_error:     String,
    sudo_callback:  Option<SudoCallback>,

    // Confirm dialog
    show_confirm:   bool,
    confirm_msg:    String,
    confirm_action: Option<ConfirmAction>,

    // Log
    show_log:       bool,
    log_lines:      Vec<(String, LogColor)>,

    // Status
    status:         String,
    busy:           bool,
}

type SudoCallback  = Box<dyn FnOnce(&str, &Arc<Mutex<Shared>>, &Option<String>) + Send>;
type ConfirmAction = Box<dyn FnOnce(&mut App) + Send>;

impl App {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let aur = detect_aur_helper();
        let shared = Arc::new(Mutex::new(Shared::default()));

        // Kick off initial update check
        let shared2 = shared.clone();
        let aur2 = aur.clone();
        thread::spawn(move || fetch_updates(&shared2, &aur2));

        Self {
            theme: Theme::dark(), dark_mode: true,
            tab: Tab::Updates, shared, aur_helper: aur,
            updates: vec![], kernel_found: false, show_reboot: false,
            search_query: String::new(), search_res: vec![],
            info_query: String::new(), pkg_info: None,
            stats: None,
            orphans: vec![],
            repo_preamble: vec![], repo_sections: vec![], repo_dirty: false,
            show_add_repo: false, new_repo_name: String::new(),
            new_repo_inc: String::new(), new_repo_err: String::new(),
            mirror_conf: MirrorConf::default(), mirror_dirty: false,
            mirror_status: String::new(),
            sudo_pw: String::new(), sudo_verified: false,
            show_sudo: false, sudo_prompt: String::new(),
            sudo_error: String::new(), sudo_callback: None,
            show_confirm: false, confirm_msg: String::new(), confirm_action: None,
            show_log: false, log_lines: vec![],
            status: "Checking for updates…".into(), busy: true,
        }
    }

    fn toggle_theme(&mut self) {
        self.dark_mode = !self.dark_mode;
        self.theme = if self.dark_mode { Theme::dark() } else { Theme::light() };
    }

    // Sync from shared state into local UI state
    fn poll_shared(&mut self) {
        let Ok(mut s) = self.shared.try_lock() else { return; };
        if !s.status.is_empty() { self.status = s.status.clone(); }
        if !s.log_lines.is_empty() {
            self.log_lines.extend(s.log_lines.drain(..));
            self.show_log = true;
        }
        if let Some(updates) = s.updates.take() {
            self.updates = updates;
            self.kernel_found = self.updates.iter().any(|u| u.kernel);
            self.busy = false;
        }
        if let Some(res) = s.search_res.take() {
            self.search_res = res;
            self.busy = false;
        }
        if let Some(info) = s.pkg_info.take() {
            self.pkg_info = Some(info);
            self.busy = false;
        }
        if let Some(stats) = s.stats.take() {
            self.stats = Some(stats);
            self.busy = false;
        }
        if let Some(orphans) = s.orphans.take() {
            self.orphans = orphans.into_iter().map(|(n,v,d)| (n,v,d,false)).collect();
            self.busy = false;
        }
        if let Some(sections) = s.repo_sections.take() {
            self.repo_sections = sections;
            self.repo_preamble = s.repo_preamble.clone();
            self.repo_dirty = false;
            self.busy = false;
        }
        if s.busy { self.busy = true; }
        if let Some(ms) = s.mirror_status.take() {
            self.mirror_status = ms;
            self.busy = false;
        }
    }

    fn request_sudo<F>(&mut self, prompt: &str, cb: F)
    where F: FnOnce(&str, &Arc<Mutex<Shared>>, &Option<String>) + Send + 'static
    {
        // Re-use cached password if still valid
        if self.sudo_verified && !self.sudo_pw.is_empty() && verify_sudo(&self.sudo_pw) {
            let pw  = self.sudo_pw.clone();
            let sh  = self.shared.clone();
            let aur = self.aur_helper.clone();
            thread::spawn(move || cb(&pw, &sh, &aur));
            return;
        }
        self.sudo_error  = String::new();
        self.sudo_prompt = prompt.to_string();
        self.sudo_callback = Some(Box::new(cb));
        self.show_sudo = true;
    }

    fn submit_sudo(&mut self) {
        let pw = self.sudo_pw.clone();
        if !verify_sudo(&pw) {
            self.sudo_error = "Incorrect password. Please try again.".into();
            self.sudo_pw.clear();
            return;
        }
        self.sudo_verified = true;
        self.show_sudo = false;
        self.sudo_error.clear();
        if let Some(cb) = self.sudo_callback.take() {
            let sh  = self.shared.clone();
            let aur = self.aur_helper.clone();
            thread::spawn(move || cb(&pw, &sh, &aur));
        }
    }

    fn clear_log(&mut self) { self.log_lines.clear(); }
}

// ── Background tasks ──────────────────────────────────────────────────────────

fn fetch_updates(shared: &Arc<Mutex<Shared>>, aur: &Option<String>) {
    if let Ok(mut s) = shared.lock() { s.busy = true; s.status = "Querying packages…".into(); }
    let aur_helper = match aur {
        Some(h) => h.clone(),
        None => {
            set_status(shared, "No AUR helper (yay/paru) found");
            if let Ok(mut s) = shared.lock() { s.busy = false; s.updates = Some(vec![]); }
            return;
        }
    };
    let out = Command::new(&aur_helper).args(["-Qu"])
        .output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let raw = if out.is_empty() {
        set_status(shared, "Syncing DBs…");
        let _ = Command::new("fakeroot").args(["--","pacman","-Sy"]).output();
        Command::new(&aur_helper).args(["-Qu"])
            .output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    } else { out };

    if raw.is_empty() {
        set_status(shared, "System is up to date ✓");
        if let Ok(mut s) = shared.lock() { s.busy = false; s.updates = Some(vec![]); }
        return;
    }

    let mut parsed: Vec<(String,String,String)> = raw.lines().filter_map(|l| {
        let p: Vec<&str> = l.split_whitespace().collect();
        if p.len() >= 4 { Some((p[0].into(), p[1].into(), p[3].into())) } else { None }
    }).collect();

    // Get repo for each package
    let si = Command::new("pacman").arg("-Si")
        .args(parsed.iter().map(|(n,_,_)| n.as_str()))
        .output().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    let mut pkg_repo: std::collections::HashMap<String,String> = Default::default();
    let mut cur_repo = String::new();
    for line in si.lines() {
        if let Some(r) = line.strip_prefix("Repository") {
            cur_repo = r.trim_start_matches(':').trim().to_string();
        } else if let Some(n) = line.strip_prefix("Name") {
            let name = n.trim_start_matches(':').trim().to_string();
            if !name.is_empty() && !cur_repo.is_empty() {
                pkg_repo.insert(name, cur_repo.clone());
            }
        }
    }

    let (_,sections) = parse_pacman_conf("/etc/pacman.conf");
    let has_chaotic = sections.iter().any(|s| s.name.to_lowercase()=="chaotic-aur" && s.enabled);

    let mut updates: Vec<UpdateEntry> = parsed.drain(..).map(|(pkg,old,new)| {
        let repo = pkg_repo.get(&pkg).cloned()
            .unwrap_or_else(|| if has_chaotic { "chaotic-aur".into() } else { "aur".into() });
        let kernel = is_kernel(&pkg);
        UpdateEntry { pkg, repo, old, new, kernel }
    }).collect();
    updates.sort_by(|a,b| repo_order(&a.repo).cmp(&repo_order(&b.repo)).then(a.pkg.cmp(&b.pkg)));

    let count = updates.len();
    set_status(shared, &format!("Ready — {} package{} to update", count, if count==1 {""} else {"s"}));
    if let Ok(mut s) = shared.lock() { s.busy = false; s.updates = Some(updates); }
}

fn do_updates(pw: &str, shared: &Arc<Mutex<Shared>>, aur: &Option<String>,
              has_off: bool, has_aur: bool, kernel_found: bool) {
    if let Ok(mut s) = shared.lock() { s.busy = true; }
    if has_off {
        push_log(shared, "── Official repo updates ──────────────────", LogColor::Dim);
        sudo_cmd_streaming(pw, &["pacman","-Syu","--noconfirm"], shared);
    }
    if has_aur {
        if let Some(h) = aur {
            push_log(shared, "── AUR / chaotic-aur updates ──────────────", LogColor::Dim);
            cmd_streaming(&[h.as_str(),"-Sua","--noconfirm"], shared);
        }
    }
    push_log(shared, "✓ All updates complete.", LogColor::Green);
    if kernel_found {
        push_log(shared, "⚠  Kernel updated — reboot required!", LogColor::Orange);
    }
    // Re-check
    set_status(shared, "Checking for updates…");
    fetch_updates(shared, aur);
}

fn fetch_search(shared: &Arc<Mutex<Shared>>, aur: &Option<String>, query: String) {
    if let Ok(mut s) = shared.lock() { s.busy = true; s.status = "Searching…".into(); }
    let mut results: Vec<SearchResult> = vec![];
    let mut seen: std::collections::HashSet<String> = Default::default();

    let parse_ss = |text: &str, source: &str, results: &mut Vec<SearchResult>, seen: &mut std::collections::HashSet<String>| {
        let lines: Vec<&str> = text.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i].trim_end();
            if !line.is_empty() && !line.starts_with(' ') && line.contains('/') {
                // repo/pkgname version [flags]
                let mut parts = line.splitn(2, '/');
                let repo = parts.next().unwrap_or("").to_string();
                let rest = parts.next().unwrap_or("");
                let mut rp = rest.splitn(2, ' ');
                let pkg = rp.next().unwrap_or("").to_string();
                let verflags = rp.next().unwrap_or("");
                let mut vp = verflags.splitn(2, ' ');
                let ver = vp.next().unwrap_or("").to_string();
                let flags = vp.next().unwrap_or("");
                let installed = flags.contains("[installed]");
                let desc = if i+1 < lines.len() { lines[i+1].trim().to_string() } else { String::new() };
                if !pkg.is_empty() && !seen.contains(&pkg) {
                    seen.insert(pkg.clone());
                    results.push(SearchResult { repo, pkg, ver, desc, installed, source: source.into(), selected: false });
                }
                i += 2;
            } else { i += 1; }
        }
    };

    let r1 = Command::new("pacman").args(["-Ss", &query])
        .output().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    parse_ss(&r1, "pacman", &mut results, &mut seen);

    if let Some(h) = aur {
        let r2 = Command::new(h).args(["-Ss","--aur",&query])
            .output().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
        parse_ss(&r2, "aur", &mut results, &mut seen);
    }

    results.sort_by(|a,b| repo_order(&a.repo).cmp(&repo_order(&b.repo)).then(a.pkg.cmp(&b.pkg)));
    let count = results.len();
    set_status(shared, &format!("{} result{}", count, if count==1 {""} else {"s"}));
    if let Ok(mut s) = shared.lock() { s.busy = false; s.search_res = Some(results); }
}

fn fetch_pkg_info(shared: &Arc<Mutex<Shared>>, aur: &Option<String>, pkg: String) {
    if let Ok(mut s) = shared.lock() { s.busy = true; }
    let local = run_cmd(&["pacman","-Qi",&pkg]);
    let sync  = run_cmd(&["pacman","-Si",&pkg]);
    let raw   = if !local.is_empty() { local.clone() } else { sync };
    let files = if !local.is_empty() { run_cmd(&["pacman","-Ql",&pkg]) } else { String::new() };
    let raw   = if raw.is_empty() {
        aur.as_ref().map(|h| run_cmd(&[h.as_str(),"-Si","--aur",&pkg])).unwrap_or_default()
    } else { raw };

    let info = if raw.is_empty() {
        None
    } else {
        let mut fields: Vec<(String,String)> = vec![];
        let mut last_key = String::new();
        for line in raw.lines() {
            if let Some(colon) = line.find(':') {
                if colon < 30 && !line.starts_with(' ') {
                    let key = line[..colon].trim().to_string();
                    let val = line[colon+1..].trim().to_string();
                    fields.push((key.clone(), val));
                    last_key = key;
                } else if !last_key.is_empty() {
                    if let Some(last) = fields.last_mut() {
                        last.1.push(' '); last.1.push_str(line.trim());
                    }
                }
            } else if !last_key.is_empty() && line.starts_with(' ') {
                if let Some(last) = fields.last_mut() {
                    last.1.push(' '); last.1.push_str(line.trim());
                }
            }
        }
        Some(PkgInfo { fields, files, installed: !local.is_empty() })
    };

    if let Ok(mut s) = shared.lock() { s.busy = false; s.pkg_info = Some((pkg, info)); }
}

fn fetch_stats(shared: &Arc<Mutex<Shared>>) {
    if let Ok(mut s) = shared.lock() { s.busy = true; }
    let mut data = StatsData::default();
    data.pkg_count = run_cmd(&["pacman","-Qq","--color","never"]).lines().count().to_string();
    data.explicit  = run_cmd(&["pacman","-Qqe","--color","never"]).lines().count().to_string();
    data.orphans   = run_cmd(&["pacman","-Qdtq","--color","never"]).lines().filter(|l| !l.is_empty()).count().to_string();

    // AUR count
    if let Ok(total) = data.pkg_count.parse::<usize>() {
        let foreign = run_cmd(&["pacman","-Qqm"]).lines().count();
        data.aur_count = foreign.to_string();
        let _ = total;
    }

    // Disk usage of package cache
    data.disk_pkg = {
        let out = run_cmd(&["du","-sh","/var/cache/pacman/pkg"]);
        out.split_whitespace().next().unwrap_or("n/a").to_string()
    };

    // Disk usage
    let disk_info = |mount: &str| -> (String, f32, f32) {
        let out = Command::new("df").args(["-B1",mount])
            .output().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
        for line in out.lines().skip(1) {
            let p: Vec<&str> = line.split_whitespace().collect();
            if p.len() >= 4 {
                let total = p[1].parse::<f64>().unwrap_or(1.0);
                let used  = p[2].parse::<f64>().unwrap_or(0.0);
                return (format!("{} / {}", fmt_bytes(used), fmt_bytes(total)), used as f32, total as f32);
            }
        }
        ("n/a".into(), 0.0, 1.0)
    };

    let (rt, ru, rtt) = disk_info("/");
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let (ht, hu, htt) = disk_info(&home);
    data.disk_root = rt; data.root_used = ru; data.root_total = rtt;
    data.disk_home = ht; data.home_used = hu; data.home_total = htt;

    // Last update from pacman log
    data.last_upd = std::fs::read_to_string("/var/log/pacman.log")
        .map(|log| {
            log.lines().filter(|l| l.to_lowercase().contains("starting full system upgrade")
                || l.to_lowercase().contains("upgraded "))
                .last()
                .and_then(|l| l.splitn(2,'[').nth(1))
                .and_then(|l| l.get(..10))
                .map(|s| s.to_string())
                .unwrap_or_else(|| "No record".into())
        }).unwrap_or_else(|_| "Unknown".into());

    data.kernel_ver = run_cmd(&["uname","-r"]);
    data.uptime = std::fs::read_to_string("/proc/uptime")
        .map(|s| {
            let secs = s.split_whitespace().next()
                .and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0) as u64;
            let d = secs/86400; let h=(secs%86400)/3600; let m=(secs%3600)/60;
            if d>0 { format!("{}d {}h {}m",d,h,m) } else { format!("{}h {}m",h,m) }
        }).unwrap_or_else(|_| "Unknown".into());

    if let Ok(mut s) = shared.lock() { s.busy = false; s.stats = Some(data); }
}

fn fetch_orphans(shared: &Arc<Mutex<Shared>>) {
    if let Ok(mut s) = shared.lock() { s.busy = true; }
    let raw = run_cmd(&["pacman","-Qdtq"]);
    let pkgs: Vec<String> = raw.lines().filter(|l| !l.is_empty()).map(|l| l.to_string()).collect();
    let mut result: Vec<(String,String,String)> = vec![];
    if !pkgs.is_empty() {
        let args: Vec<&str> = std::iter::once("pacman").chain(std::iter::once("-Qi"))
            .chain(pkgs.iter().map(|s| s.as_str())).collect();
        let si = run_cmd(&args);
        let mut cur_name = String::new(); let mut cur_ver = String::new(); let mut cur_desc = String::new();
        let flush = |name: &str, ver: &str, desc: &str, result: &mut Vec<(String,String,String)>| {
            if !name.is_empty() { result.push((name.to_string(), ver.to_string(), desc.to_string())); }
        };
        for line in si.lines() {
            if let Some(v) = line.strip_prefix("Name            :") {
                flush(&cur_name, &cur_ver, &cur_desc, &mut result);
                cur_name = v.trim().to_string(); cur_ver.clear(); cur_desc.clear();
            } else if let Some(v) = line.strip_prefix("Version         :") { cur_ver = v.trim().to_string(); }
            else if let Some(v) = line.strip_prefix("Description     :") { cur_desc = v.trim().to_string(); }
        }
        flush(&cur_name, &cur_ver, &cur_desc, &mut result);
    }
    if let Ok(mut s) = shared.lock() { s.busy = false; s.orphans = Some(result); }
}

fn fetch_repos(shared: &Arc<Mutex<Shared>>) {
    if let Ok(mut s) = shared.lock() { s.busy = true; }
    let (preamble, sections) = parse_pacman_conf("/etc/pacman.conf");
    if let Ok(mut s) = shared.lock() {
        s.repo_preamble = preamble;
        s.repo_sections = Some(sections);
        s.busy = false;
    }
}

// ── UI rendering ──────────────────────────────────────────────────────────────

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_shared();
        ctx.request_repaint_after(std::time::Duration::from_millis(200));

        // Apply visuals
        let mut visuals = if self.dark_mode { egui::Visuals::dark() } else { egui::Visuals::light() };
        visuals.window_fill       = self.theme.bg;
        visuals.panel_fill        = self.theme.bg;
        visuals.override_text_color = Some(self.theme.fg);
        visuals.widgets.noninteractive.bg_fill = self.theme.bg_panel;
        visuals.widgets.inactive.bg_fill       = self.theme.btn_bg;
        visuals.widgets.hovered.bg_fill        = self.theme.accent;
        visuals.widgets.active.bg_fill         = self.theme.accent;
        ctx.set_visuals(visuals);

        // Modal overlays
        if self.show_sudo    { self.draw_sudo_dialog(ctx); }
        if self.show_confirm { self.draw_confirm_dialog(ctx); }
        if self.show_reboot  { self.draw_reboot_dialog(ctx); }
        if self.show_add_repo{ self.draw_add_repo_dialog(ctx); }

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(self.theme.bg))
            .show(ctx, |ui| {
                self.draw_header(ui);
                self.draw_tab_bar(ui);
                ui.separator();

                // Page content
                egui::ScrollArea::vertical()
                    .id_source("main_scroll")
                    .auto_shrink([false,false])
                    .show(ui, |ui| {
                        match self.tab {
                            Tab::Updates  => self.draw_updates(ui),
                            Tab::Search   => self.draw_search(ui),
                            Tab::PkgInfo  => self.draw_pkg_info(ui),
                            Tab::Stats    => self.draw_stats(ui),
                            Tab::Orphans  => self.draw_orphans(ui),
                            Tab::Repos    => self.draw_repos(ui),
                            Tab::Mirrors  => self.draw_mirrors(ui),
                        }
                    });

                // Log panel
                if self.show_log { self.draw_log(ui); }
            });
    }
}

impl App {
    fn draw_header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add_space(16.0);
            ui.label(RichText::new("⟳  Arch-Sysup")
                .font(FontId::monospace(18.0)).color(self.theme.accent).strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(16.0);
                let lbl = if self.dark_mode { "☀ Light Mode" } else { "☾ Dark Mode" };
                if ui.button(lbl).clicked() { self.toggle_theme(); }
                ui.separator();
                ui.label(RichText::new(&self.status).font(FontId::monospace(10.0))
                    .color(self.theme.fg_dim));
                if self.busy {
                    ui.spinner();
                }
            });
        });
        ui.separator();
    }

    fn draw_tab_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let tabs = [
                (Tab::Updates,  "Updates"),
                (Tab::Search,   "Search & Install"),
                (Tab::PkgInfo,  "Package Info"),
                (Tab::Stats,    "System Stats"),
                (Tab::Orphans,  "Orphans"),
                (Tab::Repos,    "Repositories"),
                (Tab::Mirrors,  "Mirrors"),
            ];
            for (t, name) in &tabs {
                let active = self.tab == *t;
                let color  = if active { self.theme.accent } else { self.theme.fg_dim };
                let btn    = ui.add(egui::Button::new(
                    RichText::new(*name).font(FontId::monospace(10.0)).color(color).strong()
                ).fill(if active { self.theme.bg } else { self.theme.bg_panel })
                 .frame(true).rounding(0.0));
                if btn.clicked() {
                    self.tab = *t;
                    self.on_tab_switch(*t);
                }
            }
        });
    }

    fn on_tab_switch(&mut self, tab: Tab) {
        match tab {
            Tab::Repos => {
                let sh = self.shared.clone();
                thread::spawn(move || fetch_repos(&sh));
                self.busy = true;
            }
            Tab::Orphans => {
                let sh = self.shared.clone();
                thread::spawn(move || fetch_orphans(&sh));
                self.busy = true;
            }
            Tab::Stats => {
                let sh = self.shared.clone();
                thread::spawn(move || fetch_stats(&sh));
                self.busy = true;
            }
            Tab::Mirrors => {
                self.mirror_conf = load_mirror_conf();
                self.mirror_dirty = false;
                self.mirror_status = format!("Loaded from {}", REFLECTOR_CONF);
            }
            _ => {}
        }
    }

    // ── Updates ───────────────────────────────────────────────────────────────

    fn draw_updates(&mut self, ui: &mut egui::Ui) {
        // Header row
        ui.push_id("upd_hdr", |ui| {
            let frame = egui::Frame::none().fill(self.theme.bg_hdr).inner_margin(egui::Margin::symmetric(8.0,4.0));
            frame.show(ui, |ui| {
                ui.horizontal(|ui| {
                    for (lbl, w) in &[("Repo",100.0),("Package",220.0),("Old Version",160.0),("→",20.0),("New Version",160.0)] {
                        ui.add_sized([*w,18.0], egui::Label::new(
                            RichText::new(*lbl).font(FontId::monospace(9.0)).color(self.theme.fg_dim).strong()
                        ));
                    }
                });
            });
        });

        egui::ScrollArea::vertical().id_source("upd_scroll").auto_shrink([false,false])
            .max_height(ui.available_height() - 48.0)
            .show(ui, |ui| {
                if self.updates.is_empty() && !self.busy {
                    ui.add_space(40.0);
                    ui.centered_and_justified(|ui| {
                        ui.label(RichText::new("✓  System is up to date")
                            .font(FontId::monospace(13.0)).color(self.theme.ver_new));
                    });
                }
                for (i, u) in self.updates.iter().enumerate() {
                    let bg = if u.kernel { self.theme.kernel_bg }
                             else if i%2==0 { self.theme.bg_row_alt }
                             else { self.theme.bg_panel };
                    let frame = egui::Frame::none().fill(bg).inner_margin(egui::Margin::symmetric(8.0,3.0));
                    frame.show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.add_sized([100.0,18.0], egui::Label::new(
                                RichText::new(&u.repo).font(FontId::monospace(9.0))
                                    .color(self.theme.repo_color(&u.repo)).strong()
                            ));
                            let pkg_color = if u.kernel { self.theme.kernel_fg } else { self.theme.fg };
                            ui.add_sized([220.0,18.0], egui::Label::new(
                                RichText::new(&u.pkg).font(FontId::monospace(10.0)).color(pkg_color)
                            ));
                            // Version diff
                            let (pre, suf) = split_ver_diff(&u.old, &u.new);
                            ui.add_sized([160.0,18.0], egui::Label::new({
                                let mut rt = RichText::new(format!("{}{}", pre, suf)).font(FontId::monospace(10.0));
                                if !suf.is_empty() { rt = rt.color(self.theme.ver_old); }
                                else { rt = rt.color(self.theme.fg); }
                                rt
                            }));
                            ui.label(RichText::new("→").color(self.theme.fg_dim).font(FontId::monospace(10.0)));
                            let (pre2, suf2) = split_ver_diff(&u.new, &u.old);
                            ui.add_sized([160.0,18.0], egui::Label::new({
                                let mut rt = RichText::new(format!("{}{}", pre2, suf2)).font(FontId::monospace(10.0));
                                if !suf2.is_empty() { rt = rt.color(self.theme.ver_new); }
                                else { rt = rt.color(self.theme.fg); }
                                rt
                            }));
                            if u.kernel {
                                ui.label(RichText::new("⚠ KERNEL").color(self.theme.kernel_fg)
                                    .font(FontId::monospace(9.0)).strong());
                            }
                        });
                    });
                }
            });

        // Bottom bar
        ui.separator();
        ui.horizontal(|ui| {
            ui.add_space(8.0);
            let count = self.updates.len();
            let msg = if count == 0 { "No updates available".into() }
                      else { format!("{} package{} to update{}", count, if count==1 {""} else {"s"},
                             if self.kernel_found { "  ⚠ kernel update!" } else {""}) };
            ui.label(RichText::new(msg).font(FontId::monospace(10.0)).color(self.theme.fg_dim));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(8.0);
                let can_update = !self.updates.is_empty() && !self.busy;
                if ui.add_enabled(can_update,
                    egui::Button::new(RichText::new("▶  Update All").color(Color32::WHITE).strong())
                        .fill(self.theme.btn_green)
                ).clicked() {
                    let has_off = self.updates.iter().any(|u| matches!(u.repo.to_lowercase().as_str(), "core"|"extra"|"multilib"));
                    let has_aur = self.updates.iter().any(|u| matches!(u.repo.to_lowercase().as_str(), "chaotic-aur"|"aur"));
                    let kf = self.kernel_found;
                    self.clear_log(); self.show_log = true;
                    self.request_sudo("Enter your sudo password to begin updating:", move |pw, sh, aur| {
                        do_updates(pw, sh, aur, has_off, has_aur, kf);
                    });
                }
                if ui.button(RichText::new("↻  Refresh").font(FontId::monospace(10.0))).clicked() && !self.busy {
                    self.busy = true;
                    self.updates.clear();
                    let sh = self.shared.clone(); let aur = self.aur_helper.clone();
                    thread::spawn(move || fetch_updates(&sh, &aur));
                }
            });
        });
    }

    // ── Search & Install ──────────────────────────────────────────────────────

    fn draw_search(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add_space(16.0);
            ui.label(RichText::new("Search packages:").font(FontId::monospace(10.0)).color(self.theme.fg).strong());
            let resp = ui.add(egui::TextEdit::singleline(&mut self.search_query)
                .font(FontId::monospace(10.0)).desired_width(280.0)
                .hint_text("package name…"));
            if (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                || ui.button("  Search  ").clicked() {
                let q = self.search_query.clone();
                if !q.is_empty() {
                    self.busy = true; self.search_res.clear();
                    let sh = self.shared.clone(); let aur = self.aur_helper.clone();
                    thread::spawn(move || fetch_search(&sh, &aur, q));
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(8.0);
                if ui.button("☐ None").clicked() { for r in &mut self.search_res { r.selected=false; } }
                if ui.button("☑ All").clicked() { for r in &mut self.search_res { r.selected=true; } }
            });
        });
        ui.separator();

        // Column header
        egui::Frame::none().fill(self.theme.bg_hdr).inner_margin(egui::Margin::symmetric(8.0,4.0)).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.add_space(28.0);
                for (lbl,w) in &[("Repo",100.0),("Package",200.0),("Version",140.0),("Description",0.0)] {
                    ui.add_sized([*w,16.0], egui::Label::new(
                        RichText::new(*lbl).font(FontId::monospace(9.0)).color(self.theme.fg_dim).strong()
                    ));
                }
            });
        });

        egui::ScrollArea::vertical().id_source("src_scroll").auto_shrink([false,false])
            .max_height(ui.available_height() - 52.0)
            .show(ui, |ui| {
                if self.search_res.is_empty() && !self.busy {
                    ui.add_space(30.0);
                    ui.centered_and_justified(|ui| {
                        ui.label(RichText::new("Search for a package above")
                            .color(self.theme.fg_dim).font(FontId::monospace(11.0)));
                    });
                }
                for (i, r) in self.search_res.iter_mut().enumerate() {
                    let bg = if i%2==0 { self.theme.bg_row_alt } else { self.theme.bg_panel };
                    egui::Frame::none().fill(bg).inner_margin(egui::Margin::symmetric(8.0,2.0)).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut r.selected, "");
                            ui.add_sized([100.0,16.0], egui::Label::new(
                                RichText::new(&r.repo).font(FontId::monospace(9.0))
                                    .color({
                                        let t = Theme::dark();
                                        t.repo_color(&r.repo)
                                    }).strong()
                            ));
                            let pkg_txt = if r.installed { format!("{} ✓", r.pkg) } else { r.pkg.clone() };
                            let pkg_col = if r.installed { self.theme.ver_new } else { self.theme.fg };
                            ui.add_sized([200.0,16.0], egui::Label::new(
                                RichText::new(pkg_txt).font(FontId::monospace(10.0)).color(pkg_col)
                            ));
                            ui.add_sized([140.0,16.0], egui::Label::new(
                                RichText::new(&r.ver).font(FontId::monospace(10.0)).color(self.theme.fg_dim)
                            ));
                            let desc: String = r.desc.chars().take(80).collect();
                            ui.label(RichText::new(desc).font(FontId::monospace(9.0)).color(self.theme.fg_dim));
                        });
                    });
                }
            });

        // Action bar
        ui.separator();
        ui.horizontal(|ui| {
            ui.add_space(8.0);
            let to_inst: Vec<String> = self.search_res.iter().filter(|r| r.selected && !r.installed).map(|r| r.pkg.clone()).collect();
            let to_rem:  Vec<String> = self.search_res.iter().filter(|r| r.selected && r.installed).map(|r| r.pkg.clone()).collect();
            let label = if to_inst.is_empty() && to_rem.is_empty() { "No packages selected".into() }
                        else {
                            let mut parts = vec![];
                            if !to_inst.is_empty() { parts.push(format!("{} to install", to_inst.len())); }
                            if !to_rem.is_empty()  { parts.push(format!("{} to uninstall", to_rem.len())); }
                            format!("Selected: {}", parts.join("  •  "))
                        };
            ui.label(RichText::new(label).font(FontId::monospace(10.0)).color(self.theme.fg_dim));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(8.0);
                if !to_inst.is_empty() {
                    if ui.add(egui::Button::new(RichText::new("▶ Install Selected").color(Color32::WHITE))
                        .fill(self.theme.btn_green)).clicked() {
                        let pkgs = to_inst.clone();
                        let sources: Vec<String> = self.search_res.iter()
                            .filter(|r| r.selected && !r.installed).map(|r| r.source.clone()).collect();
                        self.clear_log(); self.show_log = true;
                        self.request_sudo(&format!("Enter sudo password to install: {}", pkgs.join(", ")),
                            move |pw, sh, aur| {
                                let off: Vec<&str> = pkgs.iter().zip(sources.iter())
                                    .filter(|(_,s)| *s != "aur").map(|(p,_)| p.as_str()).collect();
                                let aur_pkgs: Vec<&str> = pkgs.iter().zip(sources.iter())
                                    .filter(|(_,s)| *s == "aur").map(|(p,_)| p.as_str()).collect();
                                if !off.is_empty() {
                                    let mut cmd = vec!["pacman","-S","--noconfirm"];
                                    cmd.extend_from_slice(&off);
                                    sudo_cmd_streaming(pw, &cmd, sh);
                                }
                                if !aur_pkgs.is_empty() {
                                    if let Some(h) = aur {
                                        let mut cmd = vec![h.as_str(),"-S","--noconfirm"];
                                        cmd.extend_from_slice(&aur_pkgs);
                                        cmd_streaming(&cmd, sh);
                                    }
                                }
                                push_log(sh, "✓ Install complete.", LogColor::Green);
                            });
                    }
                }
                if !to_rem.is_empty() {
                    if ui.add(egui::Button::new(RichText::new("✕ Uninstall Selected").color(Color32::WHITE))
                        .fill(self.theme.btn_red)).clicked() {
                        let pkgs = to_rem.clone();
                        let msg  = format!("Remove {} package(s)?\n\n{}", pkgs.len(),
                                           pkgs.iter().map(|p| format!("  • {}", p)).collect::<Vec<_>>().join("\n"));
                        self.confirm_msg = msg;
                        self.show_confirm = true;
                        self.confirm_action = Some(Box::new(move |app| {
                            app.clear_log(); app.show_log = true;
                            app.request_sudo(&format!("Enter sudo password to remove: {}", pkgs.join(", ")),
                                move |pw, sh, _aur| {
                                    let mut cmd = vec!["pacman","-Rns","--noconfirm"];
                                    let pkgs_ref: Vec<&str> = pkgs.iter().map(|s| s.as_str()).collect();
                                    cmd.extend_from_slice(&pkgs_ref);
                                    sudo_cmd_streaming(pw, &cmd, sh);
                                    push_log(sh, "✓ Removal complete.", LogColor::Green);
                                });
                        }));
                    }
                }
            });
        });
    }

    // ── Package Info ──────────────────────────────────────────────────────────

    fn draw_pkg_info(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add_space(16.0);
            ui.label(RichText::new("Package name:").font(FontId::monospace(10.0)).color(self.theme.fg).strong());
            let resp = ui.add(egui::TextEdit::singleline(&mut self.info_query)
                .font(FontId::monospace(10.0)).desired_width(240.0));
            if (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                || ui.button("  Look Up  ").clicked() {
                let pkg = self.info_query.clone();
                if !pkg.is_empty() {
                    self.pkg_info = None; self.busy = true;
                    let sh = self.shared.clone(); let aur = self.aur_helper.clone();
                    thread::spawn(move || fetch_pkg_info(&sh, &aur, pkg));
                }
            }
        });
        ui.separator();

        egui::ScrollArea::vertical().id_source("info_scroll").show(ui, |ui| {
            match &self.pkg_info {
                None if !self.busy => {
                    ui.add_space(30.0);
                    ui.centered_and_justified(|ui| {
                        ui.label(RichText::new("Enter a package name above")
                            .color(self.theme.fg_dim).font(FontId::monospace(11.0)));
                    });
                }
                Some((pkg, None)) => {
                    ui.label(RichText::new(format!("Package '{}' not found.", pkg))
                        .color(self.theme.ver_old).font(FontId::monospace(11.0)));
                }
                Some((_, Some(info))) => {
                    let badge = if info.installed { ("● Installed", self.theme.ver_new) }
                                else { ("○ Not installed", self.theme.fg_dim) };
                    ui.label(RichText::new(badge.0).color(badge.1).font(FontId::monospace(10.0)).strong());
                    ui.add_space(8.0);

                    let show = ["Name","Version","Description","URL","Licenses","Repository",
                                "Installed Size","Download Size","Packager","Build Date",
                                "Install Date","Install Reason","Depends On","Optional Deps",
                                "Required By","Conflicts With"];
                    egui::Grid::new("pkg_info_grid").num_columns(2).spacing([16.0,4.0]).show(ui, |ui| {
                        for key in &show {
                            if let Some((_,val)) = info.fields.iter().find(|(k,_)| k==key) {
                                if !val.is_empty() && val != "None" {
                                    ui.label(RichText::new(format!("{}:", key))
                                        .font(FontId::monospace(10.0)).color(self.theme.fg_dim).strong());
                                    ui.label(RichText::new(val).font(FontId::monospace(10.0)).color(self.theme.fg));
                                    ui.end_row();
                                }
                            }
                        }
                    });

                    if !info.files.is_empty() {
                        ui.add_space(12.0);
                        ui.label(RichText::new("Installed Files:").font(FontId::monospace(10.0))
                            .color(self.theme.fg_dim).strong());
                        egui::ScrollArea::vertical().id_source("files_scroll").max_height(200.0).show(ui, |ui| {
                            for line in info.files.lines() {
                                let path = line.split_whitespace().nth(1).unwrap_or(line);
                                ui.label(RichText::new(path).font(FontId::monospace(9.0)).color(self.theme.fg_dim));
                            }
                        });
                    }
                }
                _ => {}
            }
        });
    }

    // ── System Stats ──────────────────────────────────────────────────────────

    fn draw_stats(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add_space(16.0);
            ui.label(RichText::new("System Statistics").font(FontId::monospace(11.0)).color(self.theme.fg).strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("↻  Refresh Stats").clicked() {
                    self.busy = true;
                    let sh = self.shared.clone();
                    thread::spawn(move || fetch_stats(&sh));
                }
            });
        });
        ui.separator();

        if let Some(ref s) = self.stats.clone() {
            egui::Grid::new("stats_grid").num_columns(4).spacing([32.0,8.0])
                .min_col_width(160.0).show(ui, |ui| {
                let add = |ui: &mut egui::Ui, lbl: &str, val: &str, col: Color32| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new(lbl).font(FontId::monospace(9.0)).color(self.theme.fg_dim));
                        ui.label(RichText::new(val).font(FontId::monospace(12.0)).color(col).strong());
                    });
                };
                add(ui, "Total Packages",  &s.pkg_count,  self.theme.fg);
                add(ui, "Explicitly installed", &s.explicit, self.theme.ver_new);
                add(ui, "Foreign / AUR",   &s.aur_count,  self.theme.repo_aur);
                add(ui, "Orphans",         &s.orphans,    if s.orphans=="0"{self.theme.fg}else{self.theme.ver_old});
                ui.end_row();
                add(ui, "Package cache",   &s.disk_pkg,   self.theme.fg);
                add(ui, "Root disk",       &s.disk_root,  self.theme.fg);
                add(ui, "Home disk",       &s.disk_home,  self.theme.fg);
                add(ui, "Last upgrade",    &s.last_upd,   self.theme.fg);
                ui.end_row();
                add(ui, "Kernel",          &s.kernel_ver, self.theme.repo_multi);
                add(ui, "Uptime",          &s.uptime,     self.theme.fg);
                ui.end_row();
            });

            ui.add_space(16.0);
            ui.separator();
            ui.add_space(8.0);

            // Disk donut bars (simple progress bars in egui)
            ui.label(RichText::new("Disk Usage").font(FontId::monospace(10.0)).color(self.theme.fg_dim).strong());
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                for (label, used, total, color) in [
                    ("Root /", s.root_used, s.root_total, self.theme.chart1),
                    ("Home ~", s.home_used, s.home_total, self.theme.chart2),
                ] {
                    ui.vertical(|ui| {
                        ui.set_min_width(200.0);
                        let pct = if total > 0.0 { used/total } else { 0.0 };
                        ui.label(RichText::new(format!("{} — {:.0}%", label, pct*100.0))
                            .font(FontId::monospace(9.0)).color(self.theme.fg_dim));
                        let bar = egui::ProgressBar::new(pct).fill(color).desired_width(180.0);
                        ui.add(bar);
                    });
                    ui.add_space(32.0);
                }
            });

            // Package breakdown bar
            let total = s.pkg_count.parse::<f32>().unwrap_or(1.0);
            let exp   = s.explicit.parse::<f32>().unwrap_or(0.0);
            let aur   = s.aur_count.parse::<f32>().unwrap_or(0.0);
            let orph  = s.orphans.parse::<f32>().unwrap_or(0.0);
            let dep   = (total - exp).max(0.0);
            ui.add_space(12.0);
            ui.label(RichText::new("Package Breakdown").font(FontId::monospace(9.0)).color(self.theme.fg_dim).strong());
            ui.add_space(4.0);
            let bar_w = ui.available_width().min(500.0);
            let (response, painter) = ui.allocate_painter(Vec2::new(bar_w, 24.0), egui::Sense::hover());
            let rect = response.rect;
            if total > 0.0 {
                let mut x = rect.left();
                for (n, color) in [(exp, self.theme.chart1),(dep, self.theme.chart2),(orph, self.theme.chart3),(aur, self.theme.repo_aur)] {
                    let w = bar_w * (n/total);
                    if w > 1.0 {
                        painter.rect_filled(egui::Rect::from_min_size(egui::pos2(x, rect.top()), Vec2::new(w, 24.0)), 0.0, color);
                        x += w;
                    }
                }
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                for (lbl, n, col) in [
                    ("Explicit", exp as u32, self.theme.chart1),
                    ("Deps", dep as u32, self.theme.chart2),
                    ("Orphans", orph as u32, self.theme.chart3),
                    ("AUR", aur as u32, self.theme.repo_aur),
                ] {
                    let (r,p) = ui.allocate_painter(Vec2::new(12.0,12.0), egui::Sense::hover());
                    p.rect_filled(r.rect, 0.0, col);
                    ui.label(RichText::new(format!("{}: {}", lbl, n))
                        .font(FontId::monospace(9.0)).color(self.theme.fg_dim));
                    ui.add_space(12.0);
                }
            });
        } else if !self.busy {
            ui.label(RichText::new("Click Refresh Stats to load").color(self.theme.fg_dim));
        }
    }

    // ── Orphans ───────────────────────────────────────────────────────────────

    fn draw_orphans(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add_space(16.0);
            ui.label(RichText::new("Orphan Packages").font(FontId::monospace(11.0)).color(self.theme.fg).strong());
            let count = self.orphans.len();
            if count > 0 {
                ui.label(RichText::new(format!("— {} found", count)).font(FontId::monospace(10.0)).color(self.theme.ver_old));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let sel: Vec<String> = self.orphans.iter().filter(|o| o.3).map(|o| o.0.clone()).collect();
                if !sel.is_empty() {
                    if ui.add(egui::Button::new(
                        RichText::new("🗑  Remove Selected").color(Color32::WHITE))
                        .fill(self.theme.btn_red)).clicked() {
                        let pkgs = sel.clone();
                        let msg = format!("Permanently remove {} orphan(s)?\n\n{}", pkgs.len(),
                                          pkgs.iter().map(|p| format!("  • {}", p)).collect::<Vec<_>>().join("\n"));
                        self.confirm_msg = msg;
                        self.show_confirm = true;
                        self.confirm_action = Some(Box::new(move |app| {
                            app.clear_log(); app.show_log = true;
                            app.request_sudo("Enter sudo password to remove orphans:", move |pw, sh, _aur| {
                                let mut cmd = vec!["pacman","-Rns","--noconfirm"];
                                let pr: Vec<&str> = pkgs.iter().map(|s| s.as_str()).collect();
                                cmd.extend_from_slice(&pr);
                                sudo_cmd_streaming(pw, &cmd, sh);
                                push_log(sh, "✓ Orphan removal complete.", LogColor::Green);
                                fetch_orphans(sh);
                            });
                        }));
                    }
                }
                if ui.button("↻  Scan").clicked() {
                    self.orphans.clear(); self.busy = true;
                    let sh = self.shared.clone();
                    thread::spawn(move || fetch_orphans(&sh));
                }
            });
        });

        ui.add_space(4.0);
        ui.label(RichText::new("ℹ  Orphans are packages installed as dependencies that are no longer required by any other package.\n   Review carefully before removing — some may be intentionally standalone.")
            .font(FontId::monospace(9.0)).color(self.theme.fg_dim));
        ui.separator();

        // Column header
        egui::Frame::none().fill(self.theme.bg_hdr).inner_margin(egui::Margin::symmetric(8.0,4.0)).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.add_space(28.0);
                for (lbl,w) in &[("Package",200.0),("Version",140.0),("Description",0.0)] {
                    ui.add_sized([*w,16.0], egui::Label::new(
                        RichText::new(*lbl).font(FontId::monospace(9.0)).color(self.theme.fg_dim).strong()
                    ));
                }
            });
        });

        egui::ScrollArea::vertical().id_source("orph_scroll").show(ui, |ui| {
            if self.orphans.is_empty() && !self.busy {
                ui.add_space(30.0);
                ui.centered_and_justified(|ui| {
                    ui.label(RichText::new("✓  No orphan packages found.").color(self.theme.ver_new).font(FontId::monospace(11.0)));
                });
            }
            for (i, (name, ver, desc, selected)) in self.orphans.iter_mut().enumerate() {
                let bg = if i%2==0 { self.theme.bg_row_alt } else { self.theme.bg_panel };
                egui::Frame::none().fill(bg).inner_margin(egui::Margin::symmetric(8.0,2.0)).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.checkbox(selected, "");
                        ui.add_sized([200.0,16.0], egui::Label::new(
                            RichText::new(name.as_str()).font(FontId::monospace(10.0)).color(self.theme.ver_old)
                        ));
                        ui.add_sized([140.0,16.0], egui::Label::new(
                            RichText::new(ver.as_str()).font(FontId::monospace(10.0)).color(self.theme.fg_dim)
                        ));
                        let d: String = desc.chars().take(70).collect();
                        ui.label(RichText::new(d).font(FontId::monospace(9.0)).color(self.theme.fg_dim));
                    });
                });
            }
        });
    }

    // ── Repositories ──────────────────────────────────────────────────────────

    fn draw_repos(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add_space(16.0);
            ui.label(RichText::new("Configured Repositories").font(FontId::monospace(11.0)).color(self.theme.fg).strong());
            if self.repo_dirty {
                ui.label(RichText::new("● Unsaved changes").font(FontId::monospace(10.0)).color(self.theme.btn_orange));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(8.0);
                if self.repo_dirty {
                    if ui.add(egui::Button::new(
                        RichText::new("💾  Save Changes").color(Color32::WHITE))
                        .fill(self.theme.btn_green)).clicked() {
                        let preamble = self.repo_preamble.clone();
                        let sections = self.repo_sections.clone();
                        let new_conf = write_pacman_conf(&preamble, &sections);
                        self.clear_log(); self.show_log = true;
                        self.request_sudo("Enter sudo password to write /etc/pacman.conf:", move |pw, sh, _aur| {
                            match sudo_write_file(pw, "/etc/pacman.conf", &new_conf) {
                                Ok(_) => {
                                    push_log(sh, "✓ pacman.conf saved.", LogColor::Green);
                                    push_log(sh, "Syncing new repo databases…", LogColor::Accent);
                                    sudo_cmd_streaming(pw, &["pacman","-Sy","--noconfirm"], sh);
                                    push_log(sh, "✓ Done.", LogColor::Green);
                                    fetch_repos(sh);
                                }
                                Err(e) => push_log(sh, &format!("✗ Failed: {}", e), LogColor::Red),
                            }
                        });
                        self.repo_dirty = false;
                    }
                }
                if ui.add(egui::Button::new(
                    RichText::new("＋  Add Repo").color(Color32::WHITE))
                    .fill(self.theme.btn_accent)).clicked() {
                    self.show_add_repo = true;
                    self.new_repo_name.clear(); self.new_repo_inc.clear(); self.new_repo_err.clear();
                }
            });
        });
        ui.separator();

        // Column header
        egui::Frame::none().fill(self.theme.bg_hdr).inner_margin(egui::Margin::symmetric(8.0,4.0)).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.add_space(8.0);
                for (lbl,w) in &[("Status",70.0),("Repository",180.0),("Include / Server",0.0)] {
                    ui.add_sized([*w,16.0], egui::Label::new(
                        RichText::new(*lbl).font(FontId::monospace(9.0)).color(self.theme.fg_dim).strong()
                    ));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_space(8.0);
                    ui.label(RichText::new("Actions").font(FontId::monospace(9.0)).color(self.theme.fg_dim).strong());
                });
            });
        });

        let mut toggle_idx: Option<(usize, bool)> = None;
        let mut remove_idx: Option<usize> = None;

        egui::ScrollArea::vertical().id_source("repo_scroll").auto_shrink([false,false])
            .max_height(ui.available_height() - 48.0)
            .show(ui, |ui| {
                let repo_secs: Vec<(usize, &RepoSection)> = self.repo_sections.iter().enumerate()
                    .filter(|(_,s)| !s.is_opts).collect();
                for (fi, (idx, sec)) in repo_secs.iter().enumerate() {
                    let bg = if fi%2==0 { self.theme.bg_row_alt } else { self.theme.bg_panel };
                    egui::Frame::none().fill(bg).inner_margin(egui::Margin::symmetric(8.0,4.0)).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let (status_txt, status_col) = if sec.enabled {
                                ("● ON", self.theme.ver_new)
                            } else {
                                ("○ OFF", self.theme.fg_dim)
                            };
                            ui.add_sized([70.0,16.0], egui::Label::new(
                                RichText::new(status_txt).font(FontId::monospace(9.0)).color(status_col).strong()
                            ));
                            ui.add_sized([180.0,16.0], egui::Label::new(
                                RichText::new(format!("[{}]", sec.name)).font(FontId::monospace(10.0))
                                    .color(self.theme.repo_color(&sec.name)).strong()
                            ));
                            // Include/Server lines
                            let incs: Vec<String> = sec.lines.iter().skip(1).filter_map(|l| {
                                let s = l.trim();
                                if s.starts_with("Include =") || s.starts_with("Server =")
                                || s.starts_with("#Include =") || s.starts_with("#Server =") {
                                    Some(s.trim_start_matches('#').trim().to_string())
                                } else { None }
                            }).collect();
                            let inc_txt = if incs.is_empty() { "(none)".into() } else { incs.join("  |  ") };
                            ui.label(RichText::new(inc_txt).font(FontId::monospace(9.0)).color(self.theme.fg_dim));

                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                let name_lower = sec.name.to_lowercase();
                                if name_lower != "core" && name_lower != "extra" && name_lower != "options" {
                                    if ui.add(egui::Button::new(
                                        RichText::new("Remove").color(Color32::WHITE))
                                        .fill(self.theme.btn_red)).clicked() {
                                        remove_idx = Some(*idx);
                                    }
                                }
                                if sec.enabled {
                                    if ui.add(egui::Button::new("Disable").fill(self.theme.btn_orange)).clicked() {
                                        toggle_idx = Some((*idx, false));
                                    }
                                } else {
                                    if ui.add(egui::Button::new(
                                        RichText::new("Enable").color(Color32::WHITE))
                                        .fill(self.theme.btn_green)).clicked() {
                                        toggle_idx = Some((*idx, true));
                                    }
                                }
                            });
                        });
                    });
                }
            });

        if let Some((idx, en)) = toggle_idx {
            self.repo_sections[idx].enabled = en;
            self.repo_dirty = true;
        }
        if let Some(idx) = remove_idx {
            self.repo_sections.remove(idx);
            self.repo_dirty = true;
        }

        ui.separator();
        ui.label(RichText::new("ℹ  Changes are written to /etc/pacman.conf and require sudo. A pacman -Sy will run after saving.")
            .font(FontId::monospace(9.0)).color(self.theme.fg_dim));
    }

    // ── Mirrors ───────────────────────────────────────────────────────────────

    fn draw_mirrors(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().id_source("mir_scroll").auto_shrink([false,false])
            .max_height(ui.available_height() - 52.0)
            .show(ui, |ui| {
                ui.add_space(8.0);

                let section = |ui: &mut egui::Ui, title: &str| {
                    ui.add_space(8.0);
                    ui.label(RichText::new(title).font(FontId::monospace(10.0))
                        .color(self.theme.accent).strong());
                    ui.separator();
                };

                // Country
                section(ui, "Country / Region");
                ui.horizontal(|ui| {
                    ui.add_space(16.0);
                    ui.label(RichText::new("Countries:").font(FontId::monospace(10.0)).color(self.theme.fg));
                    let r = ui.add(egui::TextEdit::singleline(&mut self.mirror_conf.countries)
                        .font(FontId::monospace(10.0)).desired_width(260.0));
                    if r.changed() { self.mirror_dirty = true; }
                    ui.label(RichText::new("e.g. US,GB,DE  (blank = all)").font(FontId::monospace(9.0)).color(self.theme.fg_dim));
                });

                // Protocol
                section(ui, "Protocol");
                ui.horizontal(|ui| {
                    ui.add_space(16.0);
                    let r = ui.checkbox(&mut self.mirror_conf.proto_https, "https");
                    if r.changed() { self.mirror_dirty = true; }
                    let r = ui.checkbox(&mut self.mirror_conf.proto_http, "http");
                    if r.changed() { self.mirror_dirty = true; }
                });

                // Sort
                section(ui, "Sort By");
                ui.horizontal(|ui| {
                    ui.add_space(16.0);
                    for (val, lbl) in &[("rate","Download Rate"),("score","Mirror Score"),
                                        ("delay","Sync Delay"),("age","Last Sync Age"),("country","Country")] {
                        let r = ui.radio_value(&mut self.mirror_conf.sort, val.to_string(), *lbl);
                        if r.changed() { self.mirror_dirty = true; }
                        ui.add_space(8.0);
                    }
                });

                // Number
                section(ui, "Number of Mirrors");
                ui.horizontal(|ui| {
                    ui.add_space(16.0);
                    ui.label(RichText::new("Latest N mirrors:").font(FontId::monospace(10.0)).color(self.theme.fg));
                    let r = ui.add(egui::TextEdit::singleline(&mut self.mirror_conf.latest)
                        .font(FontId::monospace(10.0)).desired_width(50.0));
                    if r.changed() { self.mirror_dirty = true; }
                    ui.label(RichText::new("select from N most recently synced").font(FontId::monospace(9.0)).color(self.theme.fg_dim));
                });

                // Age
                section(ui, "Maximum Mirror Age");
                ui.horizontal(|ui| {
                    ui.add_space(16.0);
                    ui.label(RichText::new("Maximum age:").font(FontId::monospace(10.0)).color(self.theme.fg));
                    let r = ui.add(egui::TextEdit::singleline(&mut self.mirror_conf.age)
                        .font(FontId::monospace(10.0)).desired_width(50.0));
                    if r.changed() { self.mirror_dirty = true; }
                    ui.label(RichText::new("hours since last sync").font(FontId::monospace(9.0)).color(self.theme.fg_dim));
                });

                // Timeout
                section(ui, "Connection Timeout");
                ui.horizontal(|ui| {
                    ui.add_space(16.0);
                    ui.label(RichText::new("Connection timeout:").font(FontId::monospace(10.0)).color(self.theme.fg));
                    let r = ui.add(egui::TextEdit::singleline(&mut self.mirror_conf.timeout)
                        .font(FontId::monospace(10.0)).desired_width(50.0));
                    if r.changed() { self.mirror_dirty = true; }
                    ui.label(RichText::new("seconds").font(FontId::monospace(9.0)).color(self.theme.fg_dim));
                });

                // Extra
                section(ui, "Extra Options");
                ui.horizontal(|ui| {
                    ui.add_space(16.0);
                    let r = ui.checkbox(&mut self.mirror_conf.ipv4, "IPv4 only");
                    if r.changed() { self.mirror_dirty = true; }
                    ui.add_space(16.0);
                    let r = ui.checkbox(&mut self.mirror_conf.ipv6, "IPv6 only");
                    if r.changed() { self.mirror_dirty = true; }
                });

                ui.add_space(8.0);
                ui.separator();
                if !self.mirror_status.is_empty() {
                    ui.label(RichText::new(&self.mirror_status).font(FontId::monospace(9.0)).color(self.theme.fg_dim));
                }
            });

        // Bottom bar
        ui.separator();
        ui.horizontal(|ui| {
            ui.add_space(8.0);
            if self.mirror_dirty {
                ui.label(RichText::new("● Unsaved changes").font(FontId::monospace(9.0)).color(self.theme.btn_orange));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(8.0);
                if ui.add(egui::Button::new(
                    RichText::new("▶  Run Reflector Now").color(Color32::WHITE))
                    .fill(self.theme.btn_green)).clicked() {
                    if !which("reflector") {
                        self.mirror_status = "reflector is not installed. Run: sudo pacman -S reflector".into();
                    } else {
                        let mc = self.mirror_conf.clone();
                        self.clear_log(); self.show_log = true;
                        self.request_sudo("Enter sudo password to run reflector:", move |pw, sh, _aur| {
                            push_log(sh, "Running reflector — this may take a minute…", LogColor::Accent);
                            let conf_content = std::fs::read_to_string(REFLECTOR_CONF).unwrap_or_default();
                            let mut cmd_args = vec!["reflector".to_string()];
                            for line in conf_content.lines() {
                                let s = line.trim();
                                if s.is_empty() || s.starts_with('#') { continue; }
                                let parts: Vec<&str> = s.splitn(2,' ').collect();
                                cmd_args.push(parts[0].to_string());
                                if parts.len() > 1 { cmd_args.push(parts[1].to_string()); }
                            }
                            if !cmd_args.iter().any(|a| a == "--save") {
                                cmd_args.push("--save".into());
                                cmd_args.push("/etc/pacman.d/mirrorlist".into());
                            }
                            push_log(sh, &format!("Command: {}", cmd_args.join(" ")), LogColor::Dim);
                            let refs: Vec<&str> = cmd_args.iter().map(|s| s.as_str()).collect();
                            sudo_cmd_streaming(pw, &refs, sh);
                            push_log(sh, "✓ Mirrorlist updated.", LogColor::Green);
                            if let Ok(mut s2) = sh.lock() {
                                s2.mirror_status = Some(format!("✓  Reflector ran — /etc/pacman.d/mirrorlist updated."));
                            }
                            let _ = mc; // keep alive
                        });
                    }
                }
                if ui.add(egui::Button::new(
                    RichText::new("💾  Save Config").color(Color32::WHITE))
                    .fill(self.theme.btn_accent)).clicked() {
                    let mc = self.mirror_conf.clone();
                    let conf = build_mirror_conf(&mc);
                    self.clear_log(); self.show_log = true;
                    self.request_sudo(&format!("Enter sudo password to write {}:", REFLECTOR_CONF), move |pw, sh, _aur| {
                        match sudo_write_file(pw, REFLECTOR_CONF, &conf) {
                            Ok(_) => {
                                push_log(sh, &format!("✓ {} saved.", REFLECTOR_CONF), LogColor::Green);
                                if let Ok(mut s2) = sh.lock() {
                                    s2.mirror_status = Some(format!("✓  Saved to {}", REFLECTOR_CONF));
                                }
                            }
                            Err(e) => push_log(sh, &format!("✗ Failed: {}", e), LogColor::Red),
                        }
                    });
                    self.mirror_dirty = false;
                }
            });
        });
    }

    // ── Log panel ─────────────────────────────────────────────────────────────

    fn draw_log(&mut self, ui: &mut egui::Ui) {
        ui.separator();
        let avail = (ui.available_height()).max(80.0).min(220.0);
        egui::Frame::none().fill(self.theme.bg_log).inner_margin(4.0).show(ui, |ui| {
            egui::ScrollArea::vertical().id_source("log_scroll").stick_to_bottom(true)
                .max_height(avail).auto_shrink([false,false])
                .show(ui, |ui| {
                    for (line, color) in &self.log_lines {
                        let col = match color {
                            LogColor::Normal => self.theme.fg,
                            LogColor::Dim    => self.theme.fg_dim,
                            LogColor::Green  => self.theme.ver_new,
                            LogColor::Red    => self.theme.ver_old,
                            LogColor::Accent => self.theme.accent,
                            LogColor::Orange => self.theme.btn_orange,
                        };
                        ui.label(RichText::new(line).font(FontId::monospace(9.0)).color(col));
                    }
                });
        });
    }

    // ── Dialogs ───────────────────────────────────────────────────────────────

    fn draw_sudo_dialog(&mut self, ctx: &egui::Context) {
        egui::Window::new("🔒  Authentication Required")
            .collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0,0.0])
            .min_width(380.0).show(ctx, |ui| {
                ui.add_space(8.0);
                ui.label(RichText::new(&self.sudo_prompt.clone()).font(FontId::monospace(10.0)).color(self.theme.fg));
                ui.add_space(8.0);
                let pw_resp = ui.add(egui::TextEdit::singleline(&mut self.sudo_pw)
                    .password(true).font(FontId::monospace(10.0)).desired_width(320.0)
                    .hint_text("password"));
                pw_resp.request_focus();
                if !self.sudo_error.is_empty() {
                    ui.add_space(4.0);
                    ui.label(RichText::new(&self.sudo_error.clone()).color(self.theme.ver_old).font(FontId::monospace(10.0)));
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let submitted = ui.add(egui::Button::new(
                        RichText::new("  Authenticate  ").color(Color32::WHITE))
                        .fill(self.theme.btn_green)).clicked()
                        || (pw_resp.lost_focus() && ctx.input(|i| i.key_pressed(egui::Key::Enter)));
                    if submitted { self.submit_sudo(); }
                    if ui.button("  Cancel  ").clicked() {
                        self.show_sudo = false;
                        self.sudo_pw.clear();
                        self.sudo_callback = None;
                    }
                });
                ui.add_space(4.0);
            });
    }

    fn draw_confirm_dialog(&mut self, ctx: &egui::Context) {
        let msg = self.confirm_msg.clone();
        egui::Window::new("Confirm")
            .collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0,0.0])
            .min_width(360.0).show(ctx, |ui| {
                ui.add_space(8.0);
                ui.label(RichText::new(&msg).font(FontId::monospace(10.0)).color(self.theme.fg));
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui.add(egui::Button::new(
                        RichText::new("  Yes, proceed  ").color(Color32::WHITE))
                        .fill(self.theme.btn_red)).clicked() {
                        self.show_confirm = false;
                        if let Some(action) = self.confirm_action.take() {
                            action(self);
                        }
                    }
                    if ui.button("  Cancel  ").clicked() {
                        self.show_confirm = false;
                        self.confirm_action = None;
                    }
                });
                ui.add_space(4.0);
            });
    }

    fn draw_reboot_dialog(&mut self, ctx: &egui::Context) {
        egui::Window::new("⚠  Kernel Updated")
            .collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0,0.0])
            .show(ctx, |ui| {
                ui.label(RichText::new("A new kernel was installed.\nReboot now to apply it?")
                    .font(FontId::monospace(11.0)).color(self.theme.fg));
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui.add(egui::Button::new(
                        RichText::new("  Reboot Now  ").color(Color32::WHITE))
                        .fill(self.theme.btn_red)).clicked() {
                        let _ = Command::new("sudo").args(["reboot"]).spawn();
                        self.show_reboot = false;
                    }
                    if ui.button("  Later  ").clicked() { self.show_reboot = false; }
                });
            });
    }

    fn draw_add_repo_dialog(&mut self, ctx: &egui::Context) {
        egui::Window::new("Add Repository")
            .collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0,0.0])
            .min_width(460.0).show(ctx, |ui| {
                ui.label(RichText::new("Add Repository to pacman.conf")
                    .font(FontId::monospace(10.0)).color(self.theme.accent).strong());
                ui.add_space(8.0);
                egui::Grid::new("add_repo_grid").num_columns(2).spacing([12.0,8.0]).show(ui, |ui| {
                    ui.label(RichText::new("Repository name:").font(FontId::monospace(10.0)));
                    ui.add(egui::TextEdit::singleline(&mut self.new_repo_name).desired_width(240.0));
                    ui.end_row();
                    ui.label(RichText::new("Include / Server:").font(FontId::monospace(10.0)));
                    ui.add(egui::TextEdit::singleline(&mut self.new_repo_inc).desired_width(240.0));
                    ui.end_row();
                });
                if !self.new_repo_err.is_empty() {
                    ui.label(RichText::new(&self.new_repo_err.clone()).color(self.theme.ver_old));
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.add(egui::Button::new(
                        RichText::new("  Add Repository  ").color(Color32::WHITE))
                        .fill(self.theme.btn_accent)).clicked() {
                        let name = self.new_repo_name.trim().trim_matches(|c| c=='['||c==']').to_string();
                        let inc  = self.new_repo_inc.trim().to_string();
                        if name.is_empty() { self.new_repo_err = "Repository name is required.".into(); }
                        else if inc.is_empty() { self.new_repo_err = "Include or Server line is required.".into(); }
                        else if self.repo_sections.iter().any(|s| s.name.to_lowercase()==name.to_lowercase()) {
                            self.new_repo_err = format!("[{}] already exists.", name);
                        } else {
                            let sl = if inc.starts_with("Include =") || inc.starts_with("Server =") {
                                inc.clone()
                            } else { format!("Server = {}", inc) };
                            self.repo_sections.push(RepoSection {
                                name: name.clone(), enabled: true,
                                lines: vec![format!("[{}]\n", name), format!("{}\n", sl), "\n".into()],
                                is_opts: false,
                            });
                            self.repo_dirty = true;
                            self.show_add_repo = false;
                        }
                    }
                    if ui.button("  Cancel  ").clicked() { self.show_add_repo = false; }
                });
                ui.add_space(4.0);
            });
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> eframe::Result<()> {
    let icon = load_icon();
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Arch-Sysup — System Manager")
            .with_inner_size([1120.0, 780.0])
            .with_min_inner_size([900.0, 580.0])
            .with_icon(icon.unwrap_or_default()),
        ..Default::default()
    };
    eframe::run_native("Arch-Sysup", opts, Box::new(|cc| Box::new(App::new(cc))))
}

fn load_icon() -> Option<egui::IconData> {
    let paths = [
        "/usr/share/icons/hicolor/scalable/apps/arch-sysup.svg",
        "arch-sysup.svg",
    ];
    for path in &paths {
        if !std::path::Path::new(path).exists() { continue; }
        // Try rsvg-convert
        if let Ok(out) = Command::new("rsvg-convert")
            .args(["-w","64","-h","64","-f","png", path]).output() {
            if out.status.success() {
                if let Ok(img) = load_png_rgba(&out.stdout) {
                    return Some(img);
                }
            }
        }
    }
    None
}

fn load_png_rgba(data: &[u8]) -> Result<egui::IconData, ()> {
    use image::GenericImageView;
    let img = image::load_from_memory(data).map_err(|_| ())?;
    let rgba = img.to_rgba8();
    let (w, h) = img.dimensions();
    Ok(egui::IconData { rgba: rgba.into_raw(), width: w, height: h })
}
