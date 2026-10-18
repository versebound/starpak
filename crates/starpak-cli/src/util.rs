//! Formatting and measurement helpers for the CLI.

/// Human-readable byte count.
pub fn human(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

/// Resident-set figures of the current process, in bytes (Linux only).
#[derive(Debug, Clone, Copy, Default)]
pub struct Rss {
    pub total: u64,
    pub anon: u64,
    pub file: u64,
    pub peak: u64,
}

pub fn rss() -> Option<Rss> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let mut r = Rss::default();
    for line in status.lines() {
        let (key, rest) = match line.split_once(':') {
            Some(kv) => kv,
            None => continue,
        };
        let kib: u64 = rest
            .trim()
            .trim_end_matches("kB")
            .trim()
            .parse()
            .unwrap_or(0);
        match key {
            "VmRSS" => r.total = kib * 1024,
            "RssAnon" => r.anon = kib * 1024,
            "RssFile" => r.file = kib * 1024,
            "VmHWM" => r.peak = kib * 1024,
            _ => {}
        }
    }
    Some(r)
}

/// Small deterministic PRNG (xorshift64*).
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed.max(1))
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n.max(1) as u64) as usize
    }
}
