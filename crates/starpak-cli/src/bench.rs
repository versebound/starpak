//! `starpak bench`: open / list / lookup / read measurements.

use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use clap::Args;
use starpak::{Archive, EntryId, OpenOptions};

use crate::util::{human, rss, Rng};
use crate::AnyError;

#[derive(Args)]
pub struct BenchArgs {
    /// Number of random entries to read.
    #[arg(long, default_value_t = 4000)]
    sample: usize,
    /// Skip entries larger than this many bytes (uncompressed).
    #[arg(long, default_value_t = 64 << 20)]
    max_size: u64,
    /// Threads for the parallel read phase.
    #[arg(short = 'j', long, default_value_t = crate::default_threads())]
    jobs: usize,
    /// PRNG seed for sampling.
    #[arg(long, default_value_t = 42)]
    seed: u64,
    /// Restrict the sample to entries matching a glob.
    #[arg(long)]
    glob: Option<String>,
    /// Number of path lookups to time.
    #[arg(long, default_value_t = 200_000)]
    lookups: usize,
    /// Skip the read phases.
    #[arg(long)]
    no_read: bool,
}

fn rate(bytes: u64, dt: Duration) -> String {
    format!(
        "{}/s",
        human((bytes as f64 / dt.as_secs_f64().max(1e-9)) as u64)
    )
}

pub fn run(path: &Path, mmap: bool, args: &BenchArgs) -> Result<(), AnyError> {
    let before = rss().unwrap_or_default();
    println!("archive: {}", path.display());
    println!(
        "rss before open: {} (anon {})",
        human(before.total),
        human(before.anon)
    );

    // --- open ---
    let t = Instant::now();
    let a = Archive::open_with(
        path,
        OpenOptions {
            mmap,
            ..Default::default()
        },
    )?;
    let open_dt = t.elapsed();
    let after = rss().unwrap_or_default();
    let info = a.info();
    println!(
        "open: {:.2?}  entries {}  cd {} ({})",
        open_dt,
        info.entries,
        human(info.cd_size),
        if info.mmapped { "mmap" } else { "heap" }
    );
    println!(
        "rss after open: {} (anon {}, file-backed {}); delta anon {}",
        human(after.total),
        human(after.anon),
        human(after.file),
        human(after.anon.saturating_sub(before.anon))
    );

    // --- list ---
    let t = Instant::now();
    let mut name_bytes = 0usize;
    for e in a.iter() {
        name_bytes += e.name().len();
    }
    let list_dt = t.elapsed();
    println!(
        "list names: {:.2?} ({} names, {} of name bytes, {:.0} ns/entry)",
        list_dt,
        a.len(),
        human(name_bytes as u64),
        list_dt.as_nanos() as f64 / a.len().max(1) as f64
    );

    let t = Instant::now();
    let mut total_u = 0u64;
    let mut total_c = 0u64;
    let mut enc = 0usize;
    for e in a.iter() {
        let d = e.entry();
        total_u += d.uncompressed_size;
        total_c += d.compressed_size;
        enc += d.encrypted as usize;
    }
    let stat_dt = t.elapsed();
    println!(
        "decode all metadata: {:.2?} ({:.0} ns/entry; {} stored, {} uncompressed, {} encrypted)",
        stat_dt,
        stat_dt.as_nanos() as f64 / a.len().max(1) as f64,
        human(total_c),
        human(total_u),
        enc
    );

    // --- glob ---
    let t = Instant::now();
    let xml = a.glob("**/*.xml")?.count();
    println!("glob **/*.xml: {:.2?} ({xml} matches)", t.elapsed());

    // --- lookup ---
    let mut rng = Rng::new(args.seed);
    let names: Vec<String> = (0..args.lookups.min(a.len()))
        .map(|_| {
            let id = EntryId(rng.below(a.len()) as u32);
            a.name(id)
                .unwrap_or("")
                .replace('\\', "/")
                .to_ascii_uppercase()
        })
        .collect();
    let t = Instant::now();
    let first = a.find(names.first().map(String::as_str).unwrap_or(""));
    let index_dt = t.elapsed();
    println!(
        "name index build (first lookup): {:.2?}{}",
        index_dt,
        if first.is_some() {
            ""
        } else {
            " [lookup failed]"
        }
    );
    let t = Instant::now();
    let mut hits = 0usize;
    for n in &names {
        hits += a.find(n).is_some() as usize;
    }
    let lookup_dt = t.elapsed();
    println!(
        "lookups: {} in {:.2?} ({:.0} ns/lookup, {} hits)",
        names.len(),
        lookup_dt,
        lookup_dt.as_nanos() as f64 / names.len().max(1) as f64,
        hits
    );
    let mid = rss().unwrap_or_default();
    println!(
        "rss after index: {} (anon {}; delta anon since open {})",
        human(mid.total),
        human(mid.anon),
        human(mid.anon.saturating_sub(after.anon))
    );

    // --- tree ---
    let t = Instant::now();
    let tree = a.tree();
    println!(
        "directory tree: {:.2?} ({} directories)",
        t.elapsed(),
        tree.dir_count()
    );

    if args.no_read {
        return Ok(());
    }

    // --- sample ---
    let pool: Vec<EntryId> = match &args.glob {
        Some(g) => a.glob(g)?.map(|e| e.id()).collect(),
        None => (0..a.len() as u32).map(EntryId).collect(),
    };
    let mut sample = Vec::with_capacity(args.sample);
    let mut tries = 0;
    while sample.len() < args.sample && tries < args.sample * 20 && !pool.is_empty() {
        tries += 1;
        let id = pool[rng.below(pool.len())];
        let e = match a.entry(id) {
            Some(e) => e,
            None => continue,
        };
        if e.uncompressed_size <= args.max_size && !e.is_dir() && e.method.is_supported() {
            sample.push(e);
        }
    }
    if sample.is_empty() {
        println!("no entries to sample");
        return Ok(());
    }
    let sample_u: u64 = sample.iter().map(|e| e.uncompressed_size).sum();
    let sample_c: u64 = sample.iter().map(|e| e.compressed_size).sum();
    println!(
        "sample: {} entries, {} stored -> {} uncompressed (max {})",
        sample.len(),
        human(sample_c),
        human(sample_u),
        human(args.max_size)
    );

    // --- single-thread random read (bulk, CRC verified) ---
    // First pass is whatever the page cache holds (cold after a reboot),
    // second pass is warm; both are reported.
    let mut buf = Vec::new();
    for pass in ["first pass", "warm"] {
        let t = Instant::now();
        let mut errors = 0usize;
        for e in &sample {
            buf.clear();
            if a.read_entry_into(e, &mut buf, true).is_err() {
                errors += 1;
            }
        }
        let dt = t.elapsed();
        println!(
            "read 1 thread (bulk+crc, {pass}): {:.2?}  {:.0} entries/s  in {}  out {}  errors {}",
            dt,
            sample.len() as f64 / dt.as_secs_f64(),
            rate(sample_c, dt),
            rate(sample_u, dt),
            errors
        );
    }

    // --- single-thread streaming read ---
    let stream_n = sample.len().min(500);
    let t = Instant::now();
    let mut sink = vec![0u8; 256 << 10];
    let mut out_bytes = 0u64;
    for e in &sample[..stream_n] {
        if let Ok(mut r) = a.open_entry_stream(e) {
            while let Ok(n) = r.read(&mut sink) {
                if n == 0 {
                    break;
                }
                out_bytes += n as u64;
            }
        }
    }
    let dt = t.elapsed();
    println!(
        "read 1 thread (stream+crc): {:.2?}  {stream_n} entries  out {}",
        dt,
        rate(out_bytes, dt)
    );

    // --- parallel read (warm) ---
    {
        let jobs = args.jobs.max(1);
        let next = AtomicUsize::new(0);
        let bytes = AtomicU64::new(0);
        let errs = AtomicUsize::new(0);
        let t = Instant::now();
        std::thread::scope(|s| {
            for _ in 0..jobs {
                s.spawn(|| {
                    let mut buf = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= sample.len() {
                            break;
                        }
                        buf.clear();
                        match a.read_entry_into(&sample[i], &mut buf, true) {
                            Ok(()) => {
                                bytes.fetch_add(buf.len() as u64, Ordering::Relaxed);
                            }
                            Err(_) => {
                                errs.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                });
            }
        });
        let dt = t.elapsed();
        println!(
            "read {jobs} threads (bulk+crc): {:.2?}  {:.0} entries/s  in {}  out {}  errors {}",
            dt,
            sample.len() as f64 / dt.as_secs_f64(),
            rate(sample_c, dt),
            rate(bytes.load(Ordering::Relaxed), dt),
            errs.load(Ordering::Relaxed)
        );
    }

    let end = rss().unwrap_or_default();
    println!(
        "rss at end: {} (anon {}, peak {})",
        human(end.total),
        human(end.anon),
        human(end.peak)
    );
    Ok(())
}
