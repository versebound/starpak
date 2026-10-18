//! `starpak` command-line tool: inspect, extract and benchmark p4k archives.

mod bench;
mod dcb;
mod util;

use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use clap::{Args, Parser, Subcommand};
use starpak::{Archive, DirId, Entry, EntryId};

#[derive(Parser)]
#[command(name = "starpak", version, about = "Star Citizen Data.p4k reader")]
pub(crate) struct Cli {
    /// Path to Data.p4k (or set STARPAK_P4K).
    #[arg(short = 'p', long = "p4k", global = true, env = "STARPAK_P4K")]
    p4k: Option<PathBuf>,

    /// Read the central directory into memory instead of mmap.
    #[arg(long, global = true)]
    no_mmap: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show container-level information.
    Info,
    /// List entries, optionally filtered by a glob.
    Ls(LsArgs),
    /// Show metadata of one entry (path or #index).
    Stat {
        /// Entry path (case-insensitive) or `#<index>`.
        entry: String,
    },
    /// Write the decoded entry to stdout.
    Cat {
        /// Entry path or `#<index>`.
        entry: String,
        /// Write the stored (compressed/encrypted) bytes instead.
        #[arg(long)]
        raw: bool,
        /// Skip the CRC check.
        #[arg(long)]
        no_verify: bool,
        /// Use the streaming reader instead of the bulk path.
        #[arg(long)]
        stream: bool,
    },
    /// Extract entries matching a glob into a directory.
    Extract {
        /// Glob pattern, e.g. `Data/Scripts/**/*.xml`.
        glob: String,
        /// Output directory.
        dir: PathBuf,
        /// Worker threads.
        #[arg(short = 'j', long, default_value_t = default_threads())]
        jobs: usize,
        /// Convert CryXmlB files to text XML while extracting.
        #[arg(long)]
        xml: bool,
    },
    /// Decode a (Cry)XML entry to text on stdout.
    Xml {
        /// Entry path or `#<index>`.
        entry: String,
    },
    /// Show the directory tree below a path.
    Tree {
        /// Directory path (default: root).
        dir: Option<String>,
        /// Maximum depth to print.
        #[arg(short = 'd', long, default_value_t = 1)]
        depth: usize,
        /// Also list files.
        #[arg(short = 'f', long)]
        files: bool,
    },
    /// Decode and CRC-check entries without writing them anywhere.
    Verify {
        /// Glob pattern (default: everything).
        glob: Option<String>,
        /// Worker threads.
        #[arg(short = 'j', long, default_value_t = default_threads())]
        jobs: usize,
    },
    /// Measure open, listing, lookup and read performance.
    Bench(bench::BenchArgs),
    /// DataForge (Game2.dcb) commands.
    Dcb(dcb::DcbArgs),
}

#[derive(Args)]
struct LsArgs {
    /// Glob pattern (default: everything).
    glob: Option<String>,
    /// Only entries below this prefix.
    #[arg(long)]
    prefix: Option<String>,
    /// Long format: id, method, encryption, sizes, CRC, time.
    #[arg(short = 'l', long)]
    long: bool,
    /// Only print the number of matches.
    #[arg(short = 'c', long)]
    count: bool,
}

pub(crate) fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

pub(crate) type AnyError = Box<dyn std::error::Error>;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if is_broken_pipe(&*e) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// True when the error chain bottoms out in EPIPE (stdout closed early).
fn is_broken_pipe(e: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = cur {
        if let Some(io) = err.downcast_ref::<io::Error>() {
            if io.kind() == io::ErrorKind::BrokenPipe {
                return true;
            }
        }
        if let Some(starpak::Error::Io(io)) = err.downcast_ref::<starpak::Error>() {
            if io.kind() == io::ErrorKind::BrokenPipe {
                return true;
            }
        }
        cur = err.source();
    }
    false
}

fn archive_path(cli: &Cli) -> Result<&Path, AnyError> {
    Ok(cli
        .p4k
        .as_deref()
        .ok_or("no archive given: pass --p4k <PATH> or set STARPAK_P4K")?)
}

pub(crate) fn open(cli: &Cli) -> Result<Archive, AnyError> {
    let opts = starpak::OpenOptions {
        mmap: !cli.no_mmap,
        ..Default::default()
    };
    Ok(Archive::open_with(archive_path(cli)?, opts)?)
}

fn resolve(archive: &Archive, spec: &str) -> Result<Entry, AnyError> {
    if let Some(idx) = spec.strip_prefix('#') {
        let id: u32 = idx.parse()?;
        return Ok(archive.stat(EntryId(id))?);
    }
    Ok(archive.entry_by_path(spec)?)
}

fn run(cli: Cli) -> Result<(), AnyError> {
    match &cli.cmd {
        Cmd::Bench(args) => bench::run(archive_path(&cli)?, !cli.no_mmap, args),
        Cmd::Dcb(args) => dcb::run(&cli, args),
        Cmd::Info => cmd_info(&open(&cli)?),
        Cmd::Ls(args) => cmd_ls(&open(&cli)?, args),
        Cmd::Stat { entry } => cmd_stat(&open(&cli)?, entry),
        Cmd::Cat {
            entry,
            raw,
            no_verify,
            stream,
        } => cmd_cat(&open(&cli)?, entry, *raw, *no_verify, *stream),
        Cmd::Extract {
            glob,
            dir,
            jobs,
            xml,
        } => cmd_extract(&open(&cli)?, glob, dir, *jobs, *xml),
        Cmd::Xml { entry } => {
            let a = open(&cli)?;
            let e = resolve(&a, entry)?;
            let text = a.read_xml_entry(&e)?;
            let mut out = BufWriter::new(io::stdout().lock());
            out.write_all(text.as_bytes())?;
            out.flush()?;
            Ok(())
        }
        Cmd::Tree { dir, depth, files } => cmd_tree(&open(&cli)?, dir.as_deref(), *depth, *files),
        Cmd::Verify { glob, jobs } => cmd_verify(&open(&cli)?, glob.as_deref(), *jobs),
    }
}

fn cmd_info(a: &Archive) -> Result<(), AnyError> {
    let i = a.info();
    println!("entries:      {}", i.entries);
    println!(
        "file size:    {} ({})",
        i.file_size,
        util::human(i.file_size)
    );
    println!("cd offset:    {}", i.cd_offset);
    println!("cd size:      {} ({})", i.cd_size, util::human(i.cd_size));
    println!("eocd offset:  {}", i.eocd_offset);
    println!("zip64:        {}", i.zip64);
    println!("cd mmapped:   {}", i.mmapped);
    println!("comment:      {:?}", String::from_utf8_lossy(&i.comment));
    Ok(())
}

fn cmd_ls(a: &Archive, args: &LsArgs) -> Result<(), AnyError> {
    let mut out = BufWriter::new(io::stdout().lock());
    let mut n = 0usize;
    let mut total = 0u64;
    let mut emit = |e: starpak::EntryRef<'_>| -> io::Result<()> {
        n += 1;
        if args.count {
            return Ok(());
        }
        if args.long {
            let d = e.entry();
            total += d.uncompressed_size;
            writeln!(
                out,
                "{:>7} {:>7} {} {:>12} {:>12} {:08x} {} {}",
                d.id.0,
                d.method,
                if d.encrypted { 'E' } else { '-' },
                d.compressed_size,
                d.uncompressed_size,
                d.crc32c,
                d.modified(),
                d.name
            )
        } else {
            writeln!(out, "{}", e.name())
        }
    };
    match (&args.glob, &args.prefix) {
        (Some(g), Some(p)) => {
            let m = compile(g)?;
            for e in a.with_prefix(p) {
                if m.is_match(Path::new(&e.name().replace('\\', "/"))) {
                    emit(e)?;
                }
            }
        }
        (Some(g), None) => {
            for e in a.glob(g)? {
                emit(e)?;
            }
        }
        (None, Some(p)) => {
            for e in a.with_prefix(p) {
                emit(e)?;
            }
        }
        (None, None) => {
            for e in a.iter() {
                emit(e)?;
            }
        }
    }
    if args.count {
        writeln!(out, "{n}")?;
    } else if args.long {
        writeln!(out, "{n} entries, {} uncompressed", util::human(total))?;
    }
    out.flush()?;
    Ok(())
}

fn cmd_stat(a: &Archive, entry: &str) -> Result<(), AnyError> {
    let e = resolve(a, entry)?;
    println!("name:         {}", e.name);
    println!("id:           {}", e.id.0);
    println!("method:       {} ({})", e.method, e.method.raw());
    println!("encrypted:    {}", e.encrypted);
    println!("compressed:   {}", e.compressed_size);
    println!("uncompressed: {}", e.uncompressed_size);
    println!("crc32c:       {:08x}", e.crc32c);
    println!("modified:     {}", e.modified());
    println!("local header: {}", e.local_header_offset);
    match a.local_header(&e) {
        Ok((h, off)) => {
            println!("data offset:  {off}");
            println!(
                "local sig:    {:08x} (name {} + extra {} bytes)",
                h.signature, h.name_len, h.extra_len
            );
        }
        Err(err) => println!("data offset:  unavailable ({err})"),
    }
    println!("flags:        {:#06x}", e.flags);
    println!(
        "version:      made by {} / needs {}",
        e.version_made_by, e.version_needed
    );
    Ok(())
}

fn cmd_cat(
    a: &Archive,
    entry: &str,
    raw: bool,
    no_verify: bool,
    stream: bool,
) -> Result<(), AnyError> {
    let e = resolve(a, entry)?;
    let mut out = BufWriter::new(io::stdout().lock());
    if raw {
        out.write_all(&a.read_raw(e.id)?)?;
    } else if stream {
        let mut r = a.open_entry_stream(&e)?.verify(!no_verify);
        io::copy(&mut r, &mut out)?;
    } else {
        let mut buf = Vec::new();
        a.read_entry_into(&e, &mut buf, !no_verify)?;
        out.write_all(&buf)?;
    }
    out.flush()?;
    Ok(())
}

fn cmd_extract(
    a: &Archive,
    glob: &str,
    dir: &Path,
    jobs: usize,
    xml: bool,
) -> Result<(), AnyError> {
    let ids: Vec<EntryId> = a.glob(glob)?.map(|e| e.id()).collect();
    if ids.is_empty() {
        return Err(format!("no entries match {glob:?}").into());
    }
    let t0 = Instant::now();
    let bytes = AtomicUsize::new(0);
    let next = AtomicUsize::new(0);
    let failures = AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..jobs.max(1).min(ids.len()) {
            s.spawn(|| {
                let mut buf = Vec::new();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= ids.len() {
                        break;
                    }
                    let e = match a.stat(ids[i]) {
                        Ok(e) => e,
                        Err(err) => {
                            eprintln!("error: {err}");
                            failures.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    };
                    buf.clear();
                    if let Err(err) = extract_one(a, &e, dir, xml, &mut buf) {
                        eprintln!("error: {}: {err}", e.name);
                        failures.fetch_add(1, Ordering::Relaxed);
                    } else {
                        bytes.fetch_add(buf.len(), Ordering::Relaxed);
                    }
                }
            });
        }
    });
    let dt = t0.elapsed();
    let b = bytes.load(Ordering::Relaxed) as u64;
    let failed = failures.load(Ordering::Relaxed);
    eprintln!(
        "extracted {} entries, {} in {:.2?} ({}/s), {} failed",
        ids.len() - failed,
        util::human(b),
        dt,
        util::human((b as f64 / dt.as_secs_f64()) as u64),
        failed
    );
    if failed > 0 {
        return Err("some entries failed".into());
    }
    Ok(())
}

fn cmd_tree(a: &Archive, dir: Option<&str>, depth: usize, files: bool) -> Result<(), AnyError> {
    let t0 = Instant::now();
    let tree = a.tree();
    let built = t0.elapsed();
    let root = match dir {
        Some(d) => tree
            .find(d)
            .ok_or_else(|| format!("directory not found: {d}"))?,
        None => DirId::ROOT,
    };
    let mut out = BufWriter::new(io::stdout().lock());
    print_tree(a, tree, root, 0, depth, files, &mut out)?;
    writeln!(
        out,
        "{} directories, {} files below {:?} (tree built in {:.2?})",
        tree.walk(root).len(),
        tree.file_count(root),
        tree.path(root),
        built
    )?;
    out.flush()?;
    Ok(())
}

fn cmd_verify(a: &Archive, glob: Option<&str>, jobs: usize) -> Result<(), AnyError> {
    let ids: Vec<EntryId> = match glob {
        Some(g) => a.glob(g)?.map(|e| e.id()).collect(),
        None => (0..a.len() as u32).map(EntryId).collect(),
    };
    let t0 = Instant::now();
    let next = AtomicUsize::new(0);
    let failures = AtomicUsize::new(0);
    let bytes = AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..jobs.max(1).min(ids.len().max(1)) {
            s.spawn(|| {
                let mut buf = Vec::new();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= ids.len() {
                        break;
                    }
                    buf.clear();
                    match a.read_into(ids[i], &mut buf) {
                        Ok(()) => {
                            bytes.fetch_add(buf.len(), Ordering::Relaxed);
                        }
                        Err(err) => {
                            eprintln!("FAIL {err}");
                            failures.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            });
        }
    });
    let dt = t0.elapsed();
    let b = bytes.load(Ordering::Relaxed) as u64;
    let failed = failures.load(Ordering::Relaxed);
    println!(
        "verified {} entries ({}) in {:.2?} ({}/s), {} failed",
        ids.len(),
        util::human(b),
        dt,
        util::human((b as f64 / dt.as_secs_f64()) as u64),
        failed
    );
    if failed > 0 {
        return Err("verification failed".into());
    }
    Ok(())
}

fn compile(glob: &str) -> Result<globset::GlobMatcher, globset::Error> {
    Ok(globset::GlobBuilder::new(&glob.replace('\\', "/"))
        .case_insensitive(true)
        .literal_separator(false)
        .backslash_escape(false)
        .build()?
        .compile_matcher())
}

fn extract_one(
    a: &Archive,
    e: &Entry,
    dir: &Path,
    xml: bool,
    buf: &mut Vec<u8>,
) -> Result<(), AnyError> {
    let rel: PathBuf = e
        .name
        .split(['\\', '/'])
        .filter(|c| !c.is_empty() && *c != "..")
        .collect();
    let target = dir.join(rel);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    a.read_entry_into(e, buf, true)?;
    if xml && starpak::cryxml::is_cryxmlb(buf) {
        let text = starpak::cryxml::to_xml(buf)?;
        std::fs::write(&target, text.as_bytes())?;
    } else {
        std::fs::write(&target, &buf)?;
    }
    Ok(())
}

fn print_tree(
    a: &Archive,
    tree: &starpak::DirTree,
    dir: DirId,
    level: usize,
    max_depth: usize,
    files: bool,
    out: &mut impl Write,
) -> io::Result<()> {
    let indent = "  ".repeat(level);
    if level == 0 {
        writeln!(out, "{}/", tree.path(dir))?;
    } else {
        writeln!(out, "{indent}{}/", tree.name(dir))?;
    }
    if level >= max_depth {
        return Ok(());
    }
    for d in tree.dirs(dir) {
        print_tree(a, tree, *d, level + 1, max_depth, files, out)?;
    }
    if files {
        for f in tree.files(dir) {
            if let Some(e) = a.entry(*f) {
                writeln!(
                    out,
                    "{indent}  {} ({})",
                    e.file_name(),
                    util::human(e.uncompressed_size)
                )?;
            }
        }
    }
    Ok(())
}
