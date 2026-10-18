//! `starpak dcb`: DataForge (Game2.dcb) inspection and benchmarks.

use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::time::Instant;

use clap::{Args, Subcommand};
use starpak::dataforge::{DataForge, ExportOptions, Guid, Record, Value};

use crate::util::{human, rss};
use crate::{open, AnyError, Cli};

#[derive(Args)]
pub struct DcbArgs {
    /// Read the database from a .dcb file instead of the archive.
    #[arg(long, global = true)]
    dcb: Option<PathBuf>,
    /// Entry path of the database inside the archive.
    #[arg(long, global = true, default_value = starpak::dataforge::DEFAULT_PATH)]
    entry: String,
    #[command(subcommand)]
    cmd: DcbCmd,
}

#[derive(Subcommand)]
enum DcbCmd {
    /// Show database statistics.
    Info,
    /// List records.
    Records {
        /// Only records of this struct type (including subtypes).
        #[arg(long = "type")]
        type_name: Option<String>,
        /// Only records whose file name matches this glob.
        #[arg(long)]
        path: Option<String>,
        /// Only records with this tag (v8+).
        #[arg(long)]
        tag: Option<String>,
        /// Only main (per-file) records.
        #[arg(long)]
        main: bool,
        /// Stop after this many rows.
        #[arg(long)]
        limit: Option<usize>,
        /// Print GUID, type, tag and file name.
        #[arg(short = 'l', long)]
        long: bool,
    },
    /// Export one record (by GUID, file name or record name).
    Get {
        /// GUID, `libs/foundry/...` path or `Type.Name`.
        key: String,
        /// Emit JSON instead of XML.
        #[arg(long)]
        json: bool,
        /// Emit unp4k-style XML (default).
        #[arg(long)]
        xml: bool,
        /// Print the record's own fields without resolving pointers.
        #[arg(long)]
        fields: bool,
    },
    /// List struct types.
    Types {
        /// Substring filter (case-insensitive).
        #[arg(long)]
        search: Option<String>,
        /// Show properties of each listed type.
        #[arg(short = 'p', long)]
        props: bool,
    },
    /// List enums and their options.
    Enums {
        /// Substring filter (case-insensitive).
        #[arg(long)]
        search: Option<String>,
    },
    /// Measure load time, memory and record decoding throughput.
    Bench {
        /// Also export every record to XML (slow).
        #[arg(long)]
        export: bool,
    },
}

fn load(cli: &Cli, args: &DcbArgs) -> Result<(DataForge, std::time::Duration), AnyError> {
    let t = Instant::now();
    let df = match &args.dcb {
        Some(p) => DataForge::open(p)?,
        None => DataForge::from_archive_path(&open(cli)?, &args.entry)?,
    };
    Ok((df, t.elapsed()))
}

pub fn run(cli: &Cli, args: &DcbArgs) -> Result<(), AnyError> {
    match &args.cmd {
        DcbCmd::Info => {
            let (df, dt) = load(cli, args)?;
            let i = df.info();
            println!("version:        {}", i.version);
            println!("size:           {} ({})", i.size, human(i.size as u64));
            println!("structs:        {}", i.structs);
            println!("properties:     {}", i.properties);
            println!("enums:          {}", i.enums);
            println!("records:        {}", i.records);
            println!("files:          {}", df.file_count());
            println!("instance data:  {}", human(i.instance_bytes as u64));
            println!(
                "string tables:  {} values + {} names",
                human(i.string_table_bytes as u64),
                human(i.name_table_bytes as u64)
            );
            println!(
                "pointers:       {} strong, {} weak, {} references",
                i.strong_pointers, i.weak_pointers, i.references
            );
            println!("loaded in:      {dt:.2?}");
            Ok(())
        }
        DcbCmd::Records {
            type_name,
            path,
            tag,
            main,
            limit,
            long,
        } => {
            let (df, _) = load(cli, args)?;
            let mut out = BufWriter::new(io::stdout().lock());
            let glob = path.as_deref().map(compile).transpose()?;
            let type_id = match type_name {
                Some(t) => Some(
                    df.find_struct(t)
                        .ok_or_else(|| format!("unknown struct type {t:?}"))?
                        .id(),
                ),
                None => None,
            };
            let mut n = 0usize;
            for r in df.records() {
                if let Some(t) = type_id {
                    if !r.struct_def().is_a(t) {
                        continue;
                    }
                }
                if let Some(g) = &glob {
                    if !g.is_match(std::path::Path::new(&r.file_name().replace('\\', "/"))) {
                        continue;
                    }
                }
                if let Some(t) = tag {
                    if !r.tag().eq_ignore_ascii_case(t) {
                        continue;
                    }
                }
                if *main && !r.is_main() {
                    continue;
                }
                n += 1;
                if *long {
                    writeln!(
                        out,
                        "{} {:<32} {:<14} {} {}",
                        r.guid(),
                        r.type_name(),
                        r.tag(),
                        r.name(),
                        r.file_name()
                    )?;
                } else {
                    writeln!(out, "{} {}", r.guid(), r.name())?;
                }
                if limit.is_some_and(|l| n >= l) {
                    break;
                }
            }
            out.flush()?;
            eprintln!("{n} records");
            Ok(())
        }
        DcbCmd::Get {
            key,
            json,
            xml: _,
            fields,
        } => {
            let (df, _) = load(cli, args)?;
            let r = find_record(&df, key)?;
            let mut out = BufWriter::new(io::stdout().lock());
            if *fields {
                let inst = r.instance()?;
                writeln!(
                    out,
                    "{} ({}) {} {}",
                    r.name(),
                    r.type_name(),
                    r.guid(),
                    r.file_name()
                )?;
                for f in inst.fields() {
                    let v = f.value()?;
                    let shown = match &v {
                        Value::Array(a) => format!("{}[{}]", a.data_type().name(), a.len()),
                        other => format!("{other:?}"),
                    };
                    writeln!(
                        out,
                        "  {:<40} {:<28} {}",
                        f.name(),
                        f.prop().type_name(),
                        shown
                    )?;
                }
            } else if *json {
                out.write_all(
                    starpak::dataforge::to_json(&r, &ExportOptions::default())?.as_bytes(),
                )?;
            } else {
                out.write_all(r.to_xml()?.as_bytes())?;
            }
            out.flush()?;
            Ok(())
        }
        DcbCmd::Types { search, props } => {
            let (df, _) = load(cli, args)?;
            let mut out = BufWriter::new(io::stdout().lock());
            let needle = search.as_deref().map(str::to_ascii_lowercase);
            let mut n = 0;
            for s in df.structs() {
                if needle
                    .as_ref()
                    .is_some_and(|q| !s.name().to_ascii_lowercase().contains(q.as_str()))
                {
                    continue;
                }
                n += 1;
                writeln!(
                    out,
                    "{:<48} parent={:<32} size={:<6} instances={}",
                    s.name(),
                    s.parent().map(|p| p.name()).unwrap_or("-"),
                    s.size(),
                    s.instance_count()
                )?;
                if *props {
                    for p in s.properties() {
                        writeln!(
                            out,
                            "    +{:<5} {:<36} {}",
                            p.offset(),
                            p.name(),
                            p.type_name()
                        )?;
                    }
                }
            }
            out.flush()?;
            eprintln!("{n} types");
            Ok(())
        }
        DcbCmd::Enums { search } => {
            let (df, _) = load(cli, args)?;
            let mut out = BufWriter::new(io::stdout().lock());
            let needle = search.as_deref().map(str::to_ascii_lowercase);
            for e in df.enums() {
                if needle
                    .as_ref()
                    .is_some_and(|q| !e.name().to_ascii_lowercase().contains(q.as_str()))
                {
                    continue;
                }
                writeln!(
                    out,
                    "{}: {}",
                    e.name(),
                    e.values().collect::<Vec<_>>().join(", ")
                )?;
            }
            out.flush()?;
            Ok(())
        }
        DcbCmd::Bench { export } => bench(cli, args, *export),
    }
}

fn compile(glob: &str) -> Result<globset::GlobMatcher, globset::Error> {
    Ok(globset::GlobBuilder::new(&glob.replace('\\', "/"))
        .case_insensitive(true)
        .literal_separator(false)
        .backslash_escape(false)
        .build()?
        .compile_matcher())
}

fn find_record<'a>(df: &'a DataForge, key: &str) -> Result<Record<'a>, AnyError> {
    if let Ok(g) = key.parse::<Guid>() {
        return Ok(df
            .record_by_guid(g)
            .ok_or_else(|| format!("no record with GUID {g}"))?);
    }
    if let Some(r) = df.record_by_path(key) {
        return Ok(r);
    }
    if let Some(r) = df.records().find(|r| r.name().eq_ignore_ascii_case(key)) {
        return Ok(r);
    }
    Err(
        format!("no record matches {key:?} (expected a GUID, a libs/... path or a Type.Name)")
            .into(),
    )
}

/// Visits every value reachable through classes, arrays and strong pointers.
fn walk(
    inst: &starpak::dataforge::Instance<'_>,
    depth: usize,
    stats: &mut (u64, u64),
) -> Result<(), AnyError> {
    stats.0 += 1;
    for f in inst.fields() {
        let v = f.value()?;
        stats.1 += 1;
        match v {
            Value::Class(i) => walk(&i, depth, stats)?,
            Value::StrongPointer(Some(p)) if depth < 64 => {
                if let Some(i) = inst.database().deref(Some(p))? {
                    walk(&i, depth + 1, stats)?;
                }
            }
            Value::Array(a) => {
                for item in a.iter() {
                    stats.1 += 1;
                    match item? {
                        Value::Class(i) => walk(&i, depth, stats)?,
                        Value::StrongPointer(Some(p)) if depth < 64 => {
                            if let Some(i) = inst.database().deref(Some(p))? {
                                walk(&i, depth + 1, stats)?;
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn bench(cli: &Cli, args: &DcbArgs, export: bool) -> Result<(), AnyError> {
    let before = rss().unwrap_or_default();
    let t = Instant::now();
    let raw = match &args.dcb {
        Some(p) => std::fs::read(p)?,
        None => open(cli)?.read_path(&args.entry)?,
    };
    let read_dt = t.elapsed();
    let size = raw.len();
    let t = Instant::now();
    let df = DataForge::parse(raw)?;
    let parse_dt = t.elapsed();
    let after = rss().unwrap_or_default();
    println!(
        "read {} in {:.2?}; parse {:.2?}; rss {} (anon delta {})",
        human(size as u64),
        read_dt,
        parse_dt,
        human(after.total),
        human(after.anon.saturating_sub(before.anon))
    );
    let i = df.info();
    println!(
        "version {} | {} structs, {} properties, {} enums, {} records",
        i.version, i.structs, i.properties, i.enums, i.records
    );

    let t = Instant::now();
    let first = df.records().next().map(|r| r.guid());
    let hit = first.and_then(|g| df.record_by_guid(g)).is_some();
    println!("guid index: {:.2?} (lookup ok: {hit})", t.elapsed());
    let t = Instant::now();
    let files = df.file_count();
    println!("file index: {:.2?} ({files} files)", t.elapsed());

    let t = Instant::now();
    let mut stats = (0u64, 0u64);
    let mut errors = 0usize;
    for r in df.records() {
        match r.instance() {
            Ok(inst) => {
                if let Err(e) = walk(&inst, 0, &mut stats) {
                    errors += 1;
                    if errors <= 3 {
                        eprintln!("{}: {e}", r.name());
                    }
                }
            }
            Err(e) => {
                errors += 1;
                if errors <= 3 {
                    eprintln!("{}: {e}", r.name());
                }
            }
        }
    }
    let dt = t.elapsed();
    println!(
        "decode all records: {:.2?} ({} records, {} instances, {} values, {:.1} M values/s, {errors} errors)",
        dt,
        i.records,
        stats.0,
        stats.1,
        stats.1 as f64 / dt.as_secs_f64() / 1e6
    );

    if export {
        let t = Instant::now();
        let mut bytes = 0usize;
        let mut errors = 0usize;
        for r in df.records() {
            match r.to_xml() {
                Ok(x) => bytes += x.len(),
                Err(e) => {
                    errors += 1;
                    if errors <= 3 {
                        eprintln!("{}: {e}", r.name());
                    }
                }
            }
        }
        let dt = t.elapsed();
        println!(
            "export all records to XML: {:.2?} ({} of XML, {}/s, {errors} errors)",
            dt,
            human(bytes as u64),
            human((bytes as f64 / dt.as_secs_f64()) as u64)
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
