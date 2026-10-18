//! # starpak
//!
//! Fast, allocation-light reader for Star Citizen `Data.p4k` archives.
//!
//! ```no_run
//! use starpak::Archive;
//!
//! let p4k = Archive::open("Data.p4k")?;
//! println!("{} entries", p4k.len());
//!
//! for e in p4k.glob("Data/Scripts/**/*.xml")? {
//!     println!("{}", e.name());
//! }
//! # Ok::<(), starpak::Error>(())
//! ```
//!
//! The [`Archive`] handle is `Send + Sync` and cheap to clone; reads use
//! positional I/O so many threads can read concurrently without locking.

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

mod archive;
pub mod crypto;
mod entry;
mod error;
pub mod format;
mod tree;
mod util;

pub use archive::{Archive, ArchiveInfo, GlobIter, Iter, OpenOptions};
pub use entry::{DosDateTime, Entry, EntryId, EntryRef, Method};
pub use error::{Error, Result};
pub use tree::{DirId, DirTree};

/// Library version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
