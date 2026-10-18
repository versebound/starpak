//! Directory view over the flat entry list.

use std::collections::HashMap;

use crate::archive::Archive;
use crate::entry::EntryId;
use crate::util::{hash_path, path_eq, trim_lookup_path};

fn file_name(name: &str) -> &str {
    name.rsplit(['\\', '/']).next().unwrap_or(name)
}

fn cmp_ignore_case(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    a.iter()
        .map(u8::to_ascii_lowercase)
        .cmp(b.iter().map(u8::to_ascii_lowercase))
}

/// Index of a directory node inside a [`DirTree`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct DirId(pub u32);

impl DirId {
    /// The root directory.
    pub const ROOT: DirId = DirId(0);
}

struct Node {
    name: Box<str>,
    parent: u32,
    dirs: Vec<DirId>,
    files: Vec<EntryId>,
}

/// Hierarchical view of entry names, built once on demand by
/// [`Archive::tree`]. Directory names keep the case of their first
/// occurrence; lookups are case-insensitive.
pub struct DirTree {
    nodes: Vec<Node>,
    /// (parent, hash of normalised component) -> node
    lookup: HashMap<(u32, u64), u32>,
}

impl DirTree {
    pub(crate) fn build(archive: &Archive) -> DirTree {
        let mut tree = DirTree {
            nodes: vec![Node {
                name: "".into(),
                parent: 0,
                dirs: Vec::new(),
                files: Vec::new(),
            }],
            lookup: HashMap::new(),
        };
        // Consecutive entries almost always share a directory, so the
        // previous directory is reused when the path prefix is unchanged.
        let mut last_prefix: Vec<u8> = Vec::new();
        let mut last_dir = 0u32;
        for e in archive.iter() {
            let name = e.name();
            let split = name.rfind(['\\', '/']).map(|i| i + 1).unwrap_or(0);
            let (prefix, file) = name.split_at(split);
            let dir = if prefix.as_bytes() == last_prefix.as_slice() {
                last_dir
            } else {
                let mut dir = 0u32;
                for comp in prefix.split(['\\', '/']).filter(|c| !c.is_empty()) {
                    dir = tree.child_dir(dir, comp);
                }
                last_prefix.clear();
                last_prefix.extend_from_slice(prefix.as_bytes());
                last_dir = dir;
                dir
            };
            if !file.is_empty() {
                tree.nodes[dir as usize].files.push(e.id());
            }
        }
        for node in &mut tree.nodes {
            node.dirs.shrink_to_fit();
            node.files.shrink_to_fit();
        }
        tree.sort(archive);
        tree
    }

    fn child_dir(&mut self, parent: u32, comp: &str) -> u32 {
        let h = hash_path(comp.as_bytes());
        if let Some(&id) = self.lookup.get(&(parent, h)) {
            if path_eq(self.nodes[id as usize].name.as_bytes(), comp.as_bytes()) {
                return id;
            }
            // Hash collision inside one directory: fall back to a scan.
            if let Some(id) = self.find_child_linear(parent, comp) {
                return id;
            }
        }
        let id = self.nodes.len() as u32;
        self.nodes.push(Node {
            name: comp.into(),
            parent,
            dirs: Vec::new(),
            files: Vec::new(),
        });
        self.nodes[parent as usize].dirs.push(DirId(id));
        self.lookup.entry((parent, h)).or_insert(id);
        id
    }

    fn find_child_linear(&self, parent: u32, comp: &str) -> Option<u32> {
        self.nodes[parent as usize]
            .dirs
            .iter()
            .map(|d| d.0)
            .find(|&d| path_eq(self.nodes[d as usize].name.as_bytes(), comp.as_bytes()))
    }

    fn sort(&mut self, archive: &Archive) {
        for i in 0..self.nodes.len() {
            let mut dirs = std::mem::take(&mut self.nodes[i].dirs);
            dirs.sort_by(|a, b| {
                let x = self.nodes[a.0 as usize].name.as_bytes();
                let y = self.nodes[b.0 as usize].name.as_bytes();
                cmp_ignore_case(x, y)
            });
            self.nodes[i].dirs = dirs;
            self.nodes[i].files.sort_by_cached_key(|id| {
                let name = archive.name(*id).map(file_name).unwrap_or("");
                name.to_ascii_lowercase().into_boxed_str()
            });
        }
    }

    /// Number of directories including the root.
    pub fn dir_count(&self) -> usize {
        self.nodes.len()
    }

    /// Name of a directory (empty for the root).
    pub fn name(&self, dir: DirId) -> &str {
        &self.nodes[dir.0 as usize].name
    }

    /// Parent directory; `None` for the root.
    pub fn parent(&self, dir: DirId) -> Option<DirId> {
        if dir.0 == 0 {
            None
        } else {
            Some(DirId(self.nodes[dir.0 as usize].parent))
        }
    }

    /// Full path of a directory with `/` separators (empty for the root).
    pub fn path(&self, dir: DirId) -> String {
        let mut parts = Vec::new();
        let mut cur = dir;
        while cur.0 != 0 {
            parts.push(self.name(cur));
            cur = DirId(self.nodes[cur.0 as usize].parent);
        }
        parts.reverse();
        parts.join("/")
    }

    /// Sub-directories, sorted by name.
    pub fn dirs(&self, dir: DirId) -> &[DirId] {
        &self.nodes[dir.0 as usize].dirs
    }

    /// Files directly inside the directory, sorted by file name.
    pub fn files(&self, dir: DirId) -> &[EntryId] {
        &self.nodes[dir.0 as usize].files
    }

    /// Finds a directory by path (case-insensitive, either separator).
    pub fn find(&self, path: &str) -> Option<DirId> {
        let mut cur = 0u32;
        for comp in trim_lookup_path(path)
            .split(['\\', '/'])
            .filter(|c| !c.is_empty())
        {
            let h = hash_path(comp.as_bytes());
            let cand =
                self.lookup.get(&(cur, h)).copied().filter(|&id| {
                    path_eq(self.nodes[id as usize].name.as_bytes(), comp.as_bytes())
                });
            cur = cand.or_else(|| self.find_child_linear(cur, comp))?;
        }
        Some(DirId(cur))
    }

    /// Total number of files below `dir` (recursive).
    pub fn file_count(&self, dir: DirId) -> usize {
        let node = &self.nodes[dir.0 as usize];
        node.files.len() + node.dirs.iter().map(|d| self.file_count(*d)).sum::<usize>()
    }

    /// Depth-first walk of every directory below `dir`, including `dir`.
    pub fn walk(&self, dir: DirId) -> Vec<DirId> {
        let mut out = Vec::new();
        let mut stack = vec![dir];
        while let Some(d) = stack.pop() {
            out.push(d);
            stack.extend(self.dirs(d).iter().rev().copied());
        }
        out
    }
}
