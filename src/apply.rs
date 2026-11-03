//! Writing ACLs: single item, recursive replace, recursive re-propagation,
//! with an optional backup file that `n4acl --restore` can replay.

use crate::ace::{self, Ace, INHERITED};
use crate::ids::IdDb;
use crate::model;
use crate::sys;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    This,
    Replace,
    Repropagate,
}

impl Scope {
    pub const ALL: [Scope; 3] = [Scope::This, Scope::Replace, Scope::Repropagate];
    pub fn label(self) -> &'static str {
        match self {
            Scope::This => "this item only",
            Scope::Replace => "recursive: same ACL on everything below",
            Scope::Repropagate => "recursive: keep children's own entries, refresh inherited",
        }
    }
}

#[derive(Default, Debug)]
pub struct Report {
    pub changed: usize,
    pub unchanged: usize,
    /// symlinks, special files and other datasets that were not touched
    pub skipped: usize,
    pub errors: Vec<(PathBuf, String)>,
    pub samples: Vec<(PathBuf, usize, usize)>,
    pub backup: Option<PathBuf>,
}

/// Paths are stored byte-exact: printable ASCII as-is, everything else as \xHH.
fn escape_path(p: &Path) -> String {
    let mut s = String::new();
    for &b in p.as_os_str().as_bytes() {
        if (0x21..0x7f).contains(&b) && b != b'\\' {
            s.push(b as char);
        } else {
            s.push_str(&format!("\\x{b:02x}"));
        }
    }
    s
}

fn unescape_path(s: &str) -> Option<PathBuf> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            let hex = s.get(i + 2..i + 4)?;
            if b.get(i + 1) != Some(&b'x') {
                return None;
            }
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(PathBuf::from(OsStr::from_bytes(&out)))
}

struct Backup {
    f: File,
    ids: IdDb,
    records: usize,
}

impl Backup {
    fn create(dir: &Path) -> io::Result<(Self, PathBuf)> {
        fs::create_dir_all(dir)?;
        let base = format!("backup-{}", stamp());
        for n in 0..100 {
            let name = if n == 0 { format!("{base}.acl") } else { format!("{base}-{n}.acl") };
            let path = dir.join(name);
            match OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path) {
                Ok(mut f) => {
                    writeln!(f, "# n4acl backup {} - numeric ids. Restore with: n4acl --restore {}", stamp(), path.display())?;
                    return Ok((Backup { f, ids: IdDb::numeric(), records: 0 }, path));
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::other("too many backups with the same timestamp"))
    }

    /// Written and flushed before the ACL is changed, so an interrupted run
    /// can always be undone.
    fn record(&mut self, p: &Path, acl: &[Ace]) -> io::Result<()> {
        let mut s = format!("path {}\n", escape_path(p));
        for a in acl {
            s.push_str(&format!("  {}\n", ace::ace_text(a, &self.ids, true)));
        }
        self.f.write_all(s.as_bytes())?;
        self.f.flush()?;
        self.records += 1;
        Ok(())
    }
}

/// UTC timestamp like 20261103-203015 without extra dependencies.
pub fn stamp() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64;
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    // civil-from-days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}{m:02}{d:02}-{:02}{:02}{:02}", rem / 3600, rem / 60 % 60, rem % 60)
}

pub fn backup_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("N4ACL_BACKUP_DIR") {
        return d.into();
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".n4acl")).unwrap_or_else(|| "/var/tmp".into())
}

pub struct Job<'a> {
    pub root: &'a Path,
    pub acl: &'a [Ace],
    pub scope: Scope,
    pub aclinherit: Option<&'a str>,
    pub dry_run: bool,
    pub backup: bool,
}

struct Walker<'a> {
    job: &'a Job<'a>,
    dev: u64,
    rep: Report,
    bk: Option<Backup>,
}

pub fn run(job: &Job) -> Report {
    let mut rep = Report::default();
    let dev = match fs::metadata(job.root) {
        Ok(m) => m.dev(),
        Err(e) => {
            rep.errors.push((job.root.to_path_buf(), e.to_string()));
            return rep;
        }
    };
    let mut bk = None;
    if job.backup && !job.dry_run {
        match Backup::create(&backup_dir()) {
            Ok((b, path)) => {
                bk = Some(b);
                rep.backup = Some(path);
            }
            Err(e) => {
                rep.errors.push((backup_dir(), format!("cannot create backup ({e}); nothing was written")));
                return rep;
            }
        }
    }
    let mut w = Walker { job, dev, rep, bk };
    if let Some(old) = w.read(job.root) {
        w.apply(job.root, old, job.acl.to_vec());
        if job.scope != Scope::This {
            w.walk(job.root, job.acl);
        }
    }
    let mut rep = w.rep;
    if let (Some(b), Some(p)) = (&w.bk, &rep.backup)
        && b.records == 0
    {
        let _ = fs::remove_file(p); // nothing changed: do not leave empty backups
        rep.backup = None;
    }
    rep
}

impl Walker<'_> {
    fn err(&mut self, p: &Path, e: impl ToString) {
        self.rep.errors.push((p.to_path_buf(), e.to_string()));
    }

    fn read(&mut self, p: &Path) -> Option<Vec<Ace>> {
        sys::get_acl(p).map_err(|e| self.err(p, e)).ok()
    }

    fn apply(&mut self, p: &Path, old: Vec<Ace>, new: Vec<Ace>) {
        if old == new {
            self.rep.unchanged += 1;
            return;
        }
        if self.rep.samples.len() < 12 {
            self.rep.samples.push((p.to_path_buf(), old.len(), new.len()));
        }
        if self.job.dry_run {
            self.rep.changed += 1;
            return;
        }
        if let Some(b) = &mut self.bk
            && let Err(e) = b.record(p, &old)
        {
            self.err(p, format!("backup write failed, not changed: {e}"));
            return;
        }
        match sys::set_acl(p, &new) {
            Ok(()) => self.rep.changed += 1,
            Err(e) => self.err(p, e),
        }
    }

    fn walk(&mut self, dir: &Path, dir_acl: &[Ace]) {
        let mut entries = Vec::new();
        match fs::read_dir(dir) {
            Ok(rd) => {
                for e in rd {
                    match e {
                        Ok(e) => entries.push(e.path()),
                        Err(e) => self.err(dir, e),
                    }
                }
            }
            Err(e) => return self.err(dir, e),
        }
        entries.sort();
        for p in entries {
            let md = match fs::symlink_metadata(&p) {
                Ok(m) => m,
                Err(e) => {
                    self.err(&p, e);
                    continue;
                }
            };
            let ft = md.file_type();
            if ft.is_symlink() || md.dev() != self.dev || !(ft.is_dir() || ft.is_file()) {
                self.rep.skipped += 1; // never follow symlinks or cross into other datasets
                continue;
            }
            let is_dir = ft.is_dir();
            let Some(old) = self.read(&p) else { continue };
            let new = match self.job.scope {
                Scope::This => unreachable!(),
                Scope::Replace if is_dir => dir_acl.to_vec(),
                Scope::Replace => model::for_file(dir_acl),
                Scope::Repropagate => {
                    let mut own: Vec<Ace> = old.iter().filter(|a| !a.has(INHERITED)).copied().collect();
                    own.extend(model::inherit(dir_acl, is_dir, self.job.aclinherit));
                    own
                }
            };
            if new.is_empty() {
                self.err(&p, "would end up with an empty ACL; left unchanged");
                continue;
            }
            self.apply(&p, old, new.clone());
            if is_dir {
                self.walk(&p, &new);
            }
        }
    }
}

/// Replay a backup file. Returns (restored, errors).
pub fn restore(file: &Path) -> io::Result<(usize, Vec<(PathBuf, String)>)> {
    let text = fs::read_to_string(file)?;
    let ids = IdDb::numeric();
    let mut items: Vec<(PathBuf, String)> = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if let Some(p) = line.strip_prefix("path ") {
            let path = unescape_path(p).ok_or_else(|| io::Error::other(format!("line {}: bad path", n + 1)))?;
            items.push((path, String::new()));
        } else if let Some(last) = items.last_mut()
            && line.starts_with("  ")
        {
            last.1.push_str(line.trim());
            last.1.push('\n');
        } else if !line.starts_with('#') && !line.trim().is_empty() {
            return Err(io::Error::other(format!("line {}: not an n4acl backup line", n + 1)));
        }
    }
    let (mut ok, mut errs) = (0, Vec::new());
    for (p, t) in &items {
        match ace::parse_acl(t, &ids) {
            Ok(acl) => match sys::set_acl(p, &acl) {
                Ok(()) => ok += 1,
                Err(e) => errs.push((p.clone(), e.to_string())),
            },
            Err(e) => errs.push((p.clone(), e.into_iter().map(|(_, m)| m).collect::<Vec<_>>().join("; "))),
        }
    }
    Ok((ok, errs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ace::parse_acl;

    #[test]
    fn path_escaping() {
        let p = PathBuf::from(OsStr::from_bytes(b"/a b/\\x/\n\xff\xc3\xa9"));
        let e = escape_path(&p);
        assert!(!e.contains(' ') && !e.contains('\n'));
        assert_eq!(unescape_path(&e).unwrap(), p);
        assert!(unescape_path("bad\\q1").is_none());
    }

    #[test]
    fn recursive_apply_and_restore() {
        let base = std::env::temp_dir().join(format!("n4acl-apply-{}", std::process::id()));
        let (mock, tree, bk) = (base.join("mock"), base.join("tree"), base.join("bk"));
        for d in [&mock, &tree.join("sub/deep"), &bk] {
            fs::create_dir_all(d).unwrap();
        }
        fs::write(tree.join("a.txt"), "a").unwrap();
        fs::write(tree.join("sub/deep/b.txt"), "b").unwrap();
        unsafe {
            std::env::set_var("N4ACL_MOCK", &mock);
            std::env::set_var("N4ACL_BACKUP_DIR", &bk);
        }
        let ids = IdDb::numeric();
        // an explicit entry on a.txt that must survive re-propagation
        sys::set_acl(&tree.join("a.txt"), &parse_acl("user:9:r:allow\nowner@:rw:allow", &ids).unwrap()).unwrap();
        let before = sys::get_acl(&tree.join("a.txt")).unwrap();

        let acl = parse_acl("owner@:full_set:fd:allow\ngroup:5:read_set:f:allow\neveryone@:r:allow", &ids).unwrap();
        let job = Job { root: &tree, acl: &acl, scope: Scope::Repropagate, aclinherit: Some("restricted"), dry_run: true, backup: true };
        let r = run(&job);
        assert_eq!(r.changed, 5, "{r:?}");
        assert!(sys::get_acl(&tree.join("a.txt")).unwrap() == before, "dry run must not write");

        let r = run(&Job { dry_run: false, ..job });
        assert!(r.errors.is_empty(), "{r:?}");
        let a = sys::get_acl(&tree.join("a.txt")).unwrap();
        assert_eq!(a[0].who, crate::ace::Who::User(9)); // explicit kept first
        assert_eq!(a.len(), 2 + 2); // + owner@ and group:5 inherited
        let deep = sys::get_acl(&tree.join("sub/deep")).unwrap();
        // group:5 is file-inherit only → inherit-only template on subdirs
        assert!(deep.iter().any(|x| x.who == crate::ace::Who::GroupId(5) && x.has(crate::ace::INHERIT_ONLY)));
        let b = sys::get_acl(&tree.join("sub/deep/b.txt")).unwrap();
        assert!(b.iter().any(|x| x.who == crate::ace::Who::GroupId(5) && !x.has(crate::ace::INHERIT_ONLY)));

        let (n, errs) = restore(r.backup.as_ref().unwrap()).unwrap();
        assert!(errs.is_empty());
        assert_eq!(n, 5);
        assert_eq!(sys::get_acl(&tree.join("a.txt")).unwrap(), before);
        fs::remove_dir_all(base).ok();
    }
}
