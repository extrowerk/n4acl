//! Writing ACLs: single item, recursive replace, recursive re-propagation,
//! with an optional backup file that `n4acl --restore` can replay.

use crate::ace::{self, Ace, INHERITED};
use crate::ids::IdDb;
use crate::model;
use crate::sys;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::os::unix::fs::MetadataExt;
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
            Scope::Replace => "recursive: same ACL everywhere (files get it without inheritance flags)",
            Scope::Repropagate => "recursive: keep each child's own entries, refresh the inherited (I) ones",
        }
    }
}

#[derive(Default, Debug)]
pub struct Report {
    pub changed: usize,
    pub unchanged: usize,
    pub errors: Vec<(PathBuf, String)>,
    pub samples: Vec<(PathBuf, usize, usize)>,
    pub backup: Option<PathBuf>,
}

struct Backup {
    w: BufWriter<File>,
    ids: IdDb,
}

impl Backup {
    fn record(&mut self, p: &Path, acl: &[Ace]) -> io::Result<()> {
        let esc = p.to_string_lossy().replace('\\', "\\\\").replace('\n', "\\n");
        writeln!(self.w, "path {esc}")?;
        for a in acl {
            writeln!(self.w, "  {}", ace::ace_text(a, &self.ids, true))?;
        }
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

pub fn run(job: &Job) -> Report {
    let mut rep = Report::default();
    let mut bk = None;
    if job.backup && !job.dry_run {
        let dir = backup_dir();
        let path = dir.join(format!("backup-{}.acl", stamp()));
        let opened = fs::create_dir_all(&dir).and_then(|_| File::create(&path));
        match opened {
            Ok(f) => {
                let mut w = BufWriter::new(f);
                let _ = writeln!(w, "# n4acl backup {} — numeric ids. Restore with: n4acl --restore {}", stamp(), path.display());
                bk = Some(Backup { w, ids: IdDb::numeric() });
                rep.backup = Some(path);
            }
            Err(e) => {
                rep.errors.push((path, format!("cannot create backup: {e}; nothing written")));
                return rep;
            }
        }
    }
    let dev = fs::symlink_metadata(job.root).map(|m| m.dev()).unwrap_or(0);
    apply_one(job, job.root, job.acl.to_vec(), &mut rep, &mut bk);
    if job.scope != Scope::This {
        walk(job, job.root, job.acl, dev, &mut rep, &mut bk);
    }
    if let Some(mut b) = bk {
        let _ = b.w.flush();
    }
    rep
}

fn apply_one(job: &Job, p: &Path, new: Vec<Ace>, rep: &mut Report, bk: &mut Option<Backup>) {
    let old = match sys::get_acl(p) {
        Ok(o) => o,
        Err(e) => {
            rep.errors.push((p.to_path_buf(), sys::io_msg(&e)));
            return;
        }
    };
    if old == new {
        rep.unchanged += 1;
        return;
    }
    if rep.samples.len() < 12 {
        rep.samples.push((p.to_path_buf(), old.len(), new.len()));
    }
    if job.dry_run {
        rep.changed += 1;
        return;
    }
    if let Some(b) = bk
        && let Err(e) = b.record(p, &old)
    {
        rep.errors.push((p.to_path_buf(), format!("backup write failed, skipped: {e}")));
        return;
    }
    match sys::set_acl(p, &new) {
        Ok(()) => rep.changed += 1,
        Err(e) => rep.errors.push((p.to_path_buf(), sys::io_msg(&e))),
    }
}

fn walk(job: &Job, dir: &Path, dir_acl: &[Ace], dev: u64, rep: &mut Report, bk: &mut Option<Backup>) {
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            rep.errors.push((dir.to_path_buf(), e.to_string()));
            return;
        }
    };
    let mut entries: Vec<_> = rd.filter_map(Result::ok).map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        let Ok(md) = fs::symlink_metadata(&p) else { continue };
        let ft = md.file_type();
        if ft.is_symlink() || md.dev() != dev || !(ft.is_dir() || ft.is_file()) {
            continue; // never follow symlinks or cross into other datasets
        }
        let is_dir = ft.is_dir();
        let new = match job.scope {
            Scope::This => unreachable!(),
            Scope::Replace => {
                if is_dir { dir_acl.to_vec() } else { model::for_file(dir_acl) }
            }
            Scope::Repropagate => {
                let mut own: Vec<Ace> = match sys::get_acl(&p) {
                    Ok(o) => o.into_iter().filter(|a| !a.has(INHERITED)).collect(),
                    Err(e) => {
                        rep.errors.push((p.clone(), sys::io_msg(&e)));
                        continue;
                    }
                };
                own.extend(model::inherit(dir_acl, is_dir, job.aclinherit));
                own
            }
        };
        apply_one(job, &p, new.clone(), rep, bk);
        if is_dir {
            walk(job, &p, &new, dev, rep, bk);
        }
    }
}

/// Replay a backup file. Returns (restored, errors).
pub fn restore(file: &Path) -> io::Result<(usize, Vec<(PathBuf, String)>)> {
    let text = fs::read_to_string(file)?;
    let ids = IdDb::numeric();
    let mut items: Vec<(PathBuf, String)> = Vec::new();
    for line in text.lines() {
        if let Some(p) = line.strip_prefix("path ") {
            let mut s = String::new();
            let mut it = p.chars();
            while let Some(c) = it.next() {
                if c == '\\' {
                    match it.next() {
                        Some('n') => s.push('\n'),
                        Some(o) => s.push(o),
                        None => {}
                    }
                } else {
                    s.push(c);
                }
            }
            items.push((PathBuf::from(s), String::new()));
        } else if let Some(last) = items.last_mut()
            && line.starts_with("  ")
        {
            last.1.push_str(line.trim());
            last.1.push('\n');
        }
    }
    let (mut ok, mut errs) = (0, Vec::new());
    // reverse order: if a path was recorded twice the first record is the oldest
    for (p, t) in items.iter().rev() {
        match ace::parse_acl(t, &ids) {
            Ok(acl) => match sys::set_acl(p, &acl) {
                Ok(()) => ok += 1,
                Err(e) => errs.push((p.clone(), e.to_string())),
            },
            Err(e) => errs.push((p.clone(), format!("{e:?}"))),
        }
    }
    Ok((ok, errs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ace::parse_acl;

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
