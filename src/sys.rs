//! OS access: reading/writing ACE lists, mount/dataset lookup, ZFS
//! properties and zone discovery.
//!
//! On illumos the native acl(2) syscall is used (ACE_GETACLCNT/ACE_GETACL/
//! ACE_SETACL). Elsewhere a simulated backend is available for development
//! by setting N4ACL_MOCK=<dir>.

use std::path::{Component, Path, PathBuf};
use std::process::Command;

#[cfg(any(target_os = "illumos", target_os = "solaris", n4acl_check_illumos))]
mod native {
    use crate::ace::Ace;
    use std::ffi::CString;
    use std::io;
    use std::os::raw::{c_char, c_int, c_void};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    const ACE_GETACL: c_int = 4;
    const ACE_SETACL: c_int = 5;
    const ACE_GETACLCNT: c_int = 6;
    const MAX_ACL_ENTRIES: usize = 1024;

    /// ace_t from <sys/acl.h>
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct AceT {
        a_who: u32, // uid_t
        a_access_mask: u32,
        a_flags: u16,
        a_type: u16,
    }
    const _: () = assert!(std::mem::size_of::<AceT>() == 12);

    unsafe extern "C" {
        fn acl(pathp: *const c_char, cmd: c_int, nentries: c_int, aclbufp: *mut c_void) -> c_int;
    }

    fn cpath(p: &Path) -> io::Result<CString> {
        CString::new(p.as_os_str().as_bytes()).map_err(|_| io::Error::other("path contains a NUL byte"))
    }

    fn explain(e: io::Error) -> io::Error {
        match e.raw_os_error() {
            Some(libc::ENOSYS) => io::Error::other("filesystem has no NFSv4 ACL support (not ZFS?)"),
            Some(libc::EINVAL) => io::Error::other("ZFS rejected the ACL as invalid (EINVAL)"),
            _ => e,
        }
    }

    pub fn get_acl(p: &Path) -> io::Result<Vec<Ace>> {
        let c = cpath(p)?;
        loop {
            let n = unsafe { acl(c.as_ptr(), ACE_GETACLCNT, 0, std::ptr::null_mut()) };
            if n < 0 {
                return Err(explain(io::Error::last_os_error()));
            }
            let mut buf = vec![AceT::default(); n as usize + 1];
            let r = unsafe { acl(c.as_ptr(), ACE_GETACL, buf.len() as c_int, buf.as_mut_ptr().cast()) };
            if r < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::ENOSPC) {
                    continue; // ACL grew between the two calls
                }
                return Err(explain(e));
            }
            buf.truncate(r as usize);
            return Ok(buf.iter().map(|a| Ace::from_raw(a.a_who, a.a_access_mask, a.a_flags, a.a_type)).collect());
        }
    }

    pub fn set_acl(p: &Path, aces: &[Ace]) -> io::Result<()> {
        if aces.is_empty() || aces.len() > MAX_ACL_ENTRIES {
            return Err(io::Error::other("ACL must have 1..1024 entries"));
        }
        let c = cpath(p)?;
        let mut buf: Vec<AceT> = aces
            .iter()
            .map(|a| {
                let (w, m, f, t) = a.to_raw();
                AceT { a_who: w, a_access_mask: m, a_flags: f, a_type: t }
            })
            .collect();
        let r = unsafe { acl(c.as_ptr(), ACE_SETACL, buf.len() as c_int, buf.as_mut_ptr().cast()) };
        if r < 0 { Err(explain(io::Error::last_os_error())) } else { Ok(()) }
    }
}

#[cfg(not(any(target_os = "illumos", target_os = "solaris", n4acl_check_illumos)))]
mod native {
    //! Development backend: ACLs are stored as text in $N4ACL_MOCK/<encoded path>.
    use crate::ace::{self, Ace};
    use crate::ids::IdDb;
    use std::io;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    fn store(p: &Path) -> io::Result<PathBuf> {
        let dir = std::env::var_os("N4ACL_MOCK").ok_or_else(|| {
            io::Error::other("NFSv4 ACLs need illumos/ZFS (set N4ACL_MOCK=<dir> for a simulated backend)")
        })?;
        let abs = std::fs::canonicalize(p)?;
        Ok(PathBuf::from(dir).join(abs.to_string_lossy().replace('/', "%")))
    }

    pub fn get_acl(p: &Path) -> io::Result<Vec<Ace>> {
        let s = store(p)?;
        match std::fs::read_to_string(&s) {
            Ok(t) => ace::parse_acl(&t, &IdDb::numeric()).map_err(|e| io::Error::other(format!("{e:?}"))),
            Err(_) => {
                // trivial ACL derived from the mode, roughly like ZFS does
                let m = std::fs::metadata(p)?.mode();
                let bits = |r: u32, w: u32, x: u32| {
                    let mut s = String::new();
                    if m & r != 0 { s.push('r'); }
                    if m & w != 0 { s.push_str("wp"); }
                    if m & x != 0 { s.push('x'); }
                    s
                };
                let t = format!(
                    "owner@:{}aARWcCos:allow\ngroup@:{}aRcs:allow\neveryone@:{}aRcs:allow",
                    bits(0o400, 0o200, 0o100),
                    bits(0o40, 0o20, 0o10),
                    bits(0o4, 0o2, 0o1)
                );
                Ok(ace::parse_acl(&t, &IdDb::numeric()).unwrap())
            }
        }
    }

    pub fn set_acl(p: &Path, aces: &[Ace]) -> io::Result<()> {
        if aces.is_empty() {
            return Err(io::Error::other("ACL must have 1..1024 entries"));
        }
        let ids = IdDb::numeric();
        let t: Vec<String> = aces.iter().map(|a| ace::ace_text(a, &ids, true)).collect();
        std::fs::write(store(p)?, t.join("\n") + "\n")
    }
}

pub use native::{get_acl, set_acl};

fn mock_dir() -> Option<PathBuf> {
    std::env::var_os("N4ACL_MOCK").map(PathBuf::from)
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[derive(Clone, Debug, Default)]
pub struct MountInfo {
    pub dataset: Option<String>,
    pub fstype: String,
    /// Path after following lofs mounts (what the global zone sees).
    pub real_path: PathBuf,
}

fn mount_table() -> Vec<(String, PathBuf, String)> {
    if let Ok(t) = std::fs::read_to_string("/etc/mnttab") {
        return t
            .lines()
            .filter_map(|l| {
                let f: Vec<&str> = l.split('\t').collect();
                Some((f.first()?.to_string(), PathBuf::from(f.get(1)?), f.get(2)?.to_string()))
            })
            .collect();
    }
    // development hosts only; escaped paths are not decoded
    std::fs::read_to_string("/proc/mounts")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            Some((f.first()?.to_string(), PathBuf::from(f.get(1)?), f.get(2)?.to_string()))
        })
        .collect()
}

fn depth(p: &Path) -> usize {
    p.components().filter(|c| matches!(c, Component::Normal(_))).count()
}

pub fn mount_info(path: &Path) -> MountInfo {
    let mut cur = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let table = mount_table();
    for _ in 0..8 {
        let Some((special, mp, fstype)) = table.iter().filter(|(_, mp, _)| cur.starts_with(mp)).max_by_key(|(_, mp, _)| depth(mp))
        else {
            break;
        };
        if fstype == "lofs" && special.starts_with('/') {
            let rest = cur.strip_prefix(mp).unwrap_or(Path::new("")).to_path_buf();
            let next = PathBuf::from(special).join(rest);
            // Inside a zone the lofs source is a global-zone path that is not
            // visible here; stop instead of matching an unrelated mount.
            if next == cur || std::fs::symlink_metadata(&next).is_err() {
                return MountInfo { dataset: None, fstype: "lofs".into(), real_path: cur };
            }
            cur = next;
            continue;
        }
        return MountInfo {
            dataset: (fstype == "zfs").then(|| special.clone()),
            fstype: fstype.clone(),
            real_path: cur,
        };
    }
    MountInfo { real_path: cur, ..Default::default() }
}

#[derive(Clone, Debug, Default)]
pub struct ZfsProps {
    pub aclmode: Option<String>,
    pub aclinherit: Option<String>,
    pub zoned: bool,
}

pub fn zfs_props(dataset: Option<&str>) -> ZfsProps {
    let text = match dataset {
        Some(ds) => run("zfs", &["get", "-Hp", "-o", "property,value", "aclmode,aclinherit,zoned", ds]),
        None => None,
    }
    .or_else(|| mock_dir().and_then(|d| std::fs::read_to_string(d.join("zfsprops")).ok()));
    let mut p = ZfsProps::default();
    for l in text.unwrap_or_default().lines() {
        let mut it = l.split(['\t', '=']);
        match (it.next(), it.next()) {
            (Some("aclmode"), Some(v)) => p.aclmode = Some(v.trim().to_string()),
            (Some("aclinherit"), Some(v)) => p.aclinherit = Some(v.trim().to_string()),
            (Some("zoned"), Some(v)) => p.zoned = v.trim() == "on",
            _ => {}
        }
    }
    p
}

#[derive(Clone, Debug)]
pub struct Zone {
    pub name: String,
    pub zonepath: PathBuf,
}

impl Zone {
    pub fn root(&self) -> PathBuf {
        self.zonepath.join("root")
    }
}

pub fn zones() -> Vec<Zone> {
    let text = run("zoneadm", &["list", "-cp"])
        .or_else(|| mock_dir().and_then(|d| std::fs::read_to_string(d.join("zones")).ok()))
        .unwrap_or_default();
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            let name = f.get(1)?.to_string();
            let zonepath = PathBuf::from(f.get(3)?);
            (name != "global").then_some(Zone { name, zonepath })
        })
        .collect()
}

pub fn current_zone() -> String {
    run("zonename", &[]).map(|s| s.trim().to_string()).unwrap_or_else(|| "global".into())
}

/// Guess which zone's users own this path: by zonepath prefix, or by a
/// delegated (zoned=on) dataset listed in the zone's configuration.
pub fn guess_zone(real_path: &Path, dataset: Option<&str>, zoned: bool) -> Option<Zone> {
    let zs = zones();
    if let Some(z) = zs.iter().find(|z| real_path.starts_with(z.root())) {
        return Some(z.clone());
    }
    if zoned && let Some(ds) = dataset {
        for z in &zs {
            if let Some(cfg) = run("zonecfg", &["-z", &z.name, "info", "dataset"]) {
                let hit = cfg.lines().filter_map(|l| l.trim().strip_prefix("name:")).any(|n| {
                    let n = n.trim();
                    ds == n || ds.starts_with(&format!("{n}/"))
                });
                if hit {
                    return Some(z.clone());
                }
            }
        }
    }
    None
}
