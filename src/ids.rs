//! User/group id resolution in an explicit context: the global zone, a
//! (possibly halted) non-global zone's /etc files, arbitrary files, or none.

use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub enum Source {
    Global,
    Zone { name: String, root: PathBuf },
    Files { passwd: PathBuf, group: PathBuf },
    Numeric,
}

impl Source {
    pub fn describe(&self) -> String {
        match self {
            Source::Global => "global zone".into(),
            Source::Zone { name, .. } => format!("zone {name}"),
            Source::Files { passwd, .. } => format!("{}", passwd.display()),
            Source::Numeric => "numeric mode".into(),
        }
    }
}

#[derive(Clone, Debug)]
struct User {
    name: String,
    uid: u32,
    gid: u32,
}

#[derive(Clone, Debug)]
struct Group {
    name: String,
    gid: u32,
    members: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct IdDb {
    pub source: Source,
    users: Vec<User>,
    groups: Vec<Group>,
    /// Set when the passwd/group files of the context could not be read.
    pub warning: Option<String>,
}

fn parse_passwd(text: &str) -> Vec<User> {
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.starts_with('+') && !l.starts_with('-'))
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            Some(User { name: f.first()?.to_string(), uid: f.get(2)?.parse().ok()?, gid: f.get(3)?.parse().ok()? })
        })
        .collect()
}

fn parse_group(text: &str) -> Vec<Group> {
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.starts_with('+') && !l.starts_with('-'))
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            Some(Group {
                name: f.first()?.to_string(),
                gid: f.get(2)?.parse().ok()?,
                members: f
                    .get(3)
                    .map(|m| m.split(',').filter(|s| !s.is_empty()).map(String::from).collect())
                    .unwrap_or_default(),
            })
        })
        .collect()
}

fn read(p: &Path, warn: &mut Option<String>) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|e| {
        warn.get_or_insert_with(|| format!("cannot read {}: {e}", p.display()));
        String::new()
    })
}

// --- libc fallbacks for the global zone (picks up LDAP/NIS via nsswitch) ---
fn sys_user_name(uid: u32) -> Option<String> {
    unsafe {
        let p = libc::getpwuid(uid as libc::uid_t);
        if p.is_null() { None } else { Some(CStr::from_ptr((*p).pw_name).to_string_lossy().into_owned()) }
    }
}
fn sys_group_name(gid: u32) -> Option<String> {
    unsafe {
        let p = libc::getgrgid(gid as libc::gid_t);
        if p.is_null() { None } else { Some(CStr::from_ptr((*p).gr_name).to_string_lossy().into_owned()) }
    }
}
fn sys_user(name: &str) -> Option<(u32, u32)> {
    let c = CString::new(name).ok()?;
    unsafe {
        let p = libc::getpwnam(c.as_ptr());
        if p.is_null() { None } else { Some(((*p).pw_uid as u32, (*p).pw_gid as u32)) }
    }
}
fn sys_group(name: &str) -> Option<u32> {
    let c = CString::new(name).ok()?;
    unsafe {
        let p = libc::getgrnam(c.as_ptr());
        if p.is_null() { None } else { Some((*p).gr_gid as u32) }
    }
}

impl IdDb {
    pub fn numeric() -> Self {
        IdDb { source: Source::Numeric, users: vec![], groups: vec![], warning: None }
    }

    pub fn load(source: Source) -> Self {
        let (pw, gr): (PathBuf, PathBuf) = match &source {
            Source::Global => ("/etc/passwd".into(), "/etc/group".into()),
            Source::Zone { root, .. } => (root.join("etc/passwd"), root.join("etc/group")),
            Source::Files { passwd, group } => (passwd.clone(), group.clone()),
            Source::Numeric => return Self::numeric(),
        };
        let mut warning = None;
        let users = parse_passwd(&read(&pw, &mut warning));
        let groups = parse_group(&read(&gr, &mut warning));
        IdDb { source, users, groups, warning }
    }

    pub fn is_global(&self) -> bool {
        matches!(self.source, Source::Global)
    }

    pub fn describe(&self) -> String {
        self.source.describe()
    }

    pub fn short(&self) -> String {
        match &self.source {
            Source::Zone { name, .. } => format!("zone {name}"),
            Source::Global => "global".into(),
            Source::Files { .. } => "files".into(),
            Source::Numeric => "numeric".into(),
        }
    }

    pub fn user_name(&self, uid: u32) -> Option<String> {
        if let Some(u) = self.users.iter().find(|u| u.uid == uid) {
            return Some(u.name.clone());
        }
        if self.is_global() { sys_user_name(uid) } else { None }
    }

    pub fn group_name(&self, gid: u32) -> Option<String> {
        if let Some(g) = self.groups.iter().find(|g| g.gid == gid) {
            return Some(g.name.clone());
        }
        if self.is_global() { sys_group_name(gid) } else { None }
    }

    pub fn user_id(&self, name: &str) -> Option<u32> {
        if let Some(u) = self.users.iter().find(|u| u.name == name) {
            return Some(u.uid);
        }
        if self.is_global() { sys_user(name).map(|x| x.0) } else { None }
    }

    pub fn group_id(&self, name: &str) -> Option<u32> {
        if let Some(g) = self.groups.iter().find(|g| g.name == name) {
            return Some(g.gid);
        }
        if self.is_global() { sys_group(name) } else { None }
    }

    /// Primary gid plus supplementary groups listed in the group file.
    pub fn user_groups(&self, uid: u32) -> Vec<u32> {
        let mut out = Vec::new();
        let name = self.user_name(uid);
        if let Some(u) = self.users.iter().find(|u| u.uid == uid) {
            out.push(u.gid);
        } else if self.is_global()
            && let Some((_, gid)) = name.as_deref().and_then(sys_user)
        {
            out.push(gid);
        }
        if let Some(n) = name {
            for g in &self.groups {
                if g.members.contains(&n) && !out.contains(&g.gid) {
                    out.push(g.gid);
                }
            }
        }
        out
    }

    pub fn complete_users(&self, prefix: &str) -> Vec<String> {
        let mut v: Vec<String> = self.users.iter().filter(|u| u.name.starts_with(prefix)).map(|u| u.name.clone()).collect();
        v.sort();
        v
    }

    pub fn complete_groups(&self, prefix: &str) -> Vec<String> {
        let mut v: Vec<String> = self.groups.iter().filter(|g| g.name.starts_with(prefix)).map(|g| g.name.clone()).collect();
        v.sort();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_context() {
        let dir = std::env::temp_dir().join(format!("n4acl-ids-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::write(dir.join("etc/passwd"), "www:x:1001:1001::/:/bin/sh\ndeploy:x:2002:1001::/:/bin/sh\n").unwrap();
        std::fs::write(dir.join("etc/group"), "www::1001:\nops::1003:deploy\n").unwrap();
        let db = IdDb::load(Source::Zone { name: "web01".into(), root: dir.clone() });
        assert_eq!(db.user_name(2002).as_deref(), Some("deploy"));
        assert_eq!(db.user_id("www"), Some(1001));
        assert_eq!(db.user_groups(2002), vec![1001, 1003]);
        assert_eq!(db.user_name(4711), None);
        std::fs::remove_dir_all(dir).ok();
    }
}
