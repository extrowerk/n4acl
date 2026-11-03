//! NFSv4 / ZFS ACE model, matching illumos <sys/acl.h> and the `ls -V` /
//! `chmod A...` text notation.

use crate::ids::IdDb;

// ---- access mask bits (sys/acl.h) ----
pub const READ_DATA: u32 = 0x0000_0001;
pub const WRITE_DATA: u32 = 0x0000_0002;
pub const APPEND_DATA: u32 = 0x0000_0004;
pub const READ_XATTR: u32 = 0x0000_0008;
pub const WRITE_XATTR: u32 = 0x0000_0010;
pub const EXECUTE: u32 = 0x0000_0020;
pub const DELETE_CHILD: u32 = 0x0000_0040;
pub const READ_ATTRIBUTES: u32 = 0x0000_0080;
pub const WRITE_ATTRIBUTES: u32 = 0x0000_0100;
pub const DELETE: u32 = 0x0001_0000;
pub const READ_ACL: u32 = 0x0002_0000;
pub const WRITE_ACL: u32 = 0x0004_0000;
pub const WRITE_OWNER: u32 = 0x0008_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;
pub const MASK_ALL: u32 = 0x001F_01FF;

// ---- flag bits ----
pub const FILE_INHERIT: u16 = 0x0001;
pub const DIR_INHERIT: u16 = 0x0002;
pub const NO_PROPAGATE: u16 = 0x0004;
pub const INHERIT_ONLY: u16 = 0x0008;
pub const SUCCESSFUL_ACCESS: u16 = 0x0010;
pub const FAILED_ACCESS: u16 = 0x0020;
pub const IDENTIFIER_GROUP: u16 = 0x0040;
pub const INHERITED: u16 = 0x0080;
pub const ACE_OWNER: u16 = 0x1000;
pub const ACE_GROUP: u16 = 0x2000;
pub const ACE_EVERYONE: u16 = 0x4000;
/// Flags that describe inheritance/audit behaviour (everything that is not "who").
pub const FLAG_BEHAVIOUR: u16 =
    FILE_INHERIT | DIR_INHERIT | NO_PROPAGATE | INHERIT_ONLY | SUCCESSFUL_ACCESS | FAILED_ACCESS | INHERITED;
pub const FLAG_INHERIT_ANY: u16 = FILE_INHERIT | DIR_INHERIT;

/// uids/gids at or above this are idmap ephemeral ids (SID-mapped).
pub const EPHEMERAL_MIN: u32 = 0x8000_0000;

pub struct PermInfo {
    pub ch: char,
    pub bit: u32,
    pub name: &'static str,
    pub alt: &'static str,
    pub file: &'static str,
    pub dir: &'static str,
    pub hint: &'static str,
}

/// Order is the illumos compact order: rwxpdDaARWcCos
pub const PERMS: [PermInfo; 14] = [
    PermInfo { ch: 'r', bit: READ_DATA, name: "read_data", alt: "list_directory",
        file: "read contents", dir: "list contents",
        hint: "Read file data, or list the names inside a directory." },
    PermInfo { ch: 'w', bit: WRITE_DATA, name: "write_data", alt: "add_file",
        file: "modify contents", dir: "create files",
        hint: "Overwrite/modify file data, or create new files in a directory." },
    PermInfo { ch: 'x', bit: EXECUTE, name: "execute", alt: "",
        file: "execute", dir: "traverse (cd)",
        hint: "Run a file, or pass through a directory to reach things below it." },
    PermInfo { ch: 'p', bit: APPEND_DATA, name: "append_data", alt: "add_subdirectory",
        file: "append", dir: "create subdirs",
        hint: "Append to a file (without overwriting), or create subdirectories." },
    PermInfo { ch: 'd', bit: DELETE, name: "delete", alt: "",
        file: "delete it", dir: "delete it",
        hint: "Delete this item itself. Deletion is also allowed if the parent grants D (delete_child)." },
    PermInfo { ch: 'D', bit: DELETE_CHILD, name: "delete_child", alt: "",
        file: "n/a on files", dir: "delete children",
        hint: "Directories: delete/rename any entry inside, even without d on that entry." },
    PermInfo { ch: 'a', bit: READ_ATTRIBUTES, name: "read_attributes", alt: "",
        file: "read attributes", dir: "read attributes",
        hint: "Read basic attributes: size, timestamps, mode (needed by ls -l, stat)." },
    PermInfo { ch: 'A', bit: WRITE_ATTRIBUTES, name: "write_attributes", alt: "",
        file: "write attributes", dir: "write attributes",
        hint: "Change timestamps (touch) and other basic attributes." },
    PermInfo { ch: 'R', bit: READ_XATTR, name: "read_xattr", alt: "",
        file: "read xattrs", dir: "read xattrs",
        hint: "Read extended attributes (named attributes / alternate data streams)." },
    PermInfo { ch: 'W', bit: WRITE_XATTR, name: "write_xattr", alt: "",
        file: "write xattrs", dir: "write xattrs",
        hint: "Create, write and remove extended attributes." },
    PermInfo { ch: 'c', bit: READ_ACL, name: "read_acl", alt: "",
        file: "read ACL", dir: "read ACL",
        hint: "Read the ACL and mode (ls -V)." },
    PermInfo { ch: 'C', bit: WRITE_ACL, name: "write_acl", alt: "",
        file: "change ACL/mode", dir: "change ACL/mode",
        hint: "Change the ACL and mode bits (chmod). Owners can always chmod via policy." },
    PermInfo { ch: 'o', bit: WRITE_OWNER, name: "write_owner", alt: "",
        file: "take ownership", dir: "take ownership",
        hint: "Change owner/group (chown/chgrp), limited to taking ownership yourself without privileges." },
    PermInfo { ch: 's', bit: SYNCHRONIZE, name: "synchronize", alt: "",
        file: "synchronize", dir: "synchronize",
        hint: "Placeholder for SMB clients; ZFS ignores it. Usually granted alongside read." },
];

pub struct FlagInfo {
    pub ch: char,
    pub bit: u16,
    pub name: &'static str,
    pub hint: &'static str,
}

/// Order is the illumos compact order: fdinSFI
pub const FLAGS: [FlagInfo; 7] = [
    FlagInfo { ch: 'f', bit: FILE_INHERIT, name: "file_inherit",
        hint: "New files created in this directory get a copy of this ACE." },
    FlagInfo { ch: 'd', bit: DIR_INHERIT, name: "dir_inherit",
        hint: "New subdirectories get a copy of this ACE (and keep passing it down)." },
    FlagInfo { ch: 'i', bit: INHERIT_ONLY, name: "inherit_only",
        hint: "Only a template for children: does not grant/deny anything on this directory." },
    FlagInfo { ch: 'n', bit: NO_PROPAGATE, name: "no_propagate",
        hint: "Inherit to direct children only; their copies do not inherit further." },
    FlagInfo { ch: 'S', bit: SUCCESSFUL_ACCESS, name: "successful_access",
        hint: "Audit/alarm ACEs: match successful accesses." },
    FlagInfo { ch: 'F', bit: FAILED_ACCESS, name: "failed_access",
        hint: "Audit/alarm ACEs: match failed accesses." },
    FlagInfo { ch: 'I', bit: INHERITED, name: "inherited",
        hint: "Set by ZFS: this ACE was inherited from the parent directory." },
];

pub struct Preset {
    pub name: &'static str,
    pub mask: u32,
}

pub const PRESETS: [Preset; 7] = [
    Preset { name: "full", mask: MASK_ALL },
    Preset { name: "modify", mask: MASK_ALL & !(WRITE_ACL | WRITE_OWNER) },
    Preset { name: "read+exec", mask: READ_DATA | READ_ATTRIBUTES | READ_XATTR | READ_ACL | SYNCHRONIZE | EXECUTE },
    Preset { name: "read", mask: READ_DATA | READ_ATTRIBUTES | READ_XATTR | READ_ACL | SYNCHRONIZE },
    Preset { name: "write", mask: WRITE_DATA | APPEND_DATA | WRITE_ATTRIBUTES | WRITE_XATTR | SYNCHRONIZE },
    Preset { name: "traverse", mask: EXECUTE | READ_ATTRIBUTES | READ_ACL | SYNCHRONIZE },
    Preset { name: "none", mask: 0 },
];

/// `chmod(1)` set names accepted by the parser.
const SETS: [(&str, u32); 4] = [
    ("full_set", MASK_ALL),
    ("modify_set", MASK_ALL & !(WRITE_ACL | WRITE_OWNER)),
    ("read_set", READ_DATA | READ_ATTRIBUTES | READ_XATTR | READ_ACL),
    ("write_set", WRITE_DATA | APPEND_DATA | WRITE_ATTRIBUTES | WRITE_XATTR),
];

pub fn preset_label(mask: u32) -> &'static str {
    PRESETS.iter().find(|p| p.mask == mask).map(|p| p.name).unwrap_or("custom")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AceType {
    Allow,
    Deny,
    Audit,
    Alarm,
    Other(u16),
}

impl AceType {
    pub fn from_raw(t: u16) -> Self {
        match t {
            0 => Self::Allow,
            1 => Self::Deny,
            2 => Self::Audit,
            3 => Self::Alarm,
            o => Self::Other(o),
        }
    }
    pub fn raw(self) -> u16 {
        match self {
            Self::Allow => 0,
            Self::Deny => 1,
            Self::Audit => 2,
            Self::Alarm => 3,
            Self::Other(o) => o,
        }
    }
    pub fn name(self) -> String {
        match self {
            Self::Allow => "allow".into(),
            Self::Deny => "deny".into(),
            Self::Audit => "audit".into(),
            Self::Alarm => "alarm".into(),
            Self::Other(o) => format!("type{o}"),
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            "audit" => Some(Self::Audit),
            "alarm" => Some(Self::Alarm),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Who {
    Owner,
    Group,
    Everyone,
    User(u32),
    GroupId(u32),
}

impl Who {
    pub fn is_ephemeral(self) -> bool {
        matches!(self, Who::User(id) | Who::GroupId(id) if id >= EPHEMERAL_MIN)
    }
    pub fn tag(self) -> &'static str {
        match self {
            Who::Owner => "owner@",
            Who::Group => "group@",
            Who::Everyone => "everyone@",
            Who::User(id) if id >= EPHEMERAL_MIN => "usersid",
            Who::GroupId(id) if id >= EPHEMERAL_MIN => "groupsid",
            Who::User(_) => "user",
            Who::GroupId(_) => "group",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ace {
    pub kind: AceType,
    pub who: Who,
    pub mask: u32,
    /// Behaviour flags only (FLAG_BEHAVIOUR); the "who" bits live in `who`.
    pub flags: u16,
}

impl Ace {
    pub fn from_raw(a_who: u32, mask: u32, flags: u16, typ: u16) -> Self {
        let who = if flags & ACE_OWNER != 0 {
            Who::Owner
        } else if flags & ACE_GROUP != 0 {
            Who::Group
        } else if flags & ACE_EVERYONE != 0 {
            Who::Everyone
        } else if flags & IDENTIFIER_GROUP != 0 {
            Who::GroupId(a_who)
        } else {
            Who::User(a_who)
        };
        Ace { kind: AceType::from_raw(typ), who, mask, flags: flags & FLAG_BEHAVIOUR }
    }

    /// (a_who, a_access_mask, a_flags, a_type)
    pub fn to_raw(self) -> (u32, u32, u16, u16) {
        let (who, wflags) = match self.who {
            Who::Owner => (u32::MAX, ACE_OWNER),
            Who::Group => (u32::MAX, ACE_GROUP | IDENTIFIER_GROUP),
            Who::Everyone => (u32::MAX, ACE_EVERYONE),
            Who::User(id) => (id, 0),
            Who::GroupId(id) => (id, IDENTIFIER_GROUP),
        };
        (who, self.mask, (self.flags & FLAG_BEHAVIOUR) | wflags, self.kind.raw())
    }

    pub fn has(&self, f: u16) -> bool {
        self.flags & f != 0
    }
    pub fn is_access(&self) -> bool {
        matches!(self.kind, AceType::Allow | AceType::Deny)
    }
    /// Does this ACE take part in access checks on the object it is attached to?
    pub fn applies_here(&self) -> bool {
        self.is_access() && !self.has(INHERIT_ONLY)
    }
}

pub fn mask_compact(mask: u32) -> String {
    PERMS.iter().map(|p| if mask & p.bit != 0 { p.ch } else { '-' }).collect()
}

pub fn flags_compact(flags: u16) -> String {
    FLAGS.iter().map(|f| if flags & f.bit != 0 { f.ch } else { '-' }).collect()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NameMode {
    Both,
    Name,
    Id,
}

impl NameMode {
    pub fn next(self) -> Self {
        match self {
            Self::Both => Self::Name,
            Self::Name => Self::Id,
            Self::Id => Self::Both,
        }
    }
}

/// Human display of a principal, e.g. `user:1001 (www)`.
pub fn who_display(who: Who, ids: &IdDb, mode: NameMode) -> String {
    let (tag, id, name) = match who {
        Who::Owner | Who::Group | Who::Everyone => return who.tag().to_string(),
        Who::User(id) => (who.tag(), id, ids.user_name(id)),
        Who::GroupId(id) => (who.tag(), id, ids.group_name(id)),
    };
    if who.is_ephemeral() {
        return format!("{tag}:{id} (ephemeral)");
    }
    match (mode, name) {
        (NameMode::Id, _) => format!("{tag}:{id}"),
        (_, None) if matches!(ids.source, crate::ids::Source::Numeric) => format!("{tag}:{id}"),
        (NameMode::Name, Some(n)) => format!("{tag}:{n}"),
        (NameMode::Both, Some(n)) => format!("{tag}:{id} ({n})"),
        (_, None) => format!("{tag}:{id} ?"),
    }
}

/// `chmod A=` compatible text. With `numeric`, ids are never replaced by names
/// (safe for backups and for zones where names differ).
pub fn ace_text(ace: &Ace, ids: &IdDb, numeric: bool) -> String {
    let who = match ace.who {
        Who::Owner | Who::Group | Who::Everyone => ace.who.tag().to_string(),
        Who::User(id) => {
            let n = if numeric { None } else { ids.user_name(id) };
            format!("user:{}", n.unwrap_or_else(|| id.to_string()))
        }
        Who::GroupId(id) => {
            let n = if numeric { None } else { ids.group_name(id) };
            format!("group:{}", n.unwrap_or_else(|| id.to_string()))
        }
    };
    format!("{who}:{}:{}:{}", mask_compact(ace.mask), flags_compact(ace.flags), ace.kind.name())
}

fn parse_mask(s: &str) -> Result<u32, String> {
    if s.is_empty() {
        return Ok(0);
    }
    // compact letters, '-' as filler
    let compact: Option<u32> = s.chars().try_fold(0u32, |m, c| {
        if c == '-' {
            Some(m)
        } else {
            PERMS.iter().find(|p| p.ch == c).map(|p| m | p.bit)
        }
    });
    if let Some(m) = compact {
        return Ok(m);
    }
    // verbose: read_data/write_data or set names
    let mut m = 0;
    for word in s.split('/') {
        if let Some(p) = PERMS.iter().find(|p| p.name == word || (!p.alt.is_empty() && p.alt == word)) {
            m |= p.bit;
        } else if let Some((_, b)) = SETS.iter().find(|(n, _)| *n == word) {
            m |= b;
        } else {
            return Err(format!("unknown permission '{word}'"));
        }
    }
    Ok(m)
}

fn parse_flags(s: &str) -> Result<u16, String> {
    if s.is_empty() {
        return Ok(0);
    }
    let compact: Option<u16> = s.chars().try_fold(0u16, |m, c| {
        if c == '-' {
            Some(m)
        } else {
            FLAGS.iter().find(|f| f.ch == c).map(|f| m | f.bit)
        }
    });
    if let Some(m) = compact {
        return Ok(m);
    }
    let mut m = 0;
    for word in s.split('/') {
        match FLAGS.iter().find(|f| f.name == word) {
            Some(f) => m |= f.bit,
            None => return Err(format!("unknown inheritance flag '{word}'")),
        }
    }
    Ok(m)
}

/// Parse a numeric id: "1001" or "#1001".
pub fn parse_numeric(s: &str) -> Option<u32> {
    let s = s.strip_prefix('#').unwrap_or(s);
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

pub fn resolve_user(s: &str, ids: &IdDb) -> Result<u32, String> {
    if let Some(n) = parse_numeric(s) {
        return Ok(n);
    }
    ids.user_id(s).ok_or_else(|| format!("unknown user '{s}' in {} (use a number or #id)", ids.describe()))
}

pub fn resolve_group(s: &str, ids: &IdDb) -> Result<u32, String> {
    if let Some(n) = parse_numeric(s) {
        return Ok(n);
    }
    ids.group_id(s).ok_or_else(|| format!("unknown group '{s}' in {} (use a number or #id)", ids.describe()))
}

/// Parse one ACE in chmod A syntax. Flags field may be omitted.
pub fn parse_ace(line: &str, ids: &IdDb) -> Result<Ace, String> {
    let parts: Vec<&str> = line.trim().split(':').map(str::trim).collect();
    let (who, rest): (Who, &[&str]) = match parts.first().copied() {
        Some("owner@") => (Who::Owner, &parts[1..]),
        Some("group@") => (Who::Group, &parts[1..]),
        Some("everyone@") => (Who::Everyone, &parts[1..]),
        Some(t @ ("user" | "group")) => {
            let Some(name) = parts.get(1) else { return Err("missing principal".into()) };
            let w = if t == "user" { Who::User(resolve_user(name, ids)?) } else { Who::GroupId(resolve_group(name, ids)?) };
            (w, &parts[2..])
        }
        Some("usersid" | "groupsid") => return Err("SID principals are not supported; keep the numeric ephemeral id (user:N)".into()),
        Some(other) => return Err(format!("unknown principal type '{other}'")),
        None => return Err("empty entry".into()),
    };
    let (mask, flags, typ) = match rest {
        [m, t] => (*m, "", *t),
        [m, f, t] => (*m, *f, *t),
        _ => return Err("expected perms:flags:type".into()),
    };
    Ok(Ace {
        kind: AceType::parse(typ).ok_or_else(|| format!("unknown type '{typ}' (allow/deny/audit/alarm)"))?,
        who,
        mask: parse_mask(mask)?,
        flags: parse_flags(flags)?,
    })
}

/// Parse a whole ACL: one ACE per line and/or comma separated; '#' comments.
pub fn parse_acl(text: &str, ids: &IdDb) -> Result<Vec<Ace>, Vec<(usize, String)>> {
    let mut out = Vec::new();
    let mut errs = Vec::new();
    for (ln, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for item in line.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match parse_ace(item, ids) {
                Ok(a) => out.push(a),
                Err(e) => errs.push((ln + 1, format!("{item}: {e}"))),
            }
        }
    }
    if errs.is_empty() { Ok(out) } else { Err(errs) }
}

fn list(items: &[&str]) -> String {
    if items.is_empty() { "nothing".into() } else { items.join(", ") }
}

/// Plain-language explanation of one ACE.
pub fn explain(ace: &Ace, is_dir: bool, ids: &IdDb, global: Option<&IdDb>) -> Vec<String> {
    let mut out = Vec::new();
    let who = match ace.who {
        Who::Owner => "the file owner (owner@)".to_string(),
        Who::Group => "the owning group (group@)".to_string(),
        Who::Everyone => "everyone (everyone@), including owner and group".to_string(),
        w @ (Who::User(id) | Who::GroupId(id)) => {
            let is_user = matches!(w, Who::User(_));
            let kind = if is_user { "user" } else { "group" };
            if w.is_ephemeral() {
                format!("{kind} with ephemeral id {id} (Windows SID mapped by idmap)")
            } else {
                let name = if is_user { ids.user_name(id) } else { ids.group_name(id) };
                let mut s = match &name {
                    Some(n) => format!("{kind} {id} (\"{n}\" in {})", ids.describe()),
                    None => format!("{kind} {id} (no name in {})", ids.describe()),
                };
                if let Some(g) = global {
                    let gn = if is_user { g.user_name(id) } else { g.group_name(id) };
                    if gn != name {
                        s.push_str(&format!(
                            " ; in global zone: {}",
                            gn.map(|n| format!("\"{n}\"")).unwrap_or("no name".into())
                        ));
                    }
                }
                s
            }
        }
    };
    let verb = match ace.kind {
        AceType::Allow => "ALLOW",
        AceType::Deny => "DENY",
        AceType::Audit => "AUDIT",
        AceType::Alarm => "ALARM",
        AceType::Other(_) => "UNKNOWN",
    };
    out.push(format!("{verb} {who}"));

    let on: Vec<&str> = PERMS
        .iter()
        .filter(|p| ace.mask & p.bit != 0 && !(p.bit == DELETE_CHILD && !is_dir))
        .map(|p| if is_dir { p.dir } else { p.file })
        .collect();
    let off: Vec<&str> = PERMS
        .iter()
        .filter(|p| ace.mask & p.bit == 0 && p.bit != SYNCHRONIZE && !(p.bit == DELETE_CHILD && !is_dir))
        .map(|p| if is_dir { p.dir } else { p.file })
        .collect();
    match ace.kind {
        AceType::Allow => {
            out.push(format!("  Grants: {}", list(&on)));
            out.push(format!("  Not granted by this entry: {}", list(&off)));
        }
        AceType::Deny => out.push(format!("  Denies: {}", list(&on))),
        AceType::Audit | AceType::Alarm => {
            let when = match (ace.has(SUCCESSFUL_ACCESS), ace.has(FAILED_ACCESS)) {
                (true, true) => "successful and failed",
                (true, false) => "successful",
                (false, true) => "failed",
                _ => "no (S/F unset)",
            };
            out.push(format!("  Records {when} attempts to: {}", list(&on)));
            out.push("  Note: ZFS stores audit/alarm entries but does not act on them.".into());
        }
        AceType::Other(_) => out.push("  Unknown ACE type; preserved as-is.".into()),
    }

    let item = if is_dir { "this directory" } else { "this file" };
    let mut applies = Vec::new();
    if !ace.has(INHERIT_ONLY) {
        applies.push(item.to_string());
    }
    if is_dir {
        if ace.has(FILE_INHERIT) {
            applies.push("new files inside".into());
        }
        if ace.has(DIR_INHERIT) {
            applies.push("new subdirectories".into());
        } else if ace.has(FILE_INHERIT) && !ace.has(NO_PROPAGATE) {
            applies.push("files in deeper subdirectories (via inherit-only copies)".into());
        }
    }
    let mut s = format!("  Applies to: {}", if applies.is_empty() { "nothing".into() } else { applies.join(", ") });
    if is_dir && ace.has(NO_PROPAGATE) && ace.has(FLAG_INHERIT_ANY) {
        s.push_str(" — one level only (n)");
    }
    if ace.has(INHERIT_ONLY) && is_dir {
        s.push_str(" — inherit-only, no effect on this directory");
    }
    out.push(s);
    if ace.has(INHERITED) {
        out.push("  Inherited from the parent directory (I).".into());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_text() {
        let ids = IdDb::numeric();
        for t in [
            "owner@:rwxpdDaARWcCos:fd-----:allow",
            "group:1001:rwxp-DaARWc--s:fd-----:allow",
            "user:2002:-w-p----------:-------:deny",
            "everyone@:------a-R-c--s:-------:allow",
            "user:4711:r-----a-R-c--s:fdi---I:allow",
        ] {
            let a = parse_ace(t, &ids).unwrap();
            assert_eq!(ace_text(&a, &ids, true), t);
        }
    }

    #[test]
    fn verbose_and_short() {
        let ids = IdDb::numeric();
        let a = parse_ace("user:#5:read_data/execute:file_inherit:allow", &ids).unwrap();
        assert_eq!(a.mask, READ_DATA | EXECUTE);
        assert_eq!(a.flags, FILE_INHERIT);
        let b = parse_ace("owner@:modify_set:allow", &ids).unwrap();
        assert_eq!(b.mask, MASK_ALL & !(WRITE_ACL | WRITE_OWNER));
        assert!(parse_ace("usersid:S-1-5-1:r:allow", &ids).is_err());
    }

    #[test]
    fn raw_roundtrip() {
        let ids = IdDb::numeric();
        for t in ["group@:r:allow", "group:7:r:deny", "user:8:rw:fd:allow", "everyone@:x:audit"] {
            let a = parse_ace(t, &ids).unwrap();
            let (w, m, f, ty) = a.to_raw();
            assert_eq!(Ace::from_raw(w, m, f, ty), a);
        }
    }
}
