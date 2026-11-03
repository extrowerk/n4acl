//! Analysis on top of an ACE list: lint, access evaluation, inheritance.

use crate::ace::*;
use crate::ids::IdDb;

#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warn,
}

#[derive(Clone, Debug)]
pub struct Lint {
    pub sev: Severity,
    pub ace: Option<usize>,
    pub msg: String,
}

pub struct Ctx<'a> {
    pub is_dir: bool,
    pub ids: &'a IdDb,
    pub global: Option<&'a IdDb>,
    pub aclmode: Option<&'a str>,
    pub aclinherit: Option<&'a str>,
}

fn letters(mask: u32) -> String {
    PERMS.iter().filter(|p| mask & p.bit != 0).map(|p| p.ch).collect()
}

fn is_trivial(acl: &[Ace]) -> bool {
    acl.iter().all(|a| matches!(a.who, Who::Owner | Who::Group | Who::Everyone) && a.flags & FLAG_INHERIT_ANY == 0)
}

pub fn lint(acl: &[Ace], cx: &Ctx) -> Vec<Lint> {
    let mut out = Vec::new();
    let mut w = |sev, ace: Option<usize>, msg: String| out.push(Lint { sev, ace, msg });

    for (i, a) in acl.iter().enumerate() {
        let n = i + 1;
        if a.mask == 0 && a.is_access() {
            w(Severity::Warn, Some(i), format!("#{n} has no permissions set; it does nothing"));
        }
        if !cx.is_dir && a.has(FILE_INHERIT | DIR_INHERIT | INHERIT_ONLY | NO_PROPAGATE) {
            w(Severity::Warn, Some(i), format!("#{n}: inheritance flags have no meaning on a file; ZFS may reject them"));
        }
        if !cx.is_dir && a.mask & DELETE_CHILD != 0 && a.kind == AceType::Allow {
            w(Severity::Info, Some(i), format!("#{n}: D (delete_child) only matters on directories"));
        }
        if cx.is_dir && a.has(INHERIT_ONLY) && !a.has(FLAG_INHERIT_ANY) {
            w(Severity::Warn, Some(i), format!("#{n} is inherit-only (i) but has no f/d: it never applies anywhere"));
        }
        if cx.is_dir && a.has(NO_PROPAGATE) && !a.has(FLAG_INHERIT_ANY) {
            w(Severity::Info, Some(i), format!("#{n}: no_propagate (n) without f/d has no effect"));
        }
        if matches!(a.kind, AceType::Audit | AceType::Alarm) {
            if !a.has(SUCCESSFUL_ACCESS | FAILED_ACCESS) {
                w(Severity::Warn, Some(i), format!("#{n}: audit/alarm without S or F matches nothing"));
            }
            w(Severity::Info, Some(i), format!("#{n}: ZFS keeps audit/alarm entries but does not act on them"));
        }
        if let AceType::Other(t) = a.kind {
            w(Severity::Info, Some(i), format!("#{n}: unknown ACE type {t} (CIFS?) preserved as-is"));
        }
        if a.who.is_ephemeral() {
            w(Severity::Info, Some(i), format!("#{n}: SID-mapped ephemeral id; read-only in this version"));
        }
        match a.who {
            Who::User(id) | Who::GroupId(id) if !a.who.is_ephemeral() => {
                let is_user = matches!(a.who, Who::User(_));
                let name = if is_user { cx.ids.user_name(id) } else { cx.ids.group_name(id) };
                if name.is_none() && !matches!(cx.ids.source, crate::ids::Source::Numeric) {
                    w(Severity::Warn, Some(i), format!("#{n}: id {id} has no name in {}", cx.ids.describe()));
                }
                if let (Some(g), Some(nm)) = (cx.global, &name) {
                    let gn = if is_user { g.user_name(id) } else { g.group_name(id) };
                    if let Some(gn) = gn
                        && gn != *nm
                    {
                        w(Severity::Info, Some(i), format!("#{n}: id {id} is \"{nm}\" here but \"{gn}\" in the global zone"));
                    }
                }
            }
            _ => {}
        }
        // exact duplicates
        if let Some(j) = acl[..i].iter().position(|b| b == a) {
            w(Severity::Warn, Some(i), format!("#{n} duplicates #{}", j + 1));
            continue;
        }
        // shadowing by earlier entries for the very same principal
        if a.applies_here() && a.mask != 0 {
            let decided: u32 = acl[..i].iter().filter(|b| b.applies_here() && b.who == a.who).fold(0, |m, b| m | b.mask);
            let dead = a.mask & decided;
            if dead == a.mask {
                w(Severity::Warn, Some(i), format!("#{n} has no effect on this item: earlier entries for the same principal already decide all of its bits"));
            } else if dead != 0 {
                let what = if a.kind == AceType::Deny { "deny" } else { "allow" };
                w(Severity::Warn, Some(i), format!("#{n}: {what} of '{}' has no effect — already decided above", letters(dead)));
            }
        }
    }

    if cx.is_dir {
        let inheritable_allow = acl.iter().any(|a| a.kind == AceType::Allow && a.has(FLAG_INHERIT_ANY));
        match cx.aclinherit {
            Some("discard") if acl.iter().any(|a| a.has(FLAG_INHERIT_ANY)) => {
                w(Severity::Warn, None, "aclinherit=discard: nothing here will be inherited".into())
            }
            Some("noallow") if inheritable_allow => {
                w(Severity::Warn, None, "aclinherit=noallow: inheritable allow entries are not inherited".into())
            }
            Some("restricted")
                if acl.iter().any(|a| a.kind == AceType::Allow && a.has(FLAG_INHERIT_ANY) && a.mask & (WRITE_ACL | WRITE_OWNER) != 0) =>
            {
                w(Severity::Info, None, "aclinherit=restricted: C and o are stripped from inherited copies".into())
            }
            _ => {}
        }
    }
    if !is_trivial(acl) {
        match cx.aclmode {
            Some("discard") => w(Severity::Info, None, "aclmode=discard: a chmod on this item will drop the custom entries".into()),
            Some("groupmask") => w(Severity::Info, None, "aclmode=groupmask: a chmod will mask user/group entries with the group bits".into()),
            Some("restricted") => w(Severity::Info, None, "aclmode=restricted: plain chmod on this item will fail (EPERM)".into()),
            _ => {}
        }
    }
    out.sort_by_key(|l| std::cmp::Reverse(l.sev));
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allowed(usize),
    Denied(usize),
    OwnerImplicit,
    NoMatch,
}

pub struct Subject {
    pub uid: u32,
    pub gids: Vec<u32>,
}

impl Subject {
    /// `name`, `uid`, or `user:group,group…` (names or numbers). Without an
    /// explicit group list, the groups come from the id context.
    pub fn parse(input: &str, ids: &IdDb) -> Result<Self, String> {
        let (u, g) = match input.trim().split_once(':') {
            Some((u, g)) => (u, Some(g)),
            None => (input.trim(), None),
        };
        let uid = resolve_user(u, ids)?;
        let gids = match g {
            Some(g) => g.split(',').map(str::trim).filter(|s| !s.is_empty()).map(|x| resolve_group(x, ids)).collect::<Result<_, _>>()?,
            None => ids.user_groups(uid),
        };
        Ok(Subject { uid, gids })
    }
}

fn matches(who: Who, s: &Subject, fuid: u32, fgid: u32) -> bool {
    match who {
        Who::Owner => s.uid == fuid,
        Who::Group => s.gids.contains(&fgid),
        Who::Everyone => true,
        Who::User(u) => s.uid == u,
        Who::GroupId(g) => s.gids.contains(&g),
    }
}

/// Walk the ACL like ZFS: in order, first entry that mentions a bit decides it.
pub fn evaluate(acl: &[Ace], s: &Subject, fuid: u32, fgid: u32) -> Vec<(&'static PermInfo, Decision)> {
    let mut res: Vec<(&'static PermInfo, Decision)> = PERMS.iter().map(|p| (p, Decision::NoMatch)).collect();
    for (i, a) in acl.iter().enumerate() {
        if !a.applies_here() || !matches(a.who, s, fuid, fgid) {
            continue;
        }
        for (p, d) in res.iter_mut() {
            if *d == Decision::NoMatch && a.mask & p.bit != 0 {
                *d = if a.kind == AceType::Allow { Decision::Allowed(i) } else { Decision::Denied(i) };
            }
        }
    }
    if s.uid == fuid {
        // ZFS/secpolicy: owners can always read the ACL/attributes and chmod
        for (p, d) in res.iter_mut() {
            if !matches!(d, Decision::Allowed(_)) && p.bit & (READ_ACL | READ_ATTRIBUTES | WRITE_ACL | WRITE_ATTRIBUTES) != 0 {
                *d = Decision::OwnerImplicit;
            }
        }
    }
    res
}

/// What a new child of a directory with `parent` ACL will start with
/// (before ZFS applies the creation mode).
pub fn inherit(parent: &[Ace], child_is_dir: bool, aclinherit: Option<&str>) -> Vec<Ace> {
    let mode = aclinherit.unwrap_or("restricted");
    if mode == "discard" {
        return vec![];
    }
    let mut out = Vec::new();
    for a in parent {
        if !a.has(FLAG_INHERIT_ANY) {
            continue;
        }
        if mode == "noallow" && a.kind == AceType::Allow {
            continue;
        }
        let mut c = *a;
        if mode == "restricted" && c.kind == AceType::Allow {
            c.mask &= !(WRITE_ACL | WRITE_OWNER);
        }
        if child_is_dir {
            if a.has(DIR_INHERIT) {
                if a.has(NO_PROPAGATE) {
                    c.flags &= !(FLAG_INHERIT_ANY | INHERIT_ONLY | NO_PROPAGATE);
                } else {
                    c.flags &= !INHERIT_ONLY;
                }
            } else if !a.has(NO_PROPAGATE) {
                // file_inherit only: kept as a template for files further down
                c.flags |= INHERIT_ONLY;
            } else {
                continue;
            }
        } else {
            if !a.has(FILE_INHERIT) {
                continue;
            }
            c.flags &= !(FLAG_INHERIT_ANY | INHERIT_ONLY | NO_PROPAGATE);
        }
        c.flags |= INHERITED;
        out.push(c);
    }
    out
}

/// ACL to place on a file when "replace recursively" copies a directory ACL.
pub fn for_file(dir_acl: &[Ace]) -> Vec<Ace> {
    dir_acl
        .iter()
        .filter(|a| !a.has(INHERIT_ONLY))
        .map(|a| Ace { flags: a.flags & !(FLAG_INHERIT_ANY | NO_PROPAGATE), ..*a })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acl(s: &str) -> Vec<Ace> {
        parse_acl(s, &IdDb::numeric()).unwrap()
    }

    #[test]
    fn eval_first_match() {
        let a = acl("user:5:w:deny\ngroup:10:rw:allow\neveryone@:r:allow");
        let r = evaluate(&a, &Subject { uid: 5, gids: vec![10] }, 1, 1);
        let get = |c| r.iter().find(|(p, _)| p.ch == c).unwrap().1;
        assert_eq!(get('w'), Decision::Denied(0));
        assert_eq!(get('r'), Decision::Allowed(1));
        assert_eq!(get('x'), Decision::NoMatch);
    }

    #[test]
    fn inheritance() {
        let p = acl("group:7:rwC:fd:allow\nuser:8:r:f:allow\nuser:9:r:dn:allow");
        let f = inherit(&p, false, Some("restricted"));
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].mask, READ_DATA | WRITE_DATA);
        assert_eq!(f[0].flags, INHERITED);
        let d = inherit(&p, true, Some("passthrough"));
        assert_eq!(d.len(), 3);
        assert_eq!(d[0].flags, FILE_INHERIT | DIR_INHERIT | INHERITED);
        assert_eq!(d[1].flags, FILE_INHERIT | INHERIT_ONLY | INHERITED);
        assert_eq!(d[2].flags, INHERITED);
    }

    #[test]
    fn lint_late_deny() {
        let a = acl("user:5:rw:allow\nuser:5:w:deny");
        let ids = IdDb::numeric();
        let l = lint(&a, &Ctx { is_dir: true, ids: &ids, global: None, aclmode: None, aclinherit: None });
        assert!(l.iter().any(|x| x.ace == Some(1) && x.msg.contains("no effect")));
    }
}
